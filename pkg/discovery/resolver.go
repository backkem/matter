package discovery

import (
	"context"
	"net"
	"time"

	"github.com/backkem/matter/pkg/fabric"
	"github.com/grandcat/zeroconf"
)

// DefaultBrowseTimeout is the default timeout for browse operations.
const DefaultBrowseTimeout = 10 * time.Second

// DefaultLookupTimeout is the default timeout for lookup operations.
const DefaultLookupTimeout = 5 * time.Second

// ResolvedService contains information about a discovered DNS-SD service.
type ResolvedService struct {
	// ServiceType is the type of the discovered service.
	ServiceType ServiceType

	// InstanceName is the DNS-SD instance name.
	InstanceName string

	// HostName is the target host name.
	HostName string

	// Port is the service port.
	Port int

	// IPs contains the resolved IP addresses, sorted by preference.
	IPs []net.IP

	// Text contains the raw TXT record key-value pairs.
	Text map[string]string
}

// PreferredIP returns the most preferred IP address (first in the sorted list).
// Returns nil if no addresses are available.
func (r *ResolvedService) PreferredIP() net.IP {
	if len(r.IPs) > 0 {
		return r.IPs[0]
	}
	return nil
}

// IPv6Addresses returns only IPv6 addresses from the service.
func (r *ResolvedService) IPv6Addresses() []net.IP {
	return FilterIPv6(r.IPs)
}

// IPv4Addresses returns only IPv4 addresses from the service.
func (r *ResolvedService) IPv4Addresses() []net.IP {
	return FilterIPv4(r.IPs)
}

// MDNSResolver is the interface for mDNS service resolution.
// This allows for dependency injection in tests.
type MDNSResolver interface {
	// Browse browses for services of the given type.
	Browse(ctx context.Context, service, domain string, entries chan<- *zeroconf.ServiceEntry) error

	// Lookup looks up a specific service instance.
	Lookup(ctx context.Context, instance, service, domain string, entries chan<- *zeroconf.ServiceEntry) error
}

// zeroconfResolver is the production implementation using grandcat/zeroconf.
type zeroconfResolver struct {
	resolver *zeroconf.Resolver
}

func newZeroconfResolver() (*zeroconfResolver, error) {
	r, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil, err
	}
	return &zeroconfResolver{resolver: r}, nil
}

func (z *zeroconfResolver) Browse(ctx context.Context, service, domain string, entries chan<- *zeroconf.ServiceEntry) error {
	return z.resolver.Browse(ctx, service, domain, entries)
}

func (z *zeroconfResolver) Lookup(ctx context.Context, instance, service, domain string, entries chan<- *zeroconf.ServiceEntry) error {
	return z.resolver.Lookup(ctx, instance, service, domain, entries)
}

// ResolverConfig holds configuration for the Resolver.
type ResolverConfig struct {
	// MDNSResolver is the underlying mDNS resolver implementation.
	// If nil, the default zeroconf resolver is used.
	MDNSResolver MDNSResolver

	// BrowseTimeout is the timeout for browse operations.
	// If zero, DefaultBrowseTimeout is used.
	BrowseTimeout time.Duration

	// LookupTimeout is the timeout for lookup operations.
	// If zero, DefaultLookupTimeout is used.
	LookupTimeout time.Duration
}

// Resolver discovers Matter services via DNS-SD.
type Resolver struct {
	config   ResolverConfig
	resolver MDNSResolver
}

// NewResolver creates a new Resolver with the given configuration.
func NewResolver(config ResolverConfig) (*Resolver, error) {
	resolver := config.MDNSResolver
	if resolver == nil {
		zr, err := newZeroconfResolver()
		if err != nil {
			return nil, err
		}
		resolver = zr
	}

	if config.BrowseTimeout == 0 {
		config.BrowseTimeout = DefaultBrowseTimeout
	}
	if config.LookupTimeout == 0 {
		config.LookupTimeout = DefaultLookupTimeout
	}

	return &Resolver{
		config:   config,
		resolver: resolver,
	}, nil
}

// BrowseCommissionable discovers commissionable nodes on the network.
// Returns a channel that receives discovered services until the context is cancelled
// or the browse timeout expires.
// Spec Section 4.3.1
func (r *Resolver) BrowseCommissionable(ctx context.Context) (<-chan ResolvedService, error) {
	return r.browse(ctx, ServiceTypeCommissionable, ServiceCommissionable)
}

// BrowseCommissionableWithFilter discovers commissionable nodes matching the filter.
// The filter can be:
//   - Short discriminator: "_S<value>" (e.g., "_S3")
//   - Long discriminator: "_L<value>" (e.g., "_L840")
//   - Vendor ID: "_V<value>" (e.g., "_V123")
//   - Device Type: "_T<value>" (e.g., "_T81")
//   - Commissioning Mode: "_CM"
func (r *Resolver) BrowseCommissionableWithFilter(ctx context.Context, filter string) (<-chan ResolvedService, error) {
	service := filter + "._sub." + ServiceCommissionable
	return r.browse(ctx, ServiceTypeCommissionable, service)
}

// BrowseOperational discovers operational nodes on the network.
// Returns a channel that receives discovered services until the context is cancelled
// or the browse timeout expires.
// Spec Section 4.3.2
func (r *Resolver) BrowseOperational(ctx context.Context) (<-chan ResolvedService, error) {
	return r.browse(ctx, ServiceTypeOperational, ServiceOperational)
}

// BrowseCommissioner discovers commissioners on the network.
// Returns a channel that receives discovered services until the context is cancelled
// or the browse timeout expires.
// Spec Section 4.3.3
func (r *Resolver) BrowseCommissioner(ctx context.Context) (<-chan ResolvedService, error) {
	return r.browse(ctx, ServiceTypeCommissioner, ServiceCommissioner)
}

// browse performs a generic browse operation.
func (r *Resolver) browse(ctx context.Context, serviceType ServiceType, service string) (<-chan ResolvedService, error) {
	results := make(chan ResolvedService)
	entries := make(chan *zeroconf.ServiceEntry)

	// Apply browse timeout if context doesn't have a deadline
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.config.BrowseTimeout)
		defer cancel()
	}

	// Start browsing in a goroutine
	go func() {
		defer close(results)

		// Start the browse
		go func() {
			defer close(entries)
			r.resolver.Browse(ctx, service, DefaultDomain, entries)
		}()

		// Convert entries to ResolvedService
		for entry := range entries {
			svc := entryToResolvedService(entry, serviceType)
			select {
			case results <- svc:
			case <-ctx.Done():
				return
			}
		}
	}()

	return results, nil
}

// LookupOperational looks up a specific operational node by compressed fabric ID and node ID.
// This is the primary method for finding a known commissioned node.
// Spec Section 4.3.2
func (r *Resolver) LookupOperational(ctx context.Context, compressedFabricID [8]byte, nodeID fabric.NodeID) (*ResolvedService, error) {
	instanceName := OperationalInstanceName(compressedFabricID, nodeID)
	return r.Lookup(ctx, ServiceTypeOperational, instanceName)
}

// Lookup looks up a specific service instance by name.
func (r *Resolver) Lookup(ctx context.Context, serviceType ServiceType, instanceName string) (*ResolvedService, error) {
	if !serviceType.IsValid() {
		return nil, ErrInvalidServiceType
	}

	service := serviceType.ServiceString()
	if service == "" {
		return nil, ErrInvalidServiceType
	}

	// Apply lookup timeout if context doesn't have a deadline
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.config.LookupTimeout)
		defer cancel()
	}

	entries := make(chan *zeroconf.ServiceEntry)

	// Start lookup in a goroutine
	go func() {
		defer close(entries)
		r.resolver.Lookup(ctx, instanceName, service, DefaultDomain, entries)
	}()

	// Wait for first result or timeout
	select {
	case entry, ok := <-entries:
		if !ok || entry == nil {
			return nil, ErrServiceNotFound
		}
		svc := entryToResolvedService(entry, serviceType)
		return &svc, nil
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return nil, ErrTimeout
		}
		return nil, ctx.Err()
	}
}

// entryToResolvedService converts a zeroconf.ServiceEntry to ResolvedService.
func entryToResolvedService(entry *zeroconf.ServiceEntry, serviceType ServiceType) ResolvedService {
	// Combine IPv4 and IPv6 addresses
	var allIPs []net.IP
	for _, ip := range entry.AddrIPv6 {
		allIPs = append(allIPs, ip)
	}
	for _, ip := range entry.AddrIPv4 {
		allIPs = append(allIPs, ip)
	}

	// Sort by preference (IPv6 global > IPv6 ULA > IPv6 link-local > IPv4)
	sortedIPs := SortIPsByPreference(allIPs)

	// Parse TXT records
	txtMap := ParseTXT(entry.Text)

	return ResolvedService{
		ServiceType:  serviceType,
		InstanceName: entry.Instance,
		HostName:     entry.HostName,
		Port:         entry.Port,
		IPs:          sortedIPs,
		Text:         txtMap,
	}
}

// DiscoverCommissionableNode is a convenience function to find a commissionable node
// by discriminator. It browses and filters by the long discriminator.
func (r *Resolver) DiscoverCommissionableNode(ctx context.Context, discriminator uint16) (*ResolvedService, error) {
	filter := LongDiscriminatorSubtype(discriminator)
	services, err := r.BrowseCommissionableWithFilter(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Return first match
	for svc := range services {
		return &svc, nil
	}

	return nil, ErrServiceNotFound
}

// ShortDiscriminatorSubtype returns the subtype filter for short discriminator.
// Format: "_S<value>"
func ShortDiscriminatorSubtype(shortDiscriminator uint8) string {
	return "_S" + string(rune('0'+shortDiscriminator))
}

// LongDiscriminatorSubtype returns the subtype filter for long discriminator.
// Format: "_L<value>"
func LongDiscriminatorSubtype(discriminator uint16) string {
	return "_L" + itoa(int(discriminator))
}

// VendorIDSubtype returns the subtype filter for vendor ID.
// Format: "_V<value>"
func VendorIDSubtype(vendorID fabric.VendorID) string {
	return "_V" + itoa(int(vendorID))
}

// DeviceTypeSubtype returns the subtype filter for device type.
// Format: "_T<value>"
func DeviceTypeSubtype(deviceType uint32) string {
	return "_T" + itoa(int(deviceType))
}

// CommissioningModeSubtype returns the subtype filter for nodes in commissioning mode.
const CommissioningModeSubtype = "_CM"

// itoa converts an integer to a string (simple implementation).
func itoa(i int) string {
	if i == 0 {
		return "0"
	}

	var buf [20]byte
	pos := len(buf)
	negative := i < 0
	if negative {
		i = -i
	}

	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}

	if negative {
		pos--
		buf[pos] = '-'
	}

	return string(buf[pos:])
}
