package discovery

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/backkem/matter/pkg/fabric"
)

// ManagerConfig holds configuration for the discovery Manager.
type ManagerConfig struct {
	// HostName is the mDNS host name (e.g., derived from MAC address).
	// If empty, a default will be generated.
	HostName string

	// Port is the Matter port to advertise (default: 5540).
	Port int

	// Interfaces specifies which network interfaces to use.
	// If nil, all interfaces are used.
	Interfaces []net.Interface

	// BrowseTimeout is the default timeout for browse operations.
	// If zero, DefaultBrowseTimeout is used.
	BrowseTimeout time.Duration

	// LookupTimeout is the default timeout for lookup operations.
	// If zero, DefaultLookupTimeout is used.
	LookupTimeout time.Duration

	// ServerFactory is the factory for creating mDNS servers (for testing).
	ServerFactory MDNSServerFactory

	// MDNSResolver is the mDNS resolver implementation (for testing).
	MDNSResolver MDNSResolver
}

// Manager coordinates DNS-SD advertising and resolution for Matter.
type Manager struct {
	config     ManagerConfig
	advertiser *Advertiser
	resolver   *Resolver

	mu     sync.RWMutex
	closed bool
}

// NewManager creates a new discovery Manager with the given configuration.
func NewManager(config ManagerConfig) (*Manager, error) {
	// Apply defaults
	if config.Port <= 0 {
		config.Port = DefaultPort
	}
	if config.BrowseTimeout == 0 {
		config.BrowseTimeout = DefaultBrowseTimeout
	}
	if config.LookupTimeout == 0 {
		config.LookupTimeout = DefaultLookupTimeout
	}

	// Create advertiser
	advertiser, err := NewAdvertiser(AdvertiserConfig{
		HostName:      config.HostName,
		Port:          config.Port,
		Interfaces:    config.Interfaces,
		ServerFactory: config.ServerFactory,
	})
	if err != nil {
		return nil, err
	}

	// Create resolver
	resolver, err := NewResolver(ResolverConfig{
		MDNSResolver:  config.MDNSResolver,
		BrowseTimeout: config.BrowseTimeout,
		LookupTimeout: config.LookupTimeout,
	})
	if err != nil {
		return nil, err
	}

	return &Manager{
		config:     config,
		advertiser: advertiser,
		resolver:   resolver,
	}, nil
}

// Close stops all services and releases resources.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrClosed
	}

	m.closed = true

	// Close advertiser
	if m.advertiser != nil {
		m.advertiser.Close()
	}

	return nil
}

// ---- Advertising Methods ----

// StartCommissionable begins advertising as a commissionable node.
// This should be called when the device enters commissioning mode.
// Spec Section 4.3.1
func (m *Manager) StartCommissionable(txt CommissionableTXT) error {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return ErrClosed
	}
	m.mu.RUnlock()

	return m.advertiser.StartCommissionable(txt)
}

// StartOperational begins advertising as an operational (commissioned) node.
// This should be called after the device is commissioned onto a fabric.
// Spec Section 4.3.2
func (m *Manager) StartOperational(compressedFabricID [8]byte, nodeID fabric.NodeID, txt OperationalTXT) error {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return ErrClosed
	}
	m.mu.RUnlock()

	return m.advertiser.StartOperational(compressedFabricID, nodeID, txt)
}

// StartCommissioner begins advertising as a commissioner.
// This should be called when the device acts as a commissioner.
// Spec Section 4.3.3
func (m *Manager) StartCommissioner(txt CommissionerTXT) error {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return ErrClosed
	}
	m.mu.RUnlock()

	return m.advertiser.StartCommissioner(txt)
}

// StopAdvertising stops advertising a specific service type.
func (m *Manager) StopAdvertising(serviceType ServiceType) error {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return ErrClosed
	}
	m.mu.RUnlock()

	return m.advertiser.Stop(serviceType)
}

// StopAllAdvertising stops all active service advertisements.
func (m *Manager) StopAllAdvertising() {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return
	}
	m.mu.RUnlock()

	m.advertiser.StopAll()
}

// IsAdvertising returns true if the given service type is currently being advertised.
func (m *Manager) IsAdvertising(serviceType ServiceType) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return false
	}

	return m.advertiser.IsAdvertising(serviceType)
}

// ---- Resolution Methods ----

// BrowseCommissionable discovers commissionable nodes on the network.
// Spec Section 4.3.1
func (m *Manager) BrowseCommissionable(ctx context.Context) (<-chan ResolvedService, error) {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrClosed
	}
	m.mu.RUnlock()

	return m.resolver.BrowseCommissionable(ctx)
}

// BrowseCommissionableByDiscriminator discovers commissionable nodes matching the discriminator.
func (m *Manager) BrowseCommissionableByDiscriminator(ctx context.Context, discriminator uint16) (<-chan ResolvedService, error) {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrClosed
	}
	m.mu.RUnlock()

	filter := LongDiscriminatorSubtype(discriminator)
	return m.resolver.BrowseCommissionableWithFilter(ctx, filter)
}

// BrowseCommissionableByVendor discovers commissionable nodes from a specific vendor.
func (m *Manager) BrowseCommissionableByVendor(ctx context.Context, vendorID fabric.VendorID) (<-chan ResolvedService, error) {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrClosed
	}
	m.mu.RUnlock()

	filter := VendorIDSubtype(vendorID)
	return m.resolver.BrowseCommissionableWithFilter(ctx, filter)
}

// BrowseOperational discovers operational nodes on the network.
// Spec Section 4.3.2
func (m *Manager) BrowseOperational(ctx context.Context) (<-chan ResolvedService, error) {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrClosed
	}
	m.mu.RUnlock()

	return m.resolver.BrowseOperational(ctx)
}

// BrowseCommissioner discovers commissioners on the network.
// Spec Section 4.3.3
func (m *Manager) BrowseCommissioner(ctx context.Context) (<-chan ResolvedService, error) {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrClosed
	}
	m.mu.RUnlock()

	return m.resolver.BrowseCommissioner(ctx)
}

// LookupOperational looks up a specific operational node.
// This is the primary method for finding a known commissioned node before
// establishing a CASE session.
// Spec Section 4.3.2
func (m *Manager) LookupOperational(ctx context.Context, compressedFabricID [8]byte, nodeID fabric.NodeID) (*ResolvedService, error) {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrClosed
	}
	m.mu.RUnlock()

	return m.resolver.LookupOperational(ctx, compressedFabricID, nodeID)
}

// DiscoverCommissionableNode finds a commissionable node by discriminator.
// This is a convenience method that browses and returns the first match.
func (m *Manager) DiscoverCommissionableNode(ctx context.Context, discriminator uint16) (*ResolvedService, error) {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrClosed
	}
	m.mu.RUnlock()

	return m.resolver.DiscoverCommissionableNode(ctx, discriminator)
}

// Advertiser returns the underlying Advertiser for advanced usage.
func (m *Manager) Advertiser() *Advertiser {
	return m.advertiser
}

// Resolver returns the underlying Resolver for advanced usage.
func (m *Manager) Resolver() *Resolver {
	return m.resolver
}
