package discovery

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/backkem/matter/pkg/fabric"
	"github.com/pion/logging"
)

// DefaultPort is the default Matter port.
const DefaultPort = 5540

// MDNSServer is the interface for mDNS service registration.
// This allows for dependency injection in tests.
type MDNSServer interface {
	// Shutdown stops the server.
	Shutdown()
}

// ServiceRegistration describes a DNS-SD service instance to advertise.
type ServiceRegistration struct {
	// Instance is the service instance name (e.g., "DD200C20D25AE5F7").
	Instance string

	// Service is the service type (e.g., "_matterc._udp").
	Service string

	// Subtypes are the DNS-SD subtypes the instance is also advertised under
	// (e.g., "_L840"). Spec Section 4.3.1.
	Subtypes []string

	// Domain is the DNS-SD domain (e.g., "local.").
	Domain string

	// HostName is the target host name for the SRV record.
	// If empty, the factory picks one.
	HostName string

	// Port is the service port.
	Port int

	// Text contains the TXT record "key=value" strings.
	Text []string

	// Interfaces restricts advertising to these interfaces.
	// If nil, all interfaces are used.
	Interfaces []net.Interface
}

// MDNSServerFactory creates MDNSServer instances.
type MDNSServerFactory interface {
	// Register creates a new mDNS server for the given service.
	Register(reg ServiceRegistration) (MDNSServer, error)
}

// activeService tracks an active DNS-SD service registration.
type activeService struct {
	server       MDNSServer
	serviceType  ServiceType
	instanceName string
}

// AdvertiserConfig holds configuration for the Advertiser.
type AdvertiserConfig struct {
	// HostName is the mDNS host name (e.g., from MAC address).
	// If empty, a random name will be generated.
	HostName string

	// Port is the Matter port to advertise (default: 5540).
	Port int

	// Interfaces specifies which network interfaces to advertise on.
	// If nil, all interfaces are used.
	Interfaces []net.Interface

	// ServerFactory is the factory for creating mDNS servers.
	// If nil, the default pion/mdns factory is used.
	ServerFactory MDNSServerFactory

	// LoggerFactory for creating loggers.
	LoggerFactory logging.LoggerFactory
}

// Advertiser publishes DNS-SD services to the network.
type Advertiser struct {
	config   AdvertiserConfig
	factory  MDNSServerFactory
	log      logging.LeveledLogger
	mu       sync.RWMutex
	services map[ServiceType]*activeService
	closed   bool
}

// NewAdvertiser creates a new Advertiser with the given configuration.
func NewAdvertiser(config AdvertiserConfig) (*Advertiser, error) {
	if config.Port <= 0 || config.Port > 65535 {
		config.Port = DefaultPort
	}

	factory := config.ServerFactory
	if factory == nil {
		factory = &pionServerFactory{loggerFactory: config.LoggerFactory}
	}

	a := &Advertiser{
		config:   config,
		factory:  factory,
		services: make(map[ServiceType]*activeService),
	}

	if config.LoggerFactory != nil {
		a.log = config.LoggerFactory.NewLogger("discovery")
	}

	return a, nil
}

// StartCommissionable begins advertising the commissionable node discovery service.
// Service type: _matterc._udp
// Spec Section 4.3.1
func (a *Advertiser) StartCommissionable(txt CommissionableTXT) error {
	if err := txt.Validate(); err != nil {
		return fmt.Errorf("advertiser: commissionable txt validation failed: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return ErrClosed
	}

	if _, exists := a.services[ServiceTypeCommissionable]; exists {
		return ErrAlreadyStarted
	}

	// Generate random instance name
	instanceName, err := generateRandomInstanceName()
	if err != nil {
		return fmt.Errorf("advertiser: failed to generate instance name: %w", err)
	}

	// Build subtypes for discovery filtering
	// _S<short> for short discriminator, _L<long> for long discriminator
	// _CM for commissioning mode, _V<vid> for vendor ID
	shortDiscrim := txt.ShortDiscriminator()
	subtypes := []string{
		fmt.Sprintf("_S%d", shortDiscrim),
		fmt.Sprintf("_L%d", txt.Discriminator),
	}

	if txt.CommissioningMode > CommissioningModeDisabled {
		subtypes = append(subtypes, "_CM")
	}

	if txt.VendorID != 0 {
		subtypes = append(subtypes, fmt.Sprintf("_V%d", txt.VendorID))
	}

	if txt.DeviceType != 0 {
		subtypes = append(subtypes, fmt.Sprintf("_T%d", txt.DeviceType))
	}

	service := ServiceCommissionable
	txtRecords := txt.Encode()
	if a.log != nil {
		a.log.Debugf("Registering mDNS service: instance=%s service=%s domain=%s port=%d subtypes=%v",
			instanceName, service, DefaultDomain, a.config.Port, subtypes)
		a.log.Tracef("TXT records: %v", txtRecords)
	}

	server, err := a.factory.Register(a.registration(instanceName, service, subtypes, txtRecords))
	if err != nil {
		return fmt.Errorf("advertiser: mDNS registration failed for %s: %w", service, err)
	}

	if a.log != nil {
		a.log.Infof("mDNS registration successful for %s", service)
	}

	a.services[ServiceTypeCommissionable] = &activeService{
		server:       server,
		serviceType:  ServiceTypeCommissionable,
		instanceName:  instanceName,
	}

	return nil
}

// StartOperational begins advertising the operational discovery service.
// Service type: _matter._tcp
// Spec Section 4.3.2
func (a *Advertiser) StartOperational(compressedFabricID [8]byte, nodeID fabric.NodeID, txt OperationalTXT) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return ErrClosed
	}

	if _, exists := a.services[ServiceTypeOperational]; exists {
		return ErrAlreadyStarted
	}

	instanceName := OperationalInstanceName(compressedFabricID, nodeID)

	server, err := a.factory.Register(a.registration(instanceName, ServiceOperational, nil, txt.Encode()))
	if err != nil {
		return err
	}

	a.services[ServiceTypeOperational] = &activeService{
		server:       server,
		serviceType:  ServiceTypeOperational,
		instanceName: instanceName,
	}

	return nil
}

// StartCommissioner begins advertising the commissioner discovery service.
// Service type: _matterd._udp
// Spec Section 4.3.3
func (a *Advertiser) StartCommissioner(txt CommissionerTXT) error {
	if err := txt.Validate(); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return ErrClosed
	}

	if _, exists := a.services[ServiceTypeCommissioner]; exists {
		return ErrAlreadyStarted
	}

	// Generate random instance name
	instanceName, err := generateRandomInstanceName()
	if err != nil {
		return err
	}

	// Build subtypes for filtering
	var subtypes []string

	if txt.VendorID != 0 {
		subtypes = append(subtypes, fmt.Sprintf("_V%d", txt.VendorID))
	}

	if txt.DeviceType != 0 {
		subtypes = append(subtypes, fmt.Sprintf("_T%d", txt.DeviceType))
	}

	server, err := a.factory.Register(a.registration(instanceName, ServiceCommissioner, subtypes, txt.Encode()))
	if err != nil {
		return err
	}

	a.services[ServiceTypeCommissioner] = &activeService{
		server:       server,
		serviceType:  ServiceTypeCommissioner,
		instanceName: instanceName,
	}

	return nil
}

// registration builds a ServiceRegistration using the advertiser's config.
func (a *Advertiser) registration(instance, service string, subtypes, txt []string) ServiceRegistration {
	return ServiceRegistration{
		Instance:   instance,
		Service:    service,
		Subtypes:   subtypes,
		Domain:     DefaultDomain,
		HostName:   a.config.HostName,
		Port:       a.config.Port,
		Text:       txt,
		Interfaces: a.config.Interfaces,
	}
}

// Stop stops advertising a specific service type.
func (a *Advertiser) Stop(serviceType ServiceType) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return ErrClosed
	}

	svc, exists := a.services[serviceType]
	if !exists {
		return ErrNotStarted
	}

	svc.server.Shutdown()
	delete(a.services, serviceType)

	return nil
}

// StopAll stops all active service advertisements.
func (a *Advertiser) StopAll() {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, svc := range a.services {
		svc.server.Shutdown()
	}
	a.services = make(map[ServiceType]*activeService)
}

// Close stops all services and closes the advertiser.
func (a *Advertiser) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return ErrClosed
	}

	for _, svc := range a.services {
		svc.server.Shutdown()
	}
	a.services = nil
	a.closed = true

	return nil
}

// IsAdvertising returns true if the given service type is currently being advertised.
func (a *Advertiser) IsAdvertising(serviceType ServiceType) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	_, exists := a.services[serviceType]
	return exists
}

// GetInstanceName returns the instance name for an active service.
// Returns empty string if the service is not active.
func (a *Advertiser) GetInstanceName(serviceType ServiceType) string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if svc, exists := a.services[serviceType]; exists {
		return svc.instanceName
	}
	return ""
}

// generateRandomInstanceName generates a random 64-bit instance name.
// Format: 16 uppercase hex characters.
func generateRandomInstanceName() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%016X", binary.BigEndian.Uint64(buf[:])), nil
}

// AdvertiserWithContext wraps an Advertiser with context support.
type AdvertiserWithContext struct {
	*Advertiser
	ctx    context.Context
	cancel context.CancelFunc
}

// NewAdvertiserWithContext creates an Advertiser that can be cancelled via context.
func NewAdvertiserWithContext(ctx context.Context, config AdvertiserConfig) (*AdvertiserWithContext, error) {
	adv, err := NewAdvertiser(config)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)

	awc := &AdvertiserWithContext{
		Advertiser: adv,
		ctx:        ctx,
		cancel:     cancel,
	}

	// Monitor context for cancellation
	go func() {
		<-ctx.Done()
		adv.Close()
	}()

	return awc, nil
}

// Close cancels the context and closes the advertiser.
func (a *AdvertiserWithContext) Close() error {
	a.cancel()
	return a.Advertiser.Close()
}
