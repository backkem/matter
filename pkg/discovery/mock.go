package discovery

import (
	"context"
	"net"
	"sync"
)

// MockMDNSResolver provides a mock mDNS resolver for testing without real network I/O.
// It allows registering services and simulating discovery responses.
type MockMDNSResolver struct {
	mu       sync.RWMutex
	services map[string][]*ServiceEntry
}

// NewMockMDNSResolver creates a new mock resolver.
func NewMockMDNSResolver() *MockMDNSResolver {
	return &MockMDNSResolver{
		services: make(map[string][]*ServiceEntry),
	}
}

// RegisterService registers a service that will be returned by Browse/Lookup.
func (m *MockMDNSResolver) RegisterService(service string, entry *ServiceEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.services[service] = append(m.services[service], entry)
}

// ClearServices removes all registered services.
func (m *MockMDNSResolver) ClearServices() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.services = make(map[string][]*ServiceEntry)
}

// Browse implements MDNSResolver.
func (m *MockMDNSResolver) Browse(ctx context.Context, service, domain string, entries chan<- *ServiceEntry) error {
	m.mu.RLock()
	svcEntries := make([]*ServiceEntry, len(m.services[service]))
	copy(svcEntries, m.services[service])
	m.mu.RUnlock()

	// Send entries synchronously to avoid races with channel closing.
	// This is test code so blocking behavior is acceptable.
	for _, entry := range svcEntries {
		select {
		case entries <- entry:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// Lookup implements MDNSResolver.
func (m *MockMDNSResolver) Lookup(ctx context.Context, instance, service, domain string, entries chan<- *ServiceEntry) error {
	m.mu.RLock()
	svcEntries := make([]*ServiceEntry, len(m.services[service]))
	copy(svcEntries, m.services[service])
	m.mu.RUnlock()

	// Send entries synchronously to avoid races with channel closing.
	for _, entry := range svcEntries {
		if entry.Instance == instance {
			select {
			case entries <- entry:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		}
	}

	return nil
}

// MockCommissionableService creates a mock commissionable service entry for testing.
func MockCommissionableService(instanceName string, port int, ip net.IP, discriminator uint16) *ServiceEntry {
	return &ServiceEntry{
		Instance: instanceName,
		Service:  ServiceCommissionable,
		Domain:   DefaultDomain,
		HostName: instanceName + ".local.",
		Port:     port,
		AddrIPv4: []net.IP{ip},
		Text: []string{
			"D=" + itoa(int(discriminator)),
			"CM=1",
			"VP=65521+32769",
		},
	}
}

// MockOperationalService creates a mock operational service entry for testing.
func MockOperationalService(compressedFabricID [8]byte, nodeID uint64, port int, ip net.IP) *ServiceEntry {
	instanceName := OperationalInstanceNameFromBytes(compressedFabricID[:], nodeID)
	return &ServiceEntry{
		Instance: instanceName,
		Service:  ServiceOperational,
		Domain:   DefaultDomain,
		HostName: instanceName + ".local.",
		Port:     port,
		AddrIPv4: []net.IP{ip},
		Text:     []string{},
	}
}

// OperationalInstanceNameFromBytes creates an operational instance name from raw bytes.
func OperationalInstanceNameFromBytes(compressedFabricID []byte, nodeID uint64) string {
	// Format: <CompressedFabricID>-<NodeID> in uppercase hex
	fabricHex := ""
	for _, b := range compressedFabricID {
		fabricHex += hexByte(b)
	}
	nodeHex := hexUint64(nodeID)
	return fabricHex + "-" + nodeHex
}

func hexByte(b byte) string {
	const hexChars = "0123456789ABCDEF"
	return string([]byte{hexChars[b>>4], hexChars[b&0x0F]})
}

func hexUint64(v uint64) string {
	if v == 0 {
		return "0"
	}
	const hexChars = "0123456789ABCDEF"
	var buf [16]byte
	pos := 16
	for v > 0 {
		pos--
		buf[pos] = hexChars[v&0x0F]
		v >>= 4
	}
	return string(buf[pos:])
}
