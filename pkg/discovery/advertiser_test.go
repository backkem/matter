package discovery

import (
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/backkem/matter/pkg/fabric"
)

// mockMDNSServer is a mock implementation of MDNSServer for testing.
type mockMDNSServer struct {
	shutdownCalled bool
}

func (m *mockMDNSServer) Shutdown() {
	m.shutdownCalled = true
}

// mockMDNSServerFactory is a mock implementation of MDNSServerFactory for testing.
type mockMDNSServerFactory struct {
	mu       sync.Mutex
	servers  []*mockMDNSServer
	lastArgs struct {
		instance string
		service  string
		domain   string
		port     int
		txt      []string
	}
	shouldFail bool
}

func newMockMDNSServerFactory() *mockMDNSServerFactory {
	return &mockMDNSServerFactory{}
}

func (f *mockMDNSServerFactory) Register(instance, service, domain string, port int, txt []string, ifaces []net.Interface) (MDNSServer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.shouldFail {
		return nil, ErrClosed
	}

	f.lastArgs.instance = instance
	f.lastArgs.service = service
	f.lastArgs.domain = domain
	f.lastArgs.port = port
	f.lastArgs.txt = txt

	server := &mockMDNSServer{}
	f.servers = append(f.servers, server)
	return server, nil
}

func TestNewAdvertiser(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		adv, err := NewAdvertiser(AdvertiserConfig{})
		if err != nil {
			t.Fatalf("NewAdvertiser() error = %v", err)
		}
		if adv == nil {
			t.Fatal("NewAdvertiser() returned nil")
		}
		if adv.config.Port != DefaultPort {
			t.Errorf("Port = %d, want %d", adv.config.Port, DefaultPort)
		}
	})

	t.Run("custom port", func(t *testing.T) {
		adv, err := NewAdvertiser(AdvertiserConfig{Port: 12345})
		if err != nil {
			t.Fatalf("NewAdvertiser() error = %v", err)
		}
		if adv.config.Port != 12345 {
			t.Errorf("Port = %d, want 12345", adv.config.Port)
		}
	})

	t.Run("invalid port uses default", func(t *testing.T) {
		adv, err := NewAdvertiser(AdvertiserConfig{Port: -1})
		if err != nil {
			t.Fatalf("NewAdvertiser() error = %v", err)
		}
		if adv.config.Port != DefaultPort {
			t.Errorf("Port = %d, want %d", adv.config.Port, DefaultPort)
		}
	})
}

func TestAdvertiser_StartCommissionable(t *testing.T) {
	factory := newMockMDNSServerFactory()
	adv, err := NewAdvertiser(AdvertiserConfig{
		Port:          5540,
		ServerFactory: factory,
	})
	if err != nil {
		t.Fatalf("NewAdvertiser() error = %v", err)
	}

	txt := CommissionableTXT{
		Discriminator:     840,
		CommissioningMode: CommissioningModeEnhanced,
		VendorID:          123,
		ProductID:         456,
	}

	t.Run("starts successfully", func(t *testing.T) {
		err := adv.StartCommissionable(txt)
		if err != nil {
			t.Fatalf("StartCommissionable() error = %v", err)
		}

		if !adv.IsAdvertising(ServiceTypeCommissionable) {
			t.Error("IsAdvertising(Commissionable) = false, want true")
		}

		// Verify factory was called
		if factory.lastArgs.port != 5540 {
			t.Errorf("port = %d, want 5540", factory.lastArgs.port)
		}
		if factory.lastArgs.domain != DefaultDomain {
			t.Errorf("domain = %q, want %q", factory.lastArgs.domain, DefaultDomain)
		}
	})

	t.Run("already started", func(t *testing.T) {
		err := adv.StartCommissionable(txt)
		if err != ErrAlreadyStarted {
			t.Errorf("StartCommissionable() error = %v, want %v", err, ErrAlreadyStarted)
		}
	})

	t.Run("stop and restart", func(t *testing.T) {
		err := adv.Stop(ServiceTypeCommissionable)
		if err != nil {
			t.Fatalf("Stop() error = %v", err)
		}

		if adv.IsAdvertising(ServiceTypeCommissionable) {
			t.Error("IsAdvertising(Commissionable) = true after stop, want false")
		}

		// Should be able to start again
		err = adv.StartCommissionable(txt)
		if err != nil {
			t.Fatalf("StartCommissionable() after stop error = %v", err)
		}
	})

	t.Run("invalid discriminator", func(t *testing.T) {
		adv2, _ := NewAdvertiser(AdvertiserConfig{ServerFactory: factory})
		err := adv2.StartCommissionable(CommissionableTXT{
			Discriminator: 0x1000, // Too large
		})
		if !errors.Is(err, ErrInvalidDiscriminator) {
			t.Errorf("StartCommissionable() error = %v, want %v", err, ErrInvalidDiscriminator)
		}
	})
}

func TestAdvertiser_StartOperational(t *testing.T) {
	factory := newMockMDNSServerFactory()
	adv, err := NewAdvertiser(AdvertiserConfig{
		Port:          5540,
		ServerFactory: factory,
	})
	if err != nil {
		t.Fatalf("NewAdvertiser() error = %v", err)
	}

	compressedFabricID := [8]byte{0x87, 0xE1, 0xB0, 0x04, 0xE2, 0x35, 0xA1, 0x30}
	nodeID := fabric.NodeID(0x8FC7772401CD0696)
	txt := OperationalTXT{
		TCPSupported: true,
	}

	t.Run("starts successfully", func(t *testing.T) {
		err := adv.StartOperational(compressedFabricID, nodeID, txt)
		if err != nil {
			t.Fatalf("StartOperational() error = %v", err)
		}

		if !adv.IsAdvertising(ServiceTypeOperational) {
			t.Error("IsAdvertising(Operational) = false, want true")
		}

		// Verify instance name
		expectedInstance := "87E1B004E235A130-8FC7772401CD0696"
		if factory.lastArgs.instance != expectedInstance {
			t.Errorf("instance = %q, want %q", factory.lastArgs.instance, expectedInstance)
		}
	})

	t.Run("already started", func(t *testing.T) {
		err := adv.StartOperational(compressedFabricID, nodeID, txt)
		if err != ErrAlreadyStarted {
			t.Errorf("StartOperational() error = %v, want %v", err, ErrAlreadyStarted)
		}
	})
}

func TestAdvertiser_StartCommissioner(t *testing.T) {
	factory := newMockMDNSServerFactory()
	adv, err := NewAdvertiser(AdvertiserConfig{
		Port:          33333,
		ServerFactory: factory,
	})
	if err != nil {
		t.Fatalf("NewAdvertiser() error = %v", err)
	}

	txt := CommissionerTXT{
		VendorID:             123,
		ProductID:            456,
		DeviceType:           35,
		DeviceName:           "Living Room TV",
		CommissionerPasscode: true,
	}

	t.Run("starts successfully", func(t *testing.T) {
		err := adv.StartCommissioner(txt)
		if err != nil {
			t.Fatalf("StartCommissioner() error = %v", err)
		}

		if !adv.IsAdvertising(ServiceTypeCommissioner) {
			t.Error("IsAdvertising(Commissioner) = false, want true")
		}

		if factory.lastArgs.port != 33333 {
			t.Errorf("port = %d, want 33333", factory.lastArgs.port)
		}
	})
}

func TestAdvertiser_Close(t *testing.T) {
	factory := newMockMDNSServerFactory()
	adv, err := NewAdvertiser(AdvertiserConfig{
		ServerFactory: factory,
	})
	if err != nil {
		t.Fatalf("NewAdvertiser() error = %v", err)
	}

	// Start some services
	adv.StartCommissionable(CommissionableTXT{Discriminator: 840})
	adv.StartCommissioner(CommissionerTXT{})

	t.Run("close stops all services", func(t *testing.T) {
		err := adv.Close()
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}

		// All servers should be shut down
		for i, server := range factory.servers {
			if !server.shutdownCalled {
				t.Errorf("server[%d].shutdownCalled = false, want true", i)
			}
		}
	})

	t.Run("close again returns error", func(t *testing.T) {
		err := adv.Close()
		if err != ErrClosed {
			t.Errorf("Close() error = %v, want %v", err, ErrClosed)
		}
	})

	t.Run("operations after close fail", func(t *testing.T) {
		err := adv.StartCommissionable(CommissionableTXT{})
		if err != ErrClosed {
			t.Errorf("StartCommissionable() after Close() error = %v, want %v", err, ErrClosed)
		}
	})
}

func TestAdvertiser_GetInstanceName(t *testing.T) {
	factory := newMockMDNSServerFactory()
	adv, err := NewAdvertiser(AdvertiserConfig{
		ServerFactory: factory,
	})
	if err != nil {
		t.Fatalf("NewAdvertiser() error = %v", err)
	}

	t.Run("returns empty for non-active service", func(t *testing.T) {
		name := adv.GetInstanceName(ServiceTypeCommissionable)
		if name != "" {
			t.Errorf("GetInstanceName() = %q, want empty", name)
		}
	})

	t.Run("returns instance name for active service", func(t *testing.T) {
		compressedFabricID := [8]byte{0x87, 0xE1, 0xB0, 0x04, 0xE2, 0x35, 0xA1, 0x30}
		nodeID := fabric.NodeID(0x8FC7772401CD0696)
		adv.StartOperational(compressedFabricID, nodeID, OperationalTXT{})

		name := adv.GetInstanceName(ServiceTypeOperational)
		expected := "87E1B004E235A130-8FC7772401CD0696"
		if name != expected {
			t.Errorf("GetInstanceName() = %q, want %q", name, expected)
		}
	})
}

func TestAdvertiser_StopNotStarted(t *testing.T) {
	factory := newMockMDNSServerFactory()
	adv, err := NewAdvertiser(AdvertiserConfig{
		ServerFactory: factory,
	})
	if err != nil {
		t.Fatalf("NewAdvertiser() error = %v", err)
	}

	err = adv.Stop(ServiceTypeCommissionable)
	if err != ErrNotStarted {
		t.Errorf("Stop() error = %v, want %v", err, ErrNotStarted)
	}
}
