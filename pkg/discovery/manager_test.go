package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/backkem/matter/pkg/fabric"
)

func TestNewManager(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		factory := newMockMDNSServerFactory()
		mgr, err := NewManager(ManagerConfig{
			ServerFactory: factory,
		})
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		if mgr == nil {
			t.Fatal("NewManager() returned nil")
		}
		if mgr.config.Port != DefaultPort {
			t.Errorf("Port = %d, want %d", mgr.config.Port, DefaultPort)
		}
		if mgr.config.BrowseTimeout != DefaultBrowseTimeout {
			t.Errorf("BrowseTimeout = %v, want %v", mgr.config.BrowseTimeout, DefaultBrowseTimeout)
		}
		if mgr.config.LookupTimeout != DefaultLookupTimeout {
			t.Errorf("LookupTimeout = %v, want %v", mgr.config.LookupTimeout, DefaultLookupTimeout)
		}
	})

	t.Run("custom config", func(t *testing.T) {
		factory := newMockMDNSServerFactory()
		mgr, err := NewManager(ManagerConfig{
			Port:          12345,
			BrowseTimeout: 5 * time.Second,
			LookupTimeout: 2 * time.Second,
			ServerFactory: factory,
		})
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		if mgr.config.Port != 12345 {
			t.Errorf("Port = %d, want 12345", mgr.config.Port)
		}
		if mgr.config.BrowseTimeout != 5*time.Second {
			t.Errorf("BrowseTimeout = %v, want 5s", mgr.config.BrowseTimeout)
		}
	})
}

func TestManager_Advertising(t *testing.T) {
	factory := newMockMDNSServerFactory()
	mgr, err := NewManager(ManagerConfig{
		Port:          5540,
		ServerFactory: factory,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	t.Run("StartCommissionable", func(t *testing.T) {
		err := mgr.StartCommissionable(CommissionableTXT{
			Discriminator:     840,
			CommissioningMode: CommissioningModeBasic,
		})
		if err != nil {
			t.Fatalf("StartCommissionable() error = %v", err)
		}

		if !mgr.IsAdvertising(ServiceTypeCommissionable) {
			t.Error("IsAdvertising(Commissionable) = false, want true")
		}
	})

	t.Run("StartOperational", func(t *testing.T) {
		compressedFabricID := [8]byte{0x87, 0xE1, 0xB0, 0x04, 0xE2, 0x35, 0xA1, 0x30}
		nodeID := fabric.NodeID(0x8FC7772401CD0696)

		err := mgr.StartOperational(compressedFabricID, nodeID, OperationalTXT{})
		if err != nil {
			t.Fatalf("StartOperational() error = %v", err)
		}

		if !mgr.IsAdvertising(ServiceTypeOperational) {
			t.Error("IsAdvertising(Operational) = false, want true")
		}
	})

	t.Run("StartCommissioner", func(t *testing.T) {
		err := mgr.StartCommissioner(CommissionerTXT{
			VendorID: 123,
		})
		if err != nil {
			t.Fatalf("StartCommissioner() error = %v", err)
		}

		if !mgr.IsAdvertising(ServiceTypeCommissioner) {
			t.Error("IsAdvertising(Commissioner) = false, want true")
		}
	})

	t.Run("StopAdvertising", func(t *testing.T) {
		err := mgr.StopAdvertising(ServiceTypeCommissionable)
		if err != nil {
			t.Fatalf("StopAdvertising() error = %v", err)
		}

		if mgr.IsAdvertising(ServiceTypeCommissionable) {
			t.Error("IsAdvertising(Commissionable) = true after stop, want false")
		}
	})

	t.Run("StopAllAdvertising", func(t *testing.T) {
		mgr.StopAllAdvertising()

		if mgr.IsAdvertising(ServiceTypeOperational) {
			t.Error("IsAdvertising(Operational) = true after StopAll, want false")
		}
		if mgr.IsAdvertising(ServiceTypeCommissioner) {
			t.Error("IsAdvertising(Commissioner) = true after StopAll, want false")
		}
	})
}

func TestManager_Close(t *testing.T) {
	factory := newMockMDNSServerFactory()
	mgr, err := NewManager(ManagerConfig{
		ServerFactory: factory,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	// Start some services
	mgr.StartCommissionable(CommissionableTXT{Discriminator: 840})

	t.Run("close succeeds", func(t *testing.T) {
		err := mgr.Close()
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})

	t.Run("close again returns error", func(t *testing.T) {
		err := mgr.Close()
		if err != ErrClosed {
			t.Errorf("Close() error = %v, want %v", err, ErrClosed)
		}
	})

	t.Run("operations after close fail", func(t *testing.T) {
		err := mgr.StartCommissionable(CommissionableTXT{})
		if err != ErrClosed {
			t.Errorf("StartCommissionable() after Close() error = %v, want %v", err, ErrClosed)
		}

		_, err = mgr.BrowseCommissionable(context.Background())
		if err != ErrClosed {
			t.Errorf("BrowseCommissionable() after Close() error = %v, want %v", err, ErrClosed)
		}
	})
}

func TestManager_Accessors(t *testing.T) {
	factory := newMockMDNSServerFactory()
	mgr, err := NewManager(ManagerConfig{
		ServerFactory: factory,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if mgr.Advertiser() == nil {
		t.Error("Advertiser() returned nil")
	}

	if mgr.Resolver() == nil {
		t.Error("Resolver() returned nil")
	}
}
