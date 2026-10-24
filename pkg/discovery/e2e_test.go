//go:build !race
// +build !race

package discovery

import (
	"context"
	"testing"
	"time"
)

// waitForPort drains services until one with the given port arrives.
func waitForPort(services <-chan ResolvedService, port int) (*ResolvedService, bool) {
	for svc := range services {
		if svc.Port == port {
			return &svc, true
		}
	}
	return nil, false
}

// TestE2E_CommissionableAdvertising tests real network mDNS advertising and discovery.
// It verifies that:
// 1. Services can be advertised on the network
// 2. Services can be discovered by browsing
// 3. TXT records are correctly transmitted
//
// Note: This test requires network access and may be affected by firewall rules.
func TestE2E_CommissionableAdvertising(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	adv, err := NewAdvertiser(AdvertiserConfig{
		Port: 15540, // Use non-standard port to avoid conflicts
	})
	if err != nil {
		t.Fatalf("NewAdvertiser() error = %v", err)
	}
	defer adv.Close()

	txt := CommissionableTXT{
		Discriminator:     3840,
		VendorID:          0xFFF1, // Test vendor
		ProductID:         0x8001,
		DeviceName:        "Test Device",
		CommissioningMode: CommissioningModeBasic,
	}

	t.Logf("Starting commissionable advertising with discriminator=%d", txt.Discriminator)
	if err := adv.StartCommissionable(txt); err != nil {
		t.Fatalf("StartCommissionable() error = %v", err)
	}

	resolver, err := NewResolver(ResolverConfig{})
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	services, err := resolver.BrowseCommissionable(ctx)
	if err != nil {
		t.Fatalf("BrowseCommissionable() error = %v", err)
	}

	svc, ok := waitForPort(services, 15540)
	if !ok {
		t.Fatal("Timeout waiting for service discovery - service was not advertised on network")
	}

	t.Logf("Discovered %s on %s:%d (IPs %v)", svc.InstanceName, svc.HostName, svc.Port, svc.IPs)
	want := map[string]string{"D": "3840", "VP": "65521+32769", "CM": "1"}
	for k, v := range want {
		if got := svc.Text[k]; got != v {
			t.Errorf("TXT %s = %q, want %q", k, got, v)
		}
	}
	if len(svc.IPs) == 0 {
		t.Error("no addresses resolved")
	}
}

// TestE2E_Subtypes tests that every advertised subtype can be used for
// filtered discovery.
func TestE2E_Subtypes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	adv, err := NewAdvertiser(AdvertiserConfig{
		Port: 15542,
	})
	if err != nil {
		t.Fatalf("NewAdvertiser() error = %v", err)
	}
	defer adv.Close()

	txt := CommissionableTXT{
		Discriminator:     3840,   // _S15, _L3840
		VendorID:          0xFFF1, // _V65521
		ProductID:         0x8001,
		DeviceName:        "Multi Subtype Test",
		CommissioningMode: CommissioningModeBasic, // _CM
		DeviceType:        0x0100,                 // _T256 (On/Off Light)
	}

	if err := adv.StartCommissionable(txt); err != nil {
		t.Fatalf("StartCommissionable() error = %v", err)
	}

	resolver, err := NewResolver(ResolverConfig{})
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}

	for _, subtype := range []string{"_S15", "_L3840", "_CM", "_V65521", "_T256"} {
		t.Run("subtype="+subtype, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			services, err := resolver.BrowseCommissionableWithFilter(ctx, subtype)
			if err != nil {
				t.Fatalf("BrowseCommissionableWithFilter(%s) error = %v", subtype, err)
			}
			if _, ok := waitForPort(services, 15542); !ok {
				t.Errorf("service not discoverable via subtype %s", subtype)
			}
		})
	}

	t.Run("non-matching subtype", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		services, err := resolver.BrowseCommissionableWithFilter(ctx, "_L1234")
		if err != nil {
			t.Fatalf("BrowseCommissionableWithFilter error = %v", err)
		}
		if _, ok := waitForPort(services, 15542); ok {
			t.Error("service discovered via a subtype it does not advertise")
		}
	})

	t.Run("DiscoverCommissionableNode", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		svc, err := resolver.DiscoverCommissionableNode(ctx, 3840)
		if err != nil {
			t.Fatalf("DiscoverCommissionableNode() error = %v", err)
		}
		if svc.Text["D"] != "3840" {
			t.Errorf("D = %q, want 3840", svc.Text["D"])
		}
	})
}

// TestE2E_OperationalLookup tests advertising an operational instance and
// resolving it by instance name.
func TestE2E_OperationalLookup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	adv, err := NewAdvertiser(AdvertiserConfig{Port: 15543})
	if err != nil {
		t.Fatalf("NewAdvertiser() error = %v", err)
	}
	defer adv.Close()

	cfid := [8]byte{0x87, 0xE1, 0xB0, 0x04, 0xE2, 0x35, 0xA1, 0x30}
	if err := adv.StartOperational(cfid, 0x8FC7772401CD0696, OperationalTXT{}); err != nil {
		t.Fatalf("StartOperational() error = %v", err)
	}

	resolver, err := NewResolver(ResolverConfig{})
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	svc, err := resolver.LookupOperational(ctx, cfid, 0x8FC7772401CD0696)
	if err != nil {
		t.Fatalf("LookupOperational() error = %v", err)
	}
	if svc.Port != 15543 {
		t.Errorf("Port = %d, want 15543", svc.Port)
	}
	if svc.InstanceName != "87E1B004E235A130-8FC7772401CD0696" {
		t.Errorf("InstanceName = %q", svc.InstanceName)
	}
}
