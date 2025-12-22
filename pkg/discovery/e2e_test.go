// +build !race

package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/grandcat/zeroconf"
)

// TestE2E_CommissionableAdvertising tests real network mDNS advertising and discovery.
// This test uses actual zeroconf library to verify that:
// 1. Services can be advertised on the network
// 2. Services can be discovered by browsing
// 3. Subtypes work correctly for filtering
// 4. TXT records are correctly transmitted
//
// Note: This test requires network access and may be affected by firewall rules.
func TestE2E_CommissionableAdvertising(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	// Create advertiser with real zeroconf
	adv, err := NewAdvertiser(AdvertiserConfig{
		Port: 15540, // Use non-standard port to avoid conflicts
	})
	if err != nil {
		t.Fatalf("NewAdvertiser() error = %v", err)
	}
	defer adv.Close()

	// Start advertising a commissionable node
	txt := CommissionableTXT{
		Discriminator:     3840,
		VendorID:          0xFFF1, // Test vendor
		ProductID:         0x8001,
		DeviceName:        "Test Device",
		CommissioningMode: CommissioningModeBasic,
	}

	t.Logf("Starting commissionable advertising with discriminator=%d", txt.Discriminator)
	err = adv.StartCommissionable(txt)
	if err != nil {
		t.Fatalf("StartCommissionable() error = %v", err)
	}

	// Wait a moment for the service to be advertised
	time.Sleep(1 * time.Second)

	// Now try to discover it using a resolver
	t.Log("Starting discovery...")
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}

	entries := make(chan *zeroconf.ServiceEntry)
	foundService := make(chan *zeroconf.ServiceEntry, 1)

	go func() {
		for entry := range entries {
			t.Logf("Discovered service: %s on %s:%d", entry.Instance, entry.HostName, entry.Port)
			t.Logf("  Service: %s", entry.Service)
			t.Logf("  TXT: %v", entry.Text)

			// Check if this is our service
			if entry.Port == 15540 {
				select {
				case foundService <- entry:
				default:
				}
			}
		}
	}()

	// Browse for _matterc._udp services
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Log("Browsing for _matterc._udp services...")
	err = resolver.Browse(ctx, ServiceCommissionable, "local.", entries)
	if err != nil {
		t.Fatalf("Browse() error = %v", err)
	}

	// Wait for discovery or timeout
	select {
	case entry := <-foundService:
		t.Log("✓ Service discovered successfully!")

		// Verify the service details
		if entry.Port != 15540 {
			t.Errorf("Port = %d, want 15540", entry.Port)
		}

		// Verify TXT records contain our data
		foundDiscriminator := false
		foundVendorID := false
		foundMode := false

		for _, txtRecord := range entry.Text {
			t.Logf("  TXT record: %s", txtRecord)
			if txtRecord == "D=3840" {
				foundDiscriminator = true
			}
			if txtRecord == "VP=65521+32769" {
				foundVendorID = true
			}
			if txtRecord == "CM=1" {
				foundMode = true
			}
		}

		if !foundDiscriminator {
			t.Error("TXT record 'D=3840' not found")
		}
		if !foundVendorID {
			t.Error("TXT record 'VP=65521+32769' not found")
		}
		if !foundMode {
			t.Error("TXT record 'CM=1' not found")
		}

	case <-ctx.Done():
		t.Fatal("Timeout waiting for service discovery - service was not advertised on network")
	}
}

// TestE2E_SubtypeFiltering tests that DNS-SD subtypes work for filtered discovery.
// This verifies that we can discover services using subtype filters like _S15.
func TestE2E_SubtypeFiltering(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	// Create advertiser
	adv, err := NewAdvertiser(AdvertiserConfig{
		Port: 15541,
	})
	if err != nil {
		t.Fatalf("NewAdvertiser() error = %v", err)
	}
	defer adv.Close()

	// Start advertising with specific discriminator
	// Discriminator 3840 (0xF00) has short discriminator 15 (bits 8-11)
	txt := CommissionableTXT{
		Discriminator:     3840, // Short discriminator = 15
		VendorID:          0xFFF1,
		ProductID:         0x8001,
		DeviceName:        "Subtype Test",
		CommissioningMode: CommissioningModeBasic,
	}

	err = adv.StartCommissionable(txt)
	if err != nil {
		t.Fatalf("StartCommissionable() error = %v", err)
	}

	time.Sleep(1 * time.Second)

	// Try to discover using subtype filter
	// The service should be advertised as: _matterc._udp,_S15,_L3840,...
	t.Log("Attempting discovery with subtype filter _S15...")

	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}

	entries := make(chan *zeroconf.ServiceEntry)
	foundWithSubtype := make(chan bool, 1)

	go func() {
		for entry := range entries {
			t.Logf("Discovered via subtype: %s on port %d", entry.Instance, entry.Port)
			if entry.Port == 15541 {
				foundWithSubtype <- true
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Browse with subtype filter (format: _matterc._udp,_S15)
	subtypeService := ServiceCommissionable + ",_S15"
	t.Logf("Browsing for: %s", subtypeService)
	err = resolver.Browse(ctx, subtypeService, "local.", entries)
	if err != nil {
		t.Fatalf("Browse() error = %v", err)
	}

	// Check if discovery worked
	select {
	case <-foundWithSubtype:
		t.Log("✓ Subtype filtering works! Service discovered via _S15 subtype")
	case <-ctx.Done():
		t.Error("FAIL: Service not discoverable via subtype _S15")
		t.Log("This indicates grandcat/zeroconf may not properly support DNS-SD subtypes")
		t.Log("Expected to find service advertised as: _matterc._udp,_S15,_L3840,_CM,_V65521")
	}
}

// TestE2E_MultipleSubtypes tests that all subtypes are properly advertised.
func TestE2E_MultipleSubtypes(t *testing.T) {
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
		Discriminator:     3840,  // _S15, _L3840
		VendorID:          0xFFF1, // _V65521
		ProductID:         0x8001,
		DeviceName:        "Multi Subtype Test",
		CommissioningMode: CommissioningModeBasic, // _CM
		DeviceType:        0x0100, // _T256 (On/Off Light)
	}

	err = adv.StartCommissionable(txt)
	if err != nil {
		t.Fatalf("StartCommissionable() error = %v", err)
	}

	time.Sleep(1 * time.Second)

	// Test each subtype filter
	subtypes := []string{
		"_S15",    // Short discriminator
		"_L3840",  // Long discriminator
		"_CM",     // Commissioning mode
		"_V65521", // Vendor ID
		"_T256",   // Device type
	}

	for _, subtype := range subtypes {
		t.Run("subtype="+subtype, func(t *testing.T) {
			// Create a fresh resolver for each subtype to avoid Windows mDNS state issues
			resolver, err := zeroconf.NewResolver(nil)
			if err != nil {
				t.Fatalf("Failed to create resolver: %v", err)
			}

			entries := make(chan *zeroconf.ServiceEntry)
			found := make(chan bool, 1)

			go func() {
				for entry := range entries {
					if entry.Port == 15542 {
						t.Logf("  Found via %s: %s", subtype, entry.Instance)
						found <- true
						return
					}
				}
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			subtypeService := ServiceCommissionable + "," + subtype
			err = resolver.Browse(ctx, subtypeService, "local.", entries)
			if err != nil {
				t.Errorf("Browse(%s) error = %v", subtype, err)
				return
			}

			select {
			case <-found:
				t.Logf("✓ Subtype %s works", subtype)
			case <-ctx.Done():
				t.Errorf("✗ Subtype %s NOT working", subtype)
			}
		})
	}
}
