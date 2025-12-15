package discovery

import (
	"net"
	"testing"

	"github.com/backkem/matter/pkg/fabric"
)

func TestOperationalInstanceName(t *testing.T) {
	tests := []struct {
		compressedFabricID [8]byte
		nodeID             fabric.NodeID
		want               string
	}{
		{
			compressedFabricID: [8]byte{0x29, 0x06, 0xC9, 0x08, 0xD1, 0x15, 0xD3, 0x62},
			nodeID:             fabric.NodeID(0x8FC7772401CD0696),
			want:               "2906C908D115D362-8FC7772401CD0696",
		},
		{
			compressedFabricID: [8]byte{0x87, 0xE1, 0xB0, 0x04, 0xE2, 0x35, 0xA1, 0x30},
			nodeID:             fabric.NodeID(0x8FC7772401CD0696),
			want:               "87E1B004E235A130-8FC7772401CD0696",
		},
		{
			compressedFabricID: [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			nodeID:             fabric.NodeID(1),
			want:               "0000000000000001-0000000000000001",
		},
	}

	for _, tt := range tests {
		got := OperationalInstanceName(tt.compressedFabricID, tt.nodeID)
		if got != tt.want {
			t.Errorf("OperationalInstanceName(%x, %x) = %q, want %q",
				tt.compressedFabricID, tt.nodeID, got, tt.want)
		}
	}
}

func TestParseOperationalInstanceName(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		cfid, nodeID, err := ParseOperationalInstanceName("2906C908D115D362-8FC7772401CD0696")
		if err != nil {
			t.Fatalf("ParseOperationalInstanceName() error = %v", err)
		}

		wantCFID := [8]byte{0x29, 0x06, 0xC9, 0x08, 0xD1, 0x15, 0xD3, 0x62}
		wantNodeID := fabric.NodeID(0x8FC7772401CD0696)

		if cfid != wantCFID {
			t.Errorf("compressedFabricID = %x, want %x", cfid, wantCFID)
		}
		if nodeID != wantNodeID {
			t.Errorf("nodeID = %x, want %x", nodeID, wantNodeID)
		}
	})

	t.Run("roundtrip", func(t *testing.T) {
		originalCFID := [8]byte{0x87, 0xE1, 0xB0, 0x04, 0xE2, 0x35, 0xA1, 0x30}
		originalNodeID := fabric.NodeID(0x8FC7772401CD0696)

		name := OperationalInstanceName(originalCFID, originalNodeID)
		cfid, nodeID, err := ParseOperationalInstanceName(name)
		if err != nil {
			t.Fatalf("ParseOperationalInstanceName() error = %v", err)
		}

		if cfid != originalCFID {
			t.Errorf("compressedFabricID = %x, want %x", cfid, originalCFID)
		}
		if nodeID != originalNodeID {
			t.Errorf("nodeID = %x, want %x", nodeID, originalNodeID)
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		invalidNames := []string{
			"",
			"invalid",
			"2906C908D115D362",                       // Missing node ID
			"2906C908D115D362-",                      // Empty node ID
			"-8FC7772401CD0696",                      // Empty fabric ID
			"ZZZZZZZZZZZZZZZZ-8FC7772401CD0696",      // Invalid hex
			"2906C908D115D362-ZZZZZZZZZZZZZZZZ",      // Invalid hex
			"2906C908D115D362_8FC7772401CD0696",      // Wrong separator
			"2906C908D115D36-8FC7772401CD0696",       // Short fabric ID
			"2906C908D115D362-8FC7772401CD069",       // Short node ID
			"2906C908D115D3622-8FC7772401CD0696",     // Long fabric ID
			"2906C908D115D362-8FC7772401CD06966",     // Long node ID
		}

		for _, name := range invalidNames {
			_, _, err := ParseOperationalInstanceName(name)
			if err != ErrInvalidInstanceName {
				t.Errorf("ParseOperationalInstanceName(%q) error = %v, want %v", name, err, ErrInvalidInstanceName)
			}
		}
	})
}

func TestSortIPsByPreference(t *testing.T) {
	t.Run("mixed addresses", func(t *testing.T) {
		ips := []net.IP{
			net.ParseIP("fe80::1"),            // Link-local IPv6
			net.ParseIP("192.168.1.1"),        // IPv4 private
			net.ParseIP("2001:db8::1"),        // Global IPv6
			net.ParseIP("fd00::1"),            // ULA IPv6
			net.ParseIP("::1"),                // Loopback
		}

		sorted := SortIPsByPreference(ips)

		// Expected order: Global > ULA > Link-local > IPv4 > Loopback
		// Note: 2001:db8::/32 is documentation prefix, treated as global unicast
		if len(sorted) != 5 {
			t.Fatalf("SortIPsByPreference() returned %d IPs, want 5", len(sorted))
		}

		// First should be global IPv6 (2001:db8::1)
		if !sorted[0].Equal(net.ParseIP("2001:db8::1")) {
			t.Errorf("sorted[0] = %v, want 2001:db8::1 (global)", sorted[0])
		}

		// ULA should be next (fd00::1)
		if !sorted[1].Equal(net.ParseIP("fd00::1")) {
			t.Errorf("sorted[1] = %v, want fd00::1 (ULA)", sorted[1])
		}

		// Link-local IPv6 (fe80::1)
		if !sorted[2].Equal(net.ParseIP("fe80::1")) {
			t.Errorf("sorted[2] = %v, want fe80::1 (link-local)", sorted[2])
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		sorted := SortIPsByPreference(nil)
		if sorted != nil {
			t.Errorf("SortIPsByPreference(nil) = %v, want nil", sorted)
		}
	})

	t.Run("single IP", func(t *testing.T) {
		ips := []net.IP{net.ParseIP("fe80::1")}
		sorted := SortIPsByPreference(ips)
		if len(sorted) != 1 || !sorted[0].Equal(ips[0]) {
			t.Errorf("SortIPsByPreference() = %v, want %v", sorted, ips)
		}
	})

	t.Run("does not modify original", func(t *testing.T) {
		original := []net.IP{
			net.ParseIP("fe80::1"),
			net.ParseIP("2001:db8::1"),
		}
		originalFirst := original[0].String()

		_ = SortIPsByPreference(original)

		if original[0].String() != originalFirst {
			t.Error("SortIPsByPreference() modified original slice")
		}
	})
}

func TestFilterIPv6(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("fe80::1"),
		net.ParseIP("192.168.1.1"),
		net.ParseIP("2001:db8::1"),
		net.ParseIP("10.0.0.1"),
	}

	filtered := FilterIPv6(ips)
	if len(filtered) != 2 {
		t.Fatalf("FilterIPv6() returned %d IPs, want 2", len(filtered))
	}

	for _, ip := range filtered {
		if ip.To4() != nil {
			t.Errorf("FilterIPv6() included IPv4 address %v", ip)
		}
	}
}

func TestFilterIPv4(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("fe80::1"),
		net.ParseIP("192.168.1.1"),
		net.ParseIP("2001:db8::1"),
		net.ParseIP("10.0.0.1"),
	}

	filtered := FilterIPv4(ips)
	if len(filtered) != 2 {
		t.Fatalf("FilterIPv4() returned %d IPs, want 2", len(filtered))
	}

	for _, ip := range filtered {
		if ip.To4() == nil {
			t.Errorf("FilterIPv4() included IPv6 address %v", ip)
		}
	}
}

func TestIsUniqueLocal(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"fc00::1", true},
		{"fd00::1", true},
		{"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"fe80::1", false},       // Link-local
		{"2001:db8::1", false},   // Documentation
		{"::1", false},           // Loopback
		{"192.168.1.1", false},   // IPv4
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := isUniqueLocal(ip); got != tt.want {
			t.Errorf("isUniqueLocal(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestIsGlobalUnicast(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"2001:db8::1", true},    // Documentation (but treated as global)
		{"2607:f8b0:4004:800::200e", true}, // Google IPv6
		{"fe80::1", false},       // Link-local
		{"fd00::1", false},       // ULA
		{"::1", false},           // Loopback
		{"192.168.1.1", false},   // IPv4 private
		{"10.0.0.1", false},      // IPv4 private
		{"172.16.0.1", false},    // IPv4 private
		{"8.8.8.8", true},        // IPv4 public (Google DNS)
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := isGlobalUnicast(ip); got != tt.want {
			t.Errorf("isGlobalUnicast(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestSubtypeFilters(t *testing.T) {
	t.Run("LongDiscriminatorSubtype", func(t *testing.T) {
		tests := []struct {
			discriminator uint16
			want          string
		}{
			{0, "_L0"},
			{840, "_L840"},
			{4095, "_L4095"},
		}

		for _, tt := range tests {
			got := LongDiscriminatorSubtype(tt.discriminator)
			if got != tt.want {
				t.Errorf("LongDiscriminatorSubtype(%d) = %q, want %q", tt.discriminator, got, tt.want)
			}
		}
	})

	t.Run("VendorIDSubtype", func(t *testing.T) {
		tests := []struct {
			vendorID fabric.VendorID
			want     string
		}{
			{0, "_V0"},
			{123, "_V123"},
			{0xFFF1, "_V65521"},
		}

		for _, tt := range tests {
			got := VendorIDSubtype(tt.vendorID)
			if got != tt.want {
				t.Errorf("VendorIDSubtype(%d) = %q, want %q", tt.vendorID, got, tt.want)
			}
		}
	})

	t.Run("DeviceTypeSubtype", func(t *testing.T) {
		tests := []struct {
			deviceType uint32
			want       string
		}{
			{0, "_T0"},
			{81, "_T81"},
			{266, "_T266"},
		}

		for _, tt := range tests {
			got := DeviceTypeSubtype(tt.deviceType)
			if got != tt.want {
				t.Errorf("DeviceTypeSubtype(%d) = %q, want %q", tt.deviceType, got, tt.want)
			}
		}
	})
}
