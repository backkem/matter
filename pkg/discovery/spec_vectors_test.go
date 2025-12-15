package discovery

import (
	"reflect"
	"testing"
	"time"

	"github.com/backkem/matter/pkg/fabric"
)

// TestSpecVectors_OperationalInstanceName tests the operational discovery instance name format
// per Spec Section 4.3.2.1 and the example in Section 4.3.2.7.
//
// From Spec Section 4.3.2.1:
// "For example, a Matter Node with Matter compressed fabric identifier 2906-C908-D115-D362
// and Matter Node identifier 8FC7-7724-01CD-0696 has Matter operational discovery DNS-SD
// instance name 2906C908D115D362-8FC7772401CD0696."
//
// From Spec Section 4.3.2.7:
// "dns-sd -R 87E1B004E235A130-8FC7772401CD0696 _matter._tcp . 22222"
func TestSpecVectors_OperationalInstanceName(t *testing.T) {
	tests := []struct {
		name               string
		compressedFabricID [8]byte
		nodeID             fabric.NodeID
		wantInstanceName   string
	}{
		{
			// From Section 4.3.2.1 example
			name:               "Spec 4.3.2.1 example",
			compressedFabricID: [8]byte{0x29, 0x06, 0xC9, 0x08, 0xD1, 0x15, 0xD3, 0x62},
			nodeID:             fabric.NodeID(0x8FC7772401CD0696),
			wantInstanceName:   "2906C908D115D362-8FC7772401CD0696",
		},
		{
			// From Section 4.3.2.7 example (using derived compressed fabric ID from 4.3.2.2)
			name:               "Spec 4.3.2.7 example",
			compressedFabricID: [8]byte{0x87, 0xE1, 0xB0, 0x04, 0xE2, 0x35, 0xA1, 0x30},
			nodeID:             fabric.NodeID(0x8FC7772401CD0696),
			wantInstanceName:   "87E1B004E235A130-8FC7772401CD0696",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := OperationalInstanceName(tt.compressedFabricID, tt.nodeID)
			if got != tt.wantInstanceName {
				t.Errorf("OperationalInstanceName() = %q, want %q", got, tt.wantInstanceName)
			}

			// Verify roundtrip parsing
			cfid, nodeID, err := ParseOperationalInstanceName(got)
			if err != nil {
				t.Fatalf("ParseOperationalInstanceName() error = %v", err)
			}
			if cfid != tt.compressedFabricID {
				t.Errorf("Roundtrip compressedFabricID = %x, want %x", cfid, tt.compressedFabricID)
			}
			if nodeID != tt.nodeID {
				t.Errorf("Roundtrip nodeID = %x, want %x", nodeID, tt.nodeID)
			}
		})
	}
}

// TestSpecVectors_ShortDiscriminator tests short discriminator calculation
// per Spec Section 4.3.1.5.
//
// From Spec Section 4.3.1.5:
// "The short discriminator is filterable through _S3 subtype and algorithmically through D=840 TXT key."
//
// The short discriminator is the upper 4 bits of the 12-bit discriminator:
// short = (discriminator >> 8) & 0xF
//
// For discriminator 840 (0x348):
// Binary: 0011 0100 1000
// Upper 4 bits: 0011 = 3
func TestSpecVectors_ShortDiscriminator(t *testing.T) {
	tests := []struct {
		name          string
		discriminator uint16
		wantShort     uint8
		wantSubtype   string
	}{
		{
			// From Spec Section 4.3.1.4 example: D=840 → _S3
			name:          "Spec example D=840",
			discriminator: 840, // 0x348
			wantShort:     3,
			wantSubtype:   "_S3",
		},
		{
			name:          "Minimum discriminator",
			discriminator: 0,
			wantShort:     0,
			wantSubtype:   "_S0",
		},
		{
			name:          "Maximum discriminator",
			discriminator: 4095, // 0xFFF
			wantShort:     15,
			wantSubtype:   "_S15", // Note: ShortDiscriminatorSubtype returns "_S" + single char
		},
		{
			name:          "0x100 boundary",
			discriminator: 0x100,
			wantShort:     1,
			wantSubtype:   "_S1",
		},
		{
			name:          "0x200 boundary",
			discriminator: 0x200,
			wantShort:     2,
			wantSubtype:   "_S2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txt := CommissionableTXT{Discriminator: tt.discriminator}
			got := txt.ShortDiscriminator()
			if got != tt.wantShort {
				t.Errorf("ShortDiscriminator() = %d, want %d", got, tt.wantShort)
			}
		})
	}
}

// TestSpecVectors_CommissionableTXT_MinimalExample tests the minimal commissionable TXT encoding
// per Spec Section 4.3.1.4 Example 1.
//
// From Spec:
// "dns-sd -R DD200C20D25AE5F7 _matterc._udp,_S3,_L840,_CM . 11111 D=840 CM=2"
//
// TXT Record: "D=840" "CM=2"
func TestSpecVectors_CommissionableTXT_MinimalExample(t *testing.T) {
	txt := CommissionableTXT{
		Discriminator:     840,
		CommissioningMode: CommissioningModeEnhanced, // CM=2
	}

	encoded := txt.Encode()
	want := []string{"D=840", "CM=2"}

	if !reflect.DeepEqual(encoded, want) {
		t.Errorf("Encode() = %v, want %v", encoded, want)
	}

	// Parse back and verify
	parsed, err := ParseCommissionableTXT(encoded)
	if err != nil {
		t.Fatalf("ParseCommissionableTXT() error = %v", err)
	}

	if parsed.Discriminator != 840 {
		t.Errorf("Discriminator = %d, want 840", parsed.Discriminator)
	}
	if parsed.CommissioningMode != CommissioningModeEnhanced {
		t.Errorf("CommissioningMode = %d, want %d", parsed.CommissioningMode, CommissioningModeEnhanced)
	}
}

// TestSpecVectors_CommissionableTXT_FullExample tests the full commissionable TXT encoding
// per Spec Section 4.3.1.4 Example 2.
//
// From Spec:
// "dns-sd -R DD200C20D25AE5F7 _matterc._udp,_S3,_L840,_V123,_CM,_T81 . 11111 D=840
// VP=123+456 CM=2 DT=266 DN="Kitchen Plug" PH=256 PI=5"
//
// Note: The spec example shows DT=266 in the command but DT=81 in the subtypes.
// The subtypes (_T81) and TXT (DT=81) in the resulting records show DT=81.
// We use the values from the generated DNS records which show:
// TXT "D=840" "VP=123+456" "CM=1" "DT=81" "DN=Kitchen Plug" "PH=256" "PI=5"
func TestSpecVectors_CommissionableTXT_FullExample(t *testing.T) {
	txt := CommissionableTXT{
		Discriminator:       840,
		CommissioningMode:   CommissioningModeEnhanced, // CM=2
		VendorID:            123,
		ProductID:           456,
		DeviceType:          81,
		DeviceName:          "Kitchen Plug",
		PairingHint:         256,
		PairingInstructions: "5",
	}

	encoded := txt.Encode()

	// Verify key fields are present
	expectedKeys := map[string]bool{
		"D=840":            false,
		"CM=2":             false,
		"VP=123+456":       false,
		"DT=81":            false,
		"DN=Kitchen Plug":  false,
		"PH=256":           false,
		"PI=5":             false,
	}

	for _, record := range encoded {
		if _, ok := expectedKeys[record]; ok {
			expectedKeys[record] = true
		}
	}

	for key, found := range expectedKeys {
		if !found {
			t.Errorf("Missing expected TXT record: %s", key)
		}
	}

	// Parse back and verify
	parsed, err := ParseCommissionableTXT(encoded)
	if err != nil {
		t.Fatalf("ParseCommissionableTXT() error = %v", err)
	}

	if parsed.Discriminator != 840 {
		t.Errorf("Discriminator = %d, want 840", parsed.Discriminator)
	}
	if parsed.VendorID != 123 {
		t.Errorf("VendorID = %d, want 123", parsed.VendorID)
	}
	if parsed.ProductID != 456 {
		t.Errorf("ProductID = %d, want 456", parsed.ProductID)
	}
	if parsed.DeviceType != 81 {
		t.Errorf("DeviceType = %d, want 81", parsed.DeviceType)
	}
	if parsed.DeviceName != "Kitchen Plug" {
		t.Errorf("DeviceName = %q, want %q", parsed.DeviceName, "Kitchen Plug")
	}
}

// TestSpecVectors_CommissionerTXT tests the commissioner TXT encoding
// per Spec Section 4.3.3.
//
// From Spec:
// "dns-sd -R DD200C20D25AE5F7 _matterd._udp,_V123,_T35 . 33333 VP=123+456 DT=35 DN="Living Room TV""
//
// TXT Record: "VP=123+456" "DT=35" "DN=Living Room TV"
func TestSpecVectors_CommissionerTXT(t *testing.T) {
	txt := CommissionerTXT{
		VendorID:   123,
		ProductID:  456,
		DeviceType: 35, // Casting Video Player (0x0023)
		DeviceName: "Living Room TV",
	}

	encoded := txt.Encode()

	expectedKeys := map[string]bool{
		"VP=123+456":         false,
		"DT=35":              false,
		"DN=Living Room TV":  false,
	}

	for _, record := range encoded {
		if _, ok := expectedKeys[record]; ok {
			expectedKeys[record] = true
		}
	}

	for key, found := range expectedKeys {
		if !found {
			t.Errorf("Missing expected TXT record: %s", key)
		}
	}

	// Parse back
	parsed, err := ParseCommissionerTXT(encoded)
	if err != nil {
		t.Fatalf("ParseCommissionerTXT() error = %v", err)
	}

	if parsed.VendorID != 123 {
		t.Errorf("VendorID = %d, want 123", parsed.VendorID)
	}
	if parsed.ProductID != 456 {
		t.Errorf("ProductID = %d, want 456", parsed.ProductID)
	}
	if parsed.DeviceType != 35 {
		t.Errorf("DeviceType = %d, want 35", parsed.DeviceType)
	}
	if parsed.DeviceName != "Living Room TV" {
		t.Errorf("DeviceName = %q, want %q", parsed.DeviceName, "Living Room TV")
	}
}

// TestSpecVectors_SubtypeFilters tests DNS-SD subtype filter generation
// per Spec Section 4.3.1.4.
//
// From Spec:
// "_S3._sub._matterc._udp.local."    (Short discriminator)
// "_L840._sub._matterc._udp.local."  (Long discriminator)
// "_V123._sub._matterc._udp.local."  (Vendor ID)
// "_T81._sub._matterc._udp.local."   (Device Type)
// "_CM._sub._matterc._udp.local."    (Commissioning Mode)
func TestSpecVectors_SubtypeFilters(t *testing.T) {
	t.Run("Long discriminator filter", func(t *testing.T) {
		got := LongDiscriminatorSubtype(840)
		want := "_L840"
		if got != want {
			t.Errorf("LongDiscriminatorSubtype(840) = %q, want %q", got, want)
		}
	})

	t.Run("Vendor ID filter", func(t *testing.T) {
		got := VendorIDSubtype(123)
		want := "_V123"
		if got != want {
			t.Errorf("VendorIDSubtype(123) = %q, want %q", got, want)
		}
	})

	t.Run("Device Type filter", func(t *testing.T) {
		got := DeviceTypeSubtype(81)
		want := "_T81"
		if got != want {
			t.Errorf("DeviceTypeSubtype(81) = %q, want %q", got, want)
		}
	})

	t.Run("Commissioning Mode filter constant", func(t *testing.T) {
		if CommissioningModeSubtype != "_CM" {
			t.Errorf("CommissioningModeSubtype = %q, want %q", CommissioningModeSubtype, "_CM")
		}
	})
}

// TestSpecVectors_ServiceTypes tests DNS-SD service type strings
// per Spec Section 4.3.
//
// From Spec:
// - Section 4.3.1: "_matterc._udp" for Commissionable Node Discovery
// - Section 4.3.2.3: "_matter._tcp" for Operational Discovery
// - Section 4.3.3: "_matterd._udp" for Commissioner Discovery
func TestSpecVectors_ServiceTypes(t *testing.T) {
	tests := []struct {
		serviceType ServiceType
		want        string
	}{
		{ServiceTypeCommissionable, "_matterc._udp"},
		{ServiceTypeOperational, "_matter._tcp"},
		{ServiceTypeCommissioner, "_matterd._udp"},
	}

	for _, tt := range tests {
		t.Run(tt.serviceType.String(), func(t *testing.T) {
			got := tt.serviceType.ServiceString()
			if got != tt.want {
				t.Errorf("ServiceString() = %q, want %q", got, tt.want)
			}
		})
	}

	// Also verify the constants directly
	if ServiceCommissionable != "_matterc._udp" {
		t.Errorf("ServiceCommissionable = %q, want %q", ServiceCommissionable, "_matterc._udp")
	}
	if ServiceOperational != "_matter._tcp" {
		t.Errorf("ServiceOperational = %q, want %q", ServiceOperational, "_matter._tcp")
	}
	if ServiceCommissioner != "_matterd._udp" {
		t.Errorf("ServiceCommissioner = %q, want %q", ServiceCommissioner, "_matterd._udp")
	}
}

// TestSpecVectors_OperationalTXT tests operational TXT record encoding
// per Spec Section 4.3.2.5 and 4.3.4.
//
// From Spec Section 4.3.4 (Common TXT Key/Value Pairs):
// - SII: SESSION_IDLE_INTERVAL in milliseconds
// - SAI: SESSION_ACTIVE_INTERVAL in milliseconds
// - T: TCP support (0 or 1)
// - ICD: ICD operating mode (0=SIT, 1=LIT)
func TestSpecVectors_OperationalTXT(t *testing.T) {
	txt := OperationalTXT{
		IdleInterval:   500 * time.Millisecond,
		ActiveInterval: 300 * time.Millisecond,
		TCPSupported:   true,
		ICDMode:        ICDModeLIT,
		ICDSet:         true,
	}

	encoded := txt.Encode()

	expectedKeys := map[string]bool{
		"SII=500": false, // 500ms
		"SAI=300": false, // 300ms
		"T=1":     false, // TCP supported
		"ICD=1":   false, // LIT mode
	}

	for _, record := range encoded {
		if _, ok := expectedKeys[record]; ok {
			expectedKeys[record] = true
		}
	}

	for key, found := range expectedKeys {
		if !found {
			t.Errorf("Missing expected TXT record: %s", key)
		}
	}

	// Parse back
	parsed, err := ParseOperationalTXT(encoded)
	if err != nil {
		t.Fatalf("ParseOperationalTXT() error = %v", err)
	}

	if parsed.IdleInterval != 500*time.Millisecond {
		t.Errorf("IdleInterval = %v, want 500ms", parsed.IdleInterval)
	}
	if parsed.ActiveInterval != 300*time.Millisecond {
		t.Errorf("ActiveInterval = %v, want 300ms", parsed.ActiveInterval)
	}
	if !parsed.TCPSupported {
		t.Error("TCPSupported = false, want true")
	}
	if parsed.ICDMode != ICDModeLIT {
		t.Errorf("ICDMode = %d, want %d", parsed.ICDMode, ICDModeLIT)
	}
}

// TestSpecVectors_MaxDiscriminator verifies the maximum discriminator value
// per Spec Section 4.3.1.5.
//
// The discriminator is a 12-bit value (0-4095).
func TestSpecVectors_MaxDiscriminator(t *testing.T) {
	if MaxDiscriminator != 4095 {
		t.Errorf("MaxDiscriminator = %d, want 4095", MaxDiscriminator)
	}

	// Valid discriminator at max
	txt := CommissionableTXT{Discriminator: 4095}
	if err := txt.Validate(); err != nil {
		t.Errorf("Validate() for max discriminator error = %v", err)
	}

	// Invalid discriminator above max
	txt = CommissionableTXT{Discriminator: 4096}
	if err := txt.Validate(); err != ErrInvalidDiscriminator {
		t.Errorf("Validate() for discriminator 4096 error = %v, want %v", err, ErrInvalidDiscriminator)
	}
}

// TestSpecVectors_MaxDeviceName verifies the maximum device name length
// per Spec Section 4.3.1.9.
//
// The device name is limited to 32 characters.
func TestSpecVectors_MaxDeviceName(t *testing.T) {
	if MaxDeviceNameLength != 32 {
		t.Errorf("MaxDeviceNameLength = %d, want 32", MaxDeviceNameLength)
	}

	// Valid device name at max length
	txt := CommissionableTXT{
		Discriminator: 840,
		DeviceName:    "12345678901234567890123456789012", // 32 chars
	}
	if err := txt.Validate(); err != nil {
		t.Errorf("Validate() for max length device name error = %v", err)
	}

	// Invalid device name above max
	txt = CommissionableTXT{
		Discriminator: 840,
		DeviceName:    "123456789012345678901234567890123", // 33 chars
	}
	if err := txt.Validate(); err != ErrInvalidDeviceName {
		t.Errorf("Validate() for 33-char device name error = %v, want %v", err, ErrInvalidDeviceName)
	}
}

// TestSpecVectors_CommissioningModes verifies commissioning mode values
// per Spec Section 4.3.1.3.
//
// CM values:
// - 0: Not currently in commissioning mode (Extended Discovery only)
// - 1: Basic commissioning mode
// - 2: Enhanced commissioning mode (Administrator-opened window)
func TestSpecVectors_CommissioningModes(t *testing.T) {
	tests := []struct {
		mode      CommissioningMode
		wantValue int
		wantStr   string
	}{
		{CommissioningModeDisabled, 0, "Disabled"},
		{CommissioningModeBasic, 1, "Basic"},
		{CommissioningModeEnhanced, 2, "Enhanced"},
	}

	for _, tt := range tests {
		if int(tt.mode) != tt.wantValue {
			t.Errorf("CommissioningMode %s = %d, want %d", tt.wantStr, tt.mode, tt.wantValue)
		}
		if tt.mode.String() != tt.wantStr {
			t.Errorf("CommissioningMode.String() = %q, want %q", tt.mode.String(), tt.wantStr)
		}
	}
}
