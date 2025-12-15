package payload

import (
	"testing"
)

// Test vectors from C++ TestHelpers.h
const (
	// Default test payload QR code: VID=12, PID=1, disc=128, passcode=2048
	defaultPayloadQRCode = "MT:M5L90MP500K64J00000"

	// Concatenated QR codes (4 payloads with incrementing discriminators/passcodes)
	concatenatedQRCode = "MT:M5L90MP500K64J00000*M5L90U.D010K4J00000*M5L900CM02IX4J00000*M5L908OU03-85J00000"
)

func TestExtractPayload(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "basic", input: "MT:ABC", want: "ABC"},
		{name: "empty after prefix", input: "MT:", want: ""},
		{name: "no MT prefix", input: "H:", want: ""},
		{name: "wrong prefix", input: "ASMT:", want: ""},

		// URL-encoded with % delimiters
		{name: "prefix in middle", input: "Z%MT:ABC%", want: "ABC"},
		{name: "prefix at end", input: "Z%MT:ABC", want: "ABC"},
		{name: "prefix after delimiter", input: "%Z%MT:ABC", want: "ABC"},
		{name: "multiple delimiters", input: "%Z%MT:ABC%", want: "ABC"},
		{name: "content after", input: "%Z%MT:ABC%DDD", want: "ABC"},

		// Concatenated payloads
		{name: "concatenated", input: "MT:ABC*DEF*GHI", want: "ABC*DEF*GHI"},
		{name: "concatenated with delimiters", input: "Z%MT:ABC*DEF*GHI%DDD", want: "ABC*DEF*GHI"},
		{name: "complex", input: "%Z*WX%MT:ABC*DEF*GHI%DDD*EEE", want: "ABC*DEF*GHI"},

		// Edge cases
		{name: "just delimiter", input: "A%", want: ""},
		{name: "MT after delimiter empty", input: "MT:%", want: ""},
		{name: "MT after double delimiter", input: "%MT:", want: ""},
		{name: "MT after double delimiter empty", input: "%MT:%", want: ""},
		{name: "only ABC", input: "ABC", want: ""},
		{name: "empty", input: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractPayload(tt.input)
			if got != tt.want {
				t.Errorf("ExtractPayload(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseQRCode(t *testing.T) {
	t.Run("default payload", func(t *testing.T) {
		payload, err := ParseQRCode(defaultPayloadQRCode)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify expected values from C++ TestHelpers.h GetDefaultPayload()
		if payload.Version != 0 {
			t.Errorf("Version = %d, want 0", payload.Version)
		}
		if payload.VendorID != 12 {
			t.Errorf("VendorID = %d, want 12", payload.VendorID)
		}
		if payload.ProductID != 1 {
			t.Errorf("ProductID = %d, want 1", payload.ProductID)
		}
		if payload.CommissioningFlow != CommissioningFlowStandard {
			t.Errorf("CommissioningFlow = %v, want Standard", payload.CommissioningFlow)
		}
		if payload.DiscoveryCapabilities != DiscoveryCapabilitySoftAP {
			t.Errorf("DiscoveryCapabilities = %v, want SoftAP", payload.DiscoveryCapabilities)
		}
		if payload.Discriminator.Long() != 128 {
			t.Errorf("Discriminator = %d, want 128", payload.Discriminator.Long())
		}
		if payload.Passcode != 2048 {
			t.Errorf("Passcode = %d, want 2048", payload.Passcode)
		}
		if !payload.HasDiscoveryCapabilities {
			t.Error("expected HasDiscoveryCapabilities = true")
		}
	})

	t.Run("invalid prefix", func(t *testing.T) {
		_, err := ParseQRCode("AT:M5L90MP500K64J00000")
		if err == nil {
			t.Error("expected error for invalid prefix")
		}
	})

	t.Run("empty", func(t *testing.T) {
		_, err := ParseQRCode("")
		if err == nil {
			t.Error("expected error for empty input")
		}
	})

	t.Run("concatenated rejects", func(t *testing.T) {
		_, err := ParseQRCode(concatenatedQRCode)
		if err == nil {
			t.Error("expected error for concatenated QR code with ParseQRCode")
		}
	})
}

func TestParseQRCodes(t *testing.T) {
	t.Run("single payload", func(t *testing.T) {
		payloads, err := ParseQRCodes(defaultPayloadQRCode)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(payloads) != 1 {
			t.Fatalf("expected 1 payload, got %d", len(payloads))
		}
	})

	t.Run("concatenated", func(t *testing.T) {
		payloads, err := ParseQRCodes(concatenatedQRCode)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(payloads) != 4 {
			t.Fatalf("expected 4 payloads, got %d", len(payloads))
		}

		// Verify payloads have incrementing discriminators and passcodes
		for i, p := range payloads {
			expectedDisc := uint16(128 + i)
			expectedPasscode := uint32(2048 + i)

			if p.Discriminator.Long() != expectedDisc {
				t.Errorf("payload[%d].Discriminator = %d, want %d",
					i, p.Discriminator.Long(), expectedDisc)
			}
			if p.Passcode != expectedPasscode {
				t.Errorf("payload[%d].Passcode = %d, want %d",
					i, p.Passcode, expectedPasscode)
			}
		}
	})
}

func TestEncodeQRCode(t *testing.T) {
	t.Run("default payload", func(t *testing.T) {
		payload := &SetupPayload{
			Version:                  0,
			VendorID:                 12,
			ProductID:                1,
			CommissioningFlow:        CommissioningFlowStandard,
			DiscoveryCapabilities:    DiscoveryCapabilitySoftAP,
			HasDiscoveryCapabilities: true,
			Discriminator:            NewLongDiscriminator(128),
			Passcode:                 2048,
		}

		qrCode, err := EncodeQRCode(payload)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if qrCode != defaultPayloadQRCode {
			t.Errorf("EncodeQRCode() = %q, want %q", qrCode, defaultPayloadQRCode)
		}
	})

	t.Run("invalid payload", func(t *testing.T) {
		payload := &SetupPayload{
			Passcode: 0, // Invalid
		}

		_, err := EncodeQRCode(payload)
		if err == nil {
			t.Error("expected error for invalid payload")
		}
	})

	t.Run("missing discovery capabilities", func(t *testing.T) {
		payload := &SetupPayload{
			Version:       0,
			Discriminator: NewLongDiscriminator(128),
			Passcode:      2048,
			// HasDiscoveryCapabilities = false
		}

		_, err := EncodeQRCode(payload)
		if err == nil {
			t.Error("expected error for missing discovery capabilities")
		}
	})
}

func TestQRCodeRoundtrip(t *testing.T) {
	testCases := []struct {
		name    string
		payload *SetupPayload
	}{
		{
			name: "default",
			payload: &SetupPayload{
				Version:                  0,
				VendorID:                 12,
				ProductID:                1,
				CommissioningFlow:        CommissioningFlowStandard,
				DiscoveryCapabilities:    DiscoveryCapabilitySoftAP,
				HasDiscoveryCapabilities: true,
				Discriminator:            NewLongDiscriminator(128),
				Passcode:                 2048,
			},
		},
		{
			name: "max values",
			payload: &SetupPayload{
				Version:                  0, // Must be 0
				VendorID:                 0xFFFF,
				ProductID:                0xFFFF,
				CommissioningFlow:        CommissioningFlowCustom,
				DiscoveryCapabilities:    DiscoveryCapabilityBLE | DiscoveryCapabilityOnNetwork | DiscoveryCapabilityNFC,
				HasDiscoveryCapabilities: true,
				Discriminator:            NewLongDiscriminator(0xFFF),
				Passcode:                 99999998,
			},
		},
		{
			name: "user intent flow",
			payload: &SetupPayload{
				Version:                  0,
				VendorID:                 0x1234,
				ProductID:                0x5678,
				CommissioningFlow:        CommissioningFlowUserIntent,
				DiscoveryCapabilities:    DiscoveryCapabilityBLE,
				HasDiscoveryCapabilities: true,
				Discriminator:            NewLongDiscriminator(2560),
				Passcode:                 12345679,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode
			qrCode, err := EncodeQRCode(tc.payload)
			if err != nil {
				t.Fatalf("EncodeQRCode error: %v", err)
			}

			// Decode
			decoded, err := ParseQRCode(qrCode)
			if err != nil {
				t.Fatalf("ParseQRCode error: %v", err)
			}

			// Compare
			if decoded.Version != tc.payload.Version {
				t.Errorf("Version: got %d, want %d", decoded.Version, tc.payload.Version)
			}
			if decoded.VendorID != tc.payload.VendorID {
				t.Errorf("VendorID: got %d, want %d", decoded.VendorID, tc.payload.VendorID)
			}
			if decoded.ProductID != tc.payload.ProductID {
				t.Errorf("ProductID: got %d, want %d", decoded.ProductID, tc.payload.ProductID)
			}
			if decoded.CommissioningFlow != tc.payload.CommissioningFlow {
				t.Errorf("CommissioningFlow: got %v, want %v", decoded.CommissioningFlow, tc.payload.CommissioningFlow)
			}
			if decoded.DiscoveryCapabilities != tc.payload.DiscoveryCapabilities {
				t.Errorf("DiscoveryCapabilities: got %v, want %v", decoded.DiscoveryCapabilities, tc.payload.DiscoveryCapabilities)
			}
			if decoded.Discriminator.Long() != tc.payload.Discriminator.Long() {
				t.Errorf("Discriminator: got %d, want %d", decoded.Discriminator.Long(), tc.payload.Discriminator.Long())
			}
			if decoded.Passcode != tc.payload.Passcode {
				t.Errorf("Passcode: got %d, want %d", decoded.Passcode, tc.payload.Passcode)
			}
		})
	}
}

func TestBitReader(t *testing.T) {
	// Test data: 0x12, 0x34 = 00010010 00110100
	// LSB first: bit 0 = 0, bit 1 = 1, bit 2 = 0, bit 3 = 0, bit 4 = 1, ...
	data := []byte{0x12, 0x34}
	reader := &bitReader{data: data}

	// Read 4 bits: should get 0010 = 2
	v, err := reader.readBits(4)
	if err != nil {
		t.Fatal(err)
	}
	if v != 2 {
		t.Errorf("first 4 bits = %d, want 2", v)
	}

	// Read 4 bits: should get 0001 = 1
	v, err = reader.readBits(4)
	if err != nil {
		t.Fatal(err)
	}
	if v != 1 {
		t.Errorf("second 4 bits = %d, want 1", v)
	}

	// Read 8 bits: should get 0x34 = 52
	v, err = reader.readBits(8)
	if err != nil {
		t.Fatal(err)
	}
	if v != 0x34 {
		t.Errorf("third 8 bits = %d, want %d", v, 0x34)
	}
}

func TestBitWriter(t *testing.T) {
	writer := &bitWriter{}

	// Write 4 bits: 2 = 0010
	writer.writeBits(2, 4)
	// Write 4 bits: 1 = 0001
	writer.writeBits(1, 4)
	// Write 8 bits: 0x34
	writer.writeBits(0x34, 8)

	data := writer.bytes()
	if len(data) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(data))
	}
	if data[0] != 0x12 {
		t.Errorf("byte[0] = 0x%02x, want 0x12", data[0])
	}
	if data[1] != 0x34 {
		t.Errorf("byte[1] = 0x%02x, want 0x34", data[1])
	}
}
