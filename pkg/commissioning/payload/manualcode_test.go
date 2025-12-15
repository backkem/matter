package payload

import (
	"testing"
)

// Test vectors derived from C++ TestManualCode.cpp
// Default payload: passcode=12345679, discriminator=2560 (0xA00)
// Short discriminator = 0xA (MSBs of 0xA00)

func TestParseManualCode(t *testing.T) {
	tests := []struct {
		name                   string
		input                  string
		wantPasscode           uint32
		wantShortDiscriminator uint8
		wantVendorID           uint16
		wantProductID          uint16
		wantCustomFlow         bool
		wantErr                error
	}{
		// Test vectors derived from C++ TestManualCode.cpp
		// Base code "2412950753" with Verhoeff check digit
		{
			name:                   "short code",
			input:                  "24129507533", // 2412950753 + check '3'
			wantPasscode:           12345679,
			wantShortDiscriminator: 0xA,
			wantCustomFlow:         false,
		},
		{
			name:                   "long code with vid/pid 1",
			input:                  "641295075300001000017", // + check '7'
			wantPasscode:           12345679,
			wantShortDiscriminator: 0xA,
			wantVendorID:           1,
			wantProductID:          1,
			wantCustomFlow:         true,
		},
		{
			name:                   "long code full",
			input:                  "641295075345367145262", // + check '2'
			wantPasscode:           12345679,
			wantShortDiscriminator: 0xA,
			wantVendorID:           45367,
			wantProductID:          14526,
			wantCustomFlow:         true,
		},

		// Formatting tests
		{
			name:                   "with dashes",
			input:                  "2412-9507-533",
			wantPasscode:           12345679,
			wantShortDiscriminator: 0xA,
			wantCustomFlow:         false,
		},
		{
			name:                   "with spaces",
			input:                  "2412 9507 533",
			wantPasscode:           12345679,
			wantShortDiscriminator: 0xA,
			wantCustomFlow:         false,
		},

		// Error cases
		{
			name:    "invalid check digit",
			input:   "24129507530", // wrong check digit (should be 3)
			wantErr: ErrManualCodeInvalidChecksum,
		},
		{
			name:    "too short",
			input:   "12345",
			wantErr: ErrManualCodeInvalidChecksum, // Fails Verhoeff first
		},
		{
			name:    "chunk1 reserved value 8",
			input:   "84129507534", // Chunk1=8 is reserved
			wantErr: ErrManualCodeInvalidChunk1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := ParseManualCode(tt.input)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("ParseManualCode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseManualCode(%q) unexpected error: %v", tt.input, err)
			}

			if payload.Passcode != tt.wantPasscode {
				t.Errorf("Passcode = %d, want %d", payload.Passcode, tt.wantPasscode)
			}
			if payload.Discriminator.Short() != tt.wantShortDiscriminator {
				t.Errorf("Discriminator.Short() = %d, want %d", payload.Discriminator.Short(), tt.wantShortDiscriminator)
			}
			if payload.VendorID != tt.wantVendorID {
				t.Errorf("VendorID = %d, want %d", payload.VendorID, tt.wantVendorID)
			}
			if payload.ProductID != tt.wantProductID {
				t.Errorf("ProductID = %d, want %d", payload.ProductID, tt.wantProductID)
			}
			isCustomFlow := payload.CommissioningFlow == CommissioningFlowCustom
			if isCustomFlow != tt.wantCustomFlow {
				t.Errorf("CommissioningFlow = %v, wantCustom = %v", payload.CommissioningFlow, tt.wantCustomFlow)
			}
		})
	}
}

func TestEncodeManualCode(t *testing.T) {
	tests := []struct {
		name    string
		payload *SetupPayload
		want    string
		wantErr bool
	}{
		{
			name: "short code",
			payload: &SetupPayload{
				// discriminator 2560 (0xA00) → short = 0xA
				Discriminator:     NewLongDiscriminator(2560),
				Passcode:          12345679,
				CommissioningFlow: CommissioningFlowStandard,
			},
			want: "24129507533", // 2412950753 + check '3'
		},
		{
			name: "long code zeros vid/pid",
			payload: &SetupPayload{
				Discriminator:     NewLongDiscriminator(2560),
				Passcode:          12345679,
				VendorID:          0,
				ProductID:         0,
				CommissioningFlow: CommissioningFlowCustom,
			},
			want: "641295075300000000008", // + check '8'
		},
		{
			name: "long code with vid/pid 1",
			payload: &SetupPayload{
				Discriminator:     NewLongDiscriminator(2560),
				Passcode:          12345679,
				VendorID:          1,
				ProductID:         1,
				CommissioningFlow: CommissioningFlowCustom,
			},
			want: "641295075300001000017", // + check '7'
		},
		{
			name: "long code full",
			payload: &SetupPayload{
				Discriminator:     NewLongDiscriminator(2560),
				Passcode:          12345679,
				VendorID:          45367,
				ProductID:         14526,
				CommissioningFlow: CommissioningFlowCustom,
			},
			want: "641295075345367145262", // + check '2'
		},
		{
			name: "short discriminator input",
			payload: &SetupPayload{
				Discriminator:     NewShortDiscriminator(0xA),
				Passcode:          12345679,
				CommissioningFlow: CommissioningFlowStandard,
			},
			want: "24129507533",
		},
		{
			name: "invalid passcode",
			payload: &SetupPayload{
				Discriminator: NewLongDiscriminator(128),
				Passcode:      0, // Invalid
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeManualCode(tt.payload)
			if tt.wantErr {
				if err == nil {
					t.Errorf("EncodeManualCode() expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("EncodeManualCode() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("EncodeManualCode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestManualCodeRoundtrip(t *testing.T) {
	tests := []struct {
		name     string
		payload  *SetupPayload
		isLong   bool
	}{
		{
			name: "short code",
			payload: &SetupPayload{
				Discriminator:     NewLongDiscriminator(2560),
				Passcode:          12345679,
				CommissioningFlow: CommissioningFlowStandard,
			},
			isLong: false,
		},
		{
			name: "long code",
			payload: &SetupPayload{
				Discriminator:     NewLongDiscriminator(2560),
				Passcode:          12345679,
				VendorID:          45367,
				ProductID:         14526,
				CommissioningFlow: CommissioningFlowCustom,
			},
			isLong: true,
		},
		{
			name: "different discriminator",
			payload: &SetupPayload{
				Discriminator:     NewLongDiscriminator(0xB1F), // Short = 0xB
				Passcode:          99999998,
				CommissioningFlow: CommissioningFlowStandard,
			},
			isLong: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			code, err := EncodeManualCode(tt.payload)
			if err != nil {
				t.Fatalf("EncodeManualCode() error: %v", err)
			}

			// Check length
			expectedLen := 11
			if tt.isLong {
				expectedLen = 21
			}
			if len(code) != expectedLen {
				t.Errorf("code length = %d, want %d", len(code), expectedLen)
			}

			// Decode
			decoded, err := ParseManualCode(code)
			if err != nil {
				t.Fatalf("ParseManualCode(%q) error: %v", code, err)
			}

			// Compare (note: manual codes only preserve short discriminator)
			if decoded.Discriminator.Short() != tt.payload.Discriminator.Short() {
				t.Errorf("Discriminator.Short(): got %d, want %d",
					decoded.Discriminator.Short(), tt.payload.Discriminator.Short())
			}
			if decoded.Passcode != tt.payload.Passcode {
				t.Errorf("Passcode: got %d, want %d", decoded.Passcode, tt.payload.Passcode)
			}

			if tt.isLong {
				if decoded.VendorID != tt.payload.VendorID {
					t.Errorf("VendorID: got %d, want %d", decoded.VendorID, tt.payload.VendorID)
				}
				if decoded.ProductID != tt.payload.ProductID {
					t.Errorf("ProductID: got %d, want %d", decoded.ProductID, tt.payload.ProductID)
				}
			}
		})
	}
}

func TestStripFormatting(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"12345678901", "12345678901"},
		{"1234-5678-901", "12345678901"},
		{"1234 5678 901", "12345678901"},
		{"1234-5678 901", "12345678901"},
		{"  1234--5678--901  ", "12345678901"},
		{"", ""},
		{"----", ""},
		{"abc123def456", "123456"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := StripFormatting(tt.input)
			if got != tt.want {
				t.Errorf("StripFormatting(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
