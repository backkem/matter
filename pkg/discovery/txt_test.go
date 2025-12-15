package discovery

import (
	"reflect"
	"testing"
	"time"

	"github.com/backkem/matter/pkg/fabric"
)

func TestCommissionableTXT_Encode(t *testing.T) {
	tests := []struct {
		name string
		txt  CommissionableTXT
		want []string
	}{
		{
			name: "minimal",
			txt: CommissionableTXT{
				Discriminator:     840,
				CommissioningMode: CommissioningModeBasic,
			},
			want: []string{"D=840", "CM=1"},
		},
		{
			name: "full",
			txt: CommissionableTXT{
				Discriminator:       840,
				CommissioningMode:   CommissioningModeEnhanced,
				VendorID:            123,
				ProductID:           456,
				DeviceType:          81,
				DeviceName:          "Kitchen Plug",
				IdleInterval:        500 * time.Millisecond,
				ActiveInterval:      300 * time.Millisecond,
				TCPSupported:        true,
				ICDMode:             ICDModeLIT,
				ICDSet:              true,
				PairingHint:         256,
				PairingInstructions: "Press button",
			},
			want: []string{
				"D=840",
				"CM=2",
				"VP=123+456",
				"DT=81",
				"DN=Kitchen Plug",
				"SII=500",
				"SAI=300",
				"T=1",
				"ICD=1",
				"PH=256",
				"PI=Press button",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.txt.Encode()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Encode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommissionableTXT_Validate(t *testing.T) {
	tests := []struct {
		name    string
		txt     CommissionableTXT
		wantErr error
	}{
		{
			name: "valid",
			txt: CommissionableTXT{
				Discriminator: 840,
			},
			wantErr: nil,
		},
		{
			name: "discriminator too large",
			txt: CommissionableTXT{
				Discriminator: 0x1000, // 13 bits, max is 12
			},
			wantErr: ErrInvalidDiscriminator,
		},
		{
			name: "device name too long",
			txt: CommissionableTXT{
				Discriminator: 840,
				DeviceName:    "This device name is way too long and exceeds the maximum allowed length",
			},
			wantErr: ErrInvalidDeviceName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.txt.Validate()
			if err != tt.wantErr {
				t.Errorf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestCommissionableTXT_ShortDiscriminator(t *testing.T) {
	tests := []struct {
		discriminator uint16
		wantShort     uint8
	}{
		{0x000, 0},
		{0x100, 1},
		{0x200, 2},
		{0x300, 3},
		{0x348, 3}, // 840 decimal
		{0xFFF, 15},
		{0x0FF, 0},
	}

	for _, tt := range tests {
		txt := CommissionableTXT{Discriminator: tt.discriminator}
		got := txt.ShortDiscriminator()
		if got != tt.wantShort {
			t.Errorf("ShortDiscriminator(%d) = %d, want %d", tt.discriminator, got, tt.wantShort)
		}
	}
}

func TestOperationalTXT_Encode(t *testing.T) {
	tests := []struct {
		name string
		txt  OperationalTXT
		want []string
	}{
		{
			name: "empty",
			txt:  OperationalTXT{},
			want: nil,
		},
		{
			name: "with intervals",
			txt: OperationalTXT{
				IdleInterval:   500 * time.Millisecond,
				ActiveInterval: 300 * time.Millisecond,
			},
			want: []string{"SII=500", "SAI=300"},
		},
		{
			name: "full",
			txt: OperationalTXT{
				IdleInterval:   500 * time.Millisecond,
				ActiveInterval: 300 * time.Millisecond,
				TCPSupported:   true,
				ICDMode:        ICDModeLIT,
				ICDSet:         true,
			},
			want: []string{"SII=500", "SAI=300", "T=1", "ICD=1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.txt.Encode()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Encode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommissionerTXT_Encode(t *testing.T) {
	tests := []struct {
		name string
		txt  CommissionerTXT
		want []string
	}{
		{
			name: "empty",
			txt:  CommissionerTXT{},
			want: nil,
		},
		{
			name: "full",
			txt: CommissionerTXT{
				VendorID:             123,
				ProductID:            456,
				DeviceType:           35,
				DeviceName:           "Living Room TV",
				CommissionerPasscode: true,
			},
			want: []string{
				"VP=123+456",
				"DT=35",
				"DN=Living Room TV",
				"CP=1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.txt.Encode()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Encode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseTXT(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		want    map[string]string
	}{
		{
			name:    "empty",
			records: nil,
			want:    map[string]string{},
		},
		{
			name:    "single",
			records: []string{"D=840"},
			want:    map[string]string{"D": "840"},
		},
		{
			name:    "multiple",
			records: []string{"D=840", "CM=2", "VP=123+456"},
			want: map[string]string{
				"D":  "840",
				"CM": "2",
				"VP": "123+456",
			},
		},
		{
			name:    "with empty value",
			records: []string{"D=", "CM=2"},
			want: map[string]string{
				"D":  "",
				"CM": "2",
			},
		},
		{
			name:    "malformed ignored",
			records: []string{"D=840", "invalid", "CM=2"},
			want: map[string]string{
				"D":  "840",
				"CM": "2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseTXT(tt.records)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseTXT() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCommissionableTXT(t *testing.T) {
	t.Run("full roundtrip", func(t *testing.T) {
		original := CommissionableTXT{
			Discriminator:       840,
			CommissioningMode:   CommissioningModeEnhanced,
			VendorID:            123,
			ProductID:           456,
			DeviceType:          81,
			DeviceName:          "Kitchen Plug",
			IdleInterval:        500 * time.Millisecond,
			ActiveInterval:      300 * time.Millisecond,
			TCPSupported:        true,
			ICDMode:             ICDModeLIT,
			ICDSet:              true,
			PairingHint:         256,
			PairingInstructions: "Press button",
		}

		encoded := original.Encode()
		parsed, err := ParseCommissionableTXT(encoded)
		if err != nil {
			t.Fatalf("ParseCommissionableTXT() error = %v", err)
		}

		if parsed.Discriminator != original.Discriminator {
			t.Errorf("Discriminator = %d, want %d", parsed.Discriminator, original.Discriminator)
		}
		if parsed.CommissioningMode != original.CommissioningMode {
			t.Errorf("CommissioningMode = %d, want %d", parsed.CommissioningMode, original.CommissioningMode)
		}
		if parsed.VendorID != original.VendorID {
			t.Errorf("VendorID = %d, want %d", parsed.VendorID, original.VendorID)
		}
		if parsed.ProductID != original.ProductID {
			t.Errorf("ProductID = %d, want %d", parsed.ProductID, original.ProductID)
		}
		if parsed.DeviceType != original.DeviceType {
			t.Errorf("DeviceType = %d, want %d", parsed.DeviceType, original.DeviceType)
		}
		if parsed.DeviceName != original.DeviceName {
			t.Errorf("DeviceName = %q, want %q", parsed.DeviceName, original.DeviceName)
		}
		if parsed.TCPSupported != original.TCPSupported {
			t.Errorf("TCPSupported = %v, want %v", parsed.TCPSupported, original.TCPSupported)
		}
		if parsed.ICDMode != original.ICDMode {
			t.Errorf("ICDMode = %d, want %d", parsed.ICDMode, original.ICDMode)
		}
	})

	t.Run("invalid discriminator", func(t *testing.T) {
		_, err := ParseCommissionableTXT([]string{"D=5000"})
		if err != ErrInvalidDiscriminator {
			t.Errorf("ParseCommissionableTXT() error = %v, want %v", err, ErrInvalidDiscriminator)
		}
	})

	t.Run("invalid VP format", func(t *testing.T) {
		_, err := ParseCommissionableTXT([]string{"D=840", "VP=invalid"})
		if err != ErrInvalidTXTRecord {
			t.Errorf("ParseCommissionableTXT() error = %v, want %v", err, ErrInvalidTXTRecord)
		}
	})
}

func TestParseOperationalTXT(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		original := OperationalTXT{
			IdleInterval:   500 * time.Millisecond,
			ActiveInterval: 300 * time.Millisecond,
			TCPSupported:   true,
			ICDMode:        ICDModeSIT,
			ICDSet:         true,
		}

		encoded := original.Encode()
		parsed, err := ParseOperationalTXT(encoded)
		if err != nil {
			t.Fatalf("ParseOperationalTXT() error = %v", err)
		}

		if parsed.IdleInterval != original.IdleInterval {
			t.Errorf("IdleInterval = %v, want %v", parsed.IdleInterval, original.IdleInterval)
		}
		if parsed.ActiveInterval != original.ActiveInterval {
			t.Errorf("ActiveInterval = %v, want %v", parsed.ActiveInterval, original.ActiveInterval)
		}
		if parsed.TCPSupported != original.TCPSupported {
			t.Errorf("TCPSupported = %v, want %v", parsed.TCPSupported, original.TCPSupported)
		}
		if parsed.ICDMode != original.ICDMode {
			t.Errorf("ICDMode = %d, want %d", parsed.ICDMode, original.ICDMode)
		}
	})
}

func TestParseCommissionerTXT(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		original := CommissionerTXT{
			VendorID:             fabric.VendorID(123),
			ProductID:            456,
			DeviceType:           35,
			DeviceName:           "Living Room TV",
			CommissionerPasscode: true,
		}

		encoded := original.Encode()
		parsed, err := ParseCommissionerTXT(encoded)
		if err != nil {
			t.Fatalf("ParseCommissionerTXT() error = %v", err)
		}

		if parsed.VendorID != original.VendorID {
			t.Errorf("VendorID = %d, want %d", parsed.VendorID, original.VendorID)
		}
		if parsed.ProductID != original.ProductID {
			t.Errorf("ProductID = %d, want %d", parsed.ProductID, original.ProductID)
		}
		if parsed.DeviceType != original.DeviceType {
			t.Errorf("DeviceType = %d, want %d", parsed.DeviceType, original.DeviceType)
		}
		if parsed.DeviceName != original.DeviceName {
			t.Errorf("DeviceName = %q, want %q", parsed.DeviceName, original.DeviceName)
		}
		if parsed.CommissionerPasscode != original.CommissionerPasscode {
			t.Errorf("CommissionerPasscode = %v, want %v", parsed.CommissionerPasscode, original.CommissionerPasscode)
		}
	})
}
