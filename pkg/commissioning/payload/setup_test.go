package payload

import (
	"testing"
)

func TestDefaultPBKDFParams(t *testing.T) {
	params, err := DefaultPBKDFParams()
	if err != nil {
		t.Fatalf("DefaultPBKDFParams() error: %v", err)
	}

	if params.Iterations != PBKDFDefaultIterations {
		t.Errorf("Iterations = %d, want %d", params.Iterations, PBKDFDefaultIterations)
	}

	if len(params.Salt) != PBKDFMinSaltLength {
		t.Errorf("Salt length = %d, want %d", len(params.Salt), PBKDFMinSaltLength)
	}

	// Verify salt is not all zeros (very unlikely if random)
	allZeros := true
	for _, b := range params.Salt {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Salt appears to be all zeros")
	}
}

func TestExtractPBKDFParams(t *testing.T) {
	tests := []struct {
		name           string
		payload        *SetupPayload
		wantIterations uint32
		wantSaltLen    int
		wantErr        bool
	}{
		{
			name:           "no optional data",
			payload:        &SetupPayload{},
			wantIterations: PBKDFDefaultIterations,
			wantSaltLen:    PBKDFMinSaltLength,
		},
		{
			name: "with custom iterations",
			payload: &SetupPayload{
				OptionalData: &OptionalData{
					PBKDFIterations:    5000,
					HasPBKDFIterations: true,
				},
			},
			wantIterations: 5000,
			wantSaltLen:    PBKDFMinSaltLength,
		},
		{
			name: "with custom salt",
			payload: &SetupPayload{
				OptionalData: &OptionalData{
					BPKFSalt: make([]byte, 24),
				},
			},
			wantIterations: PBKDFDefaultIterations,
			wantSaltLen:    24,
		},
		{
			name: "with both",
			payload: &SetupPayload{
				OptionalData: &OptionalData{
					PBKDFIterations:    10000,
					HasPBKDFIterations: true,
					BPKFSalt:           make([]byte, 32),
				},
			},
			wantIterations: 10000,
			wantSaltLen:    32,
		},
		{
			name: "iterations too low",
			payload: &SetupPayload{
				OptionalData: &OptionalData{
					PBKDFIterations:    500,
					HasPBKDFIterations: true,
				},
			},
			wantErr: true,
		},
		{
			name: "iterations too high",
			payload: &SetupPayload{
				OptionalData: &OptionalData{
					PBKDFIterations:    200000,
					HasPBKDFIterations: true,
				},
			},
			wantErr: true,
		},
		{
			name: "salt too short",
			payload: &SetupPayload{
				OptionalData: &OptionalData{
					BPKFSalt: make([]byte, 8),
				},
			},
			wantErr: true,
		},
		{
			name: "salt too long",
			payload: &SetupPayload{
				OptionalData: &OptionalData{
					BPKFSalt: make([]byte, 64),
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ExtractPBKDFParams(tt.payload)
			if tt.wantErr {
				if err == nil {
					t.Error("ExtractPBKDFParams() expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtractPBKDFParams() error: %v", err)
			}

			if params.Iterations != tt.wantIterations {
				t.Errorf("Iterations = %d, want %d", params.Iterations, tt.wantIterations)
			}

			if len(params.Salt) != tt.wantSaltLen {
				t.Errorf("Salt length = %d, want %d", len(params.Salt), tt.wantSaltLen)
			}
		})
	}
}

func TestValidatePBKDFParams(t *testing.T) {
	tests := []struct {
		name    string
		params  *PBKDFParams
		wantErr error
	}{
		{
			name: "valid min",
			params: &PBKDFParams{
				Iterations: PBKDFMinIterations,
				Salt:       make([]byte, PBKDFMinSaltLength),
			},
			wantErr: nil,
		},
		{
			name: "valid max",
			params: &PBKDFParams{
				Iterations: PBKDFMaxIterations,
				Salt:       make([]byte, PBKDFMaxSaltLength),
			},
			wantErr: nil,
		},
		{
			name: "iterations too low",
			params: &PBKDFParams{
				Iterations: 999,
				Salt:       make([]byte, 16),
			},
			wantErr: ErrInvalidIterations,
		},
		{
			name: "iterations too high",
			params: &PBKDFParams{
				Iterations: 100001,
				Salt:       make([]byte, 16),
			},
			wantErr: ErrInvalidIterations,
		},
		{
			name: "salt too short",
			params: &PBKDFParams{
				Iterations: 1000,
				Salt:       make([]byte, 15),
			},
			wantErr: ErrInvalidSalt,
		},
		{
			name: "salt too long",
			params: &PBKDFParams{
				Iterations: 1000,
				Salt:       make([]byte, 33),
			},
			wantErr: ErrInvalidSalt,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePBKDFParams(tt.params)
			if err != tt.wantErr {
				t.Errorf("ValidatePBKDFParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExtractSetupInfo(t *testing.T) {
	t.Run("nil payload", func(t *testing.T) {
		_, err := ExtractSetupInfo(nil)
		if err == nil {
			t.Error("ExtractSetupInfo(nil) expected error")
		}
	})

	t.Run("basic payload", func(t *testing.T) {
		payload := &SetupPayload{
			Passcode:                 12345679,
			Discriminator:            NewLongDiscriminator(2560),
			VendorID:                 0x1234,
			ProductID:                0x5678,
			CommissioningFlow:        CommissioningFlowStandard,
			DiscoveryCapabilities:    DiscoveryCapabilityBLE | DiscoveryCapabilityOnNetwork,
			HasDiscoveryCapabilities: true,
		}

		info, err := ExtractSetupInfo(payload)
		if err != nil {
			t.Fatalf("ExtractSetupInfo() error: %v", err)
		}

		if info.Passcode != 12345679 {
			t.Errorf("Passcode = %d, want 12345679", info.Passcode)
		}
		if info.Discriminator.Long() != 2560 {
			t.Errorf("Discriminator = %d, want 2560", info.Discriminator.Long())
		}
		if info.VendorID != 0x1234 {
			t.Errorf("VendorID = %d, want 0x1234", info.VendorID)
		}
		if info.ProductID != 0x5678 {
			t.Errorf("ProductID = %d, want 0x5678", info.ProductID)
		}
		if info.CommissioningFlow != CommissioningFlowStandard {
			t.Errorf("CommissioningFlow = %v, want Standard", info.CommissioningFlow)
		}
		if !info.HasDiscoveryCapabilities {
			t.Error("HasDiscoveryCapabilities = false, want true")
		}
		if info.PBKDFParams == nil {
			t.Error("PBKDFParams is nil")
		}
	})

	t.Run("with optional data", func(t *testing.T) {
		payload := &SetupPayload{
			Passcode:      12345679,
			Discriminator: NewLongDiscriminator(2560),
			OptionalData: &OptionalData{
				SerialNumber:            "SN12345",
				HasSerialNumber:         true,
				CommissioningTimeout:    300,
				HasCommissioningTimeout: true,
				PBKDFIterations:         5000,
				HasPBKDFIterations:      true,
			},
		}

		info, err := ExtractSetupInfo(payload)
		if err != nil {
			t.Fatalf("ExtractSetupInfo() error: %v", err)
		}

		if info.SerialNumber != "SN12345" {
			t.Errorf("SerialNumber = %q, want %q", info.SerialNumber, "SN12345")
		}
		if info.CommissioningTimeout != 300 {
			t.Errorf("CommissioningTimeout = %d, want 300", info.CommissioningTimeout)
		}
		if info.PBKDFParams.Iterations != 5000 {
			t.Errorf("PBKDFParams.Iterations = %d, want 5000", info.PBKDFParams.Iterations)
		}
	})
}
