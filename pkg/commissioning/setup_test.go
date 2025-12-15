package commissioning

import (
	"testing"

	"github.com/backkem/matter/pkg/commissioning/payload"
)

func TestSetupParamsFromPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload *payload.SetupPayload
		wantErr bool
	}{
		{
			name: "basic payload",
			payload: &payload.SetupPayload{
				Passcode: 12345679,
			},
			wantErr: false,
		},
		{
			name: "payload with PBKDF params",
			payload: &payload.SetupPayload{
				Passcode: 12345679,
				OptionalData: &payload.OptionalData{
					PBKDFIterations:    5000,
					HasPBKDFIterations: true,
					BPKFSalt:           make([]byte, 24),
				},
			},
			wantErr: false,
		},
		{
			name: "payload with invalid iterations",
			payload: &payload.SetupPayload{
				Passcode: 12345679,
				OptionalData: &payload.OptionalData{
					PBKDFIterations:    500, // Too low
					HasPBKDFIterations: true,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := SetupParamsFromPayload(tt.payload)
			if tt.wantErr {
				if err == nil {
					t.Error("SetupParamsFromPayload() expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("SetupParamsFromPayload() error: %v", err)
			}

			if params.Passcode != tt.payload.Passcode {
				t.Errorf("Passcode = %d, want %d", params.Passcode, tt.payload.Passcode)
			}
			if len(params.Salt) < 16 {
				t.Errorf("Salt length = %d, want >= 16", len(params.Salt))
			}
			if params.Iterations < 1000 || params.Iterations > 100000 {
				t.Errorf("Iterations = %d, want 1000-100000", params.Iterations)
			}
		})
	}
}

func TestGenerateVerifier(t *testing.T) {
	// Test vector from C++ reference (TestPASESession.cpp)
	passcode := uint32(20202021)
	salt := make([]byte, 16)
	// Use test salt (all zeros for simplicity)
	iterations := uint32(1000)

	params := &SetupParams{
		Passcode:   passcode,
		Salt:       salt,
		Iterations: iterations,
	}

	verifier, err := GenerateVerifier(params)
	if err != nil {
		t.Fatalf("GenerateVerifier() error: %v", err)
	}

	// Verify W0 and L have correct lengths
	if len(verifier.W0) != 32 {
		t.Errorf("W0 length = %d, want 32", len(verifier.W0))
	}
	if len(verifier.L) != 65 {
		t.Errorf("L length = %d, want 65", len(verifier.L))
	}

	// L should be an uncompressed point (starts with 0x04)
	if verifier.L[0] != 0x04 {
		t.Errorf("L[0] = 0x%02x, want 0x04", verifier.L[0])
	}
}

func TestComputeW0W1(t *testing.T) {
	passcode := uint32(20202021)
	salt := make([]byte, 16)
	iterations := uint32(1000)

	params := &SetupParams{
		Passcode:   passcode,
		Salt:       salt,
		Iterations: iterations,
	}

	w0, w1, err := ComputeW0W1(params)
	if err != nil {
		t.Fatalf("ComputeW0W1() error: %v", err)
	}

	if len(w0) != 32 {
		t.Errorf("w0 length = %d, want 32", len(w0))
	}
	if len(w1) != 32 {
		t.Errorf("w1 length = %d, want 32", len(w1))
	}
}

func TestValidatePasscode(t *testing.T) {
	tests := []struct {
		passcode uint32
		wantErr  bool
	}{
		{12345679, false},
		{20202021, false},
		{1, false},
		{99999998, false},
		{0, true},
		{11111111, true},
		{12345678, true},
		{87654321, true},
	}

	for _, tt := range tests {
		err := ValidatePasscode(tt.passcode)
		if tt.wantErr && err == nil {
			t.Errorf("ValidatePasscode(%d) expected error", tt.passcode)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("ValidatePasscode(%d) unexpected error: %v", tt.passcode, err)
		}
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() error: %v", err)
	}

	if len(salt1) < 16 {
		t.Errorf("Salt length = %d, want >= 16", len(salt1))
	}

	// Generate another salt and ensure they're different
	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() error: %v", err)
	}

	// Salts should be different (extremely unlikely to be the same)
	same := true
	for i := range salt1 {
		if salt1[i] != salt2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("Two generated salts are identical (extremely unlikely)")
	}
}
