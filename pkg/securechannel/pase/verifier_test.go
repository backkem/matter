package pase

import (
	"bytes"
	"testing"
)

// Test vectors from C reference implementation (TestPASESession.cpp).
// These are the official Matter SDK test vectors.
var (
	// Test Set #01 of Spake2p Parameters
	testSpake2p01PinCode        = uint32(20202021)
	testSpake2p01IterationCount = uint32(1000)
	testSpake2p01Salt           = []byte{
		0x53, 0x50, 0x41, 0x4B, 0x45, 0x32, 0x50, 0x20,
		0x4B, 0x65, 0x79, 0x20, 0x53, 0x61, 0x6C, 0x74,
	} // "SPAKE2P Key Salt"

	// Expected W0 (32 bytes)
	testSpake2p01W0 = []byte{
		0xB9, 0x61, 0x70, 0xAA, 0xE8, 0x03, 0x34, 0x68, 0x84, 0x72, 0x4F, 0xE9, 0xA3, 0xB2, 0x87, 0xC3,
		0x03, 0x30, 0xC2, 0xA6, 0x60, 0x37, 0x5D, 0x17, 0xBB, 0x20, 0x5A, 0x8C, 0xF1, 0xAE, 0xCB, 0x35,
	}

	// Expected L (65 bytes, uncompressed point)
	testSpake2p01L = []byte{
		0x04, 0x57, 0xF8, 0xAB, 0x79, 0xEE, 0x25, 0x3A, 0xB6, 0xA8, 0xE4, 0x6B, 0xB0, 0x9E, 0x54, 0x3A,
		0xE4, 0x22, 0x73, 0x6D, 0xE5, 0x01, 0xE3, 0xDB, 0x37, 0xD4, 0x41, 0xFE, 0x34, 0x49, 0x20, 0xD0,
		0x95, 0x48, 0xE4, 0xC1, 0x82, 0x40, 0x63, 0x0C, 0x4F, 0xF4, 0x91, 0x3C, 0x53, 0x51, 0x38, 0x39,
		0xB7, 0xC0, 0x7F, 0xCC, 0x06, 0x27, 0xA1, 0xB8, 0x57, 0x3A, 0x14, 0x9F, 0xCD, 0x1F, 0xA4, 0x66,
		0xCF,
	}
)

func TestGenerateVerifierWithTestVector(t *testing.T) {
	verifier, err := GenerateVerifier(testSpake2p01PinCode, testSpake2p01Salt, testSpake2p01IterationCount)
	if err != nil {
		t.Fatalf("GenerateVerifier failed: %v", err)
	}

	if !bytes.Equal(verifier.W0, testSpake2p01W0) {
		t.Errorf("W0 mismatch:\ngot:  %x\nwant: %x", verifier.W0, testSpake2p01W0)
	}

	if !bytes.Equal(verifier.L, testSpake2p01L) {
		t.Errorf("L mismatch:\ngot:  %x\nwant: %x", verifier.L, testSpake2p01L)
	}
}

func TestVerifierSerializationRoundtrip(t *testing.T) {
	verifier, err := GenerateVerifier(testSpake2p01PinCode, testSpake2p01Salt, testSpake2p01IterationCount)
	if err != nil {
		t.Fatalf("GenerateVerifier failed: %v", err)
	}

	serialized := verifier.Serialize()
	if len(serialized) != 97 { // 32 + 65
		t.Errorf("Serialized length = %d, want 97", len(serialized))
	}

	deserialized, err := DeserializeVerifier(serialized)
	if err != nil {
		t.Fatalf("DeserializeVerifier failed: %v", err)
	}

	if !bytes.Equal(deserialized.W0, verifier.W0) {
		t.Error("W0 mismatch after deserialization")
	}
	if !bytes.Equal(deserialized.L, verifier.L) {
		t.Error("L mismatch after deserialization")
	}
}

func TestValidatePasscode(t *testing.T) {
	tests := []struct {
		name      string
		passcode  uint32
		wantError bool
	}{
		{"valid_20202021", 20202021, false},
		{"valid_12341234", 12341234, false},
		{"valid_minimum", 1, false},
		{"valid_maximum", 99999998, false},

		// Invalid patterns
		{"invalid_00000000", 00000000, true},
		{"invalid_11111111", 11111111, true},
		{"invalid_22222222", 22222222, true},
		{"invalid_33333333", 33333333, true},
		{"invalid_44444444", 44444444, true},
		{"invalid_55555555", 55555555, true},
		{"invalid_66666666", 66666666, true},
		{"invalid_77777777", 77777777, true},
		{"invalid_88888888", 88888888, true},
		{"invalid_99999999", 99999999, true},
		{"invalid_12345678", 12345678, true},
		{"invalid_87654321", 87654321, true},
		{"invalid_too_large", 100000000, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePasscode(tc.passcode)
			if tc.wantError && err == nil {
				t.Errorf("ValidatePasscode(%d) = nil, want error", tc.passcode)
			}
			if !tc.wantError && err != nil {
				t.Errorf("ValidatePasscode(%d) = %v, want nil", tc.passcode, err)
			}
		})
	}
}

func TestGenerateVerifierInvalidParams(t *testing.T) {
	validPasscode := uint32(20202021)
	validSalt := make([]byte, 32)
	validIterations := uint32(1000)

	t.Run("invalid_passcode", func(t *testing.T) {
		_, err := GenerateVerifier(00000000, validSalt, validIterations)
		if err == nil {
			t.Error("Expected error for invalid passcode")
		}
	})

	t.Run("salt_too_short", func(t *testing.T) {
		shortSalt := make([]byte, 8) // Min is 16
		_, err := GenerateVerifier(validPasscode, shortSalt, validIterations)
		if err == nil {
			t.Error("Expected error for short salt")
		}
	})

	t.Run("salt_too_long", func(t *testing.T) {
		longSalt := make([]byte, 64) // Max is 32
		_, err := GenerateVerifier(validPasscode, longSalt, validIterations)
		if err == nil {
			t.Error("Expected error for long salt")
		}
	})

	t.Run("iterations_too_low", func(t *testing.T) {
		_, err := GenerateVerifier(validPasscode, validSalt, 500) // Min is 1000
		if err == nil {
			t.Error("Expected error for low iterations")
		}
	})

	t.Run("iterations_too_high", func(t *testing.T) {
		_, err := GenerateVerifier(validPasscode, validSalt, 200000) // Max is 100000
		if err == nil {
			t.Error("Expected error for high iterations")
		}
	})
}

func TestComputeW0W1(t *testing.T) {
	w0, w1, err := ComputeW0W1(testSpake2p01PinCode, testSpake2p01Salt, testSpake2p01IterationCount)
	if err != nil {
		t.Fatalf("ComputeW0W1 failed: %v", err)
	}

	// W0 should match test vector
	if !bytes.Equal(w0, testSpake2p01W0) {
		t.Errorf("W0 mismatch:\ngot:  %x\nwant: %x", w0, testSpake2p01W0)
	}

	// W1 is not in the test vector, but should be 32 bytes
	if len(w1) != 32 {
		t.Errorf("W1 length = %d, want 32", len(w1))
	}
}

// TestSerializedVerifierFormat verifies the exact serialized format matches C reference.
// The serialized format is W0 || L (32 + 65 = 97 bytes).
// This matches the C SDK's Spake2pVerifierSerialized format from TestPASESession.cpp.
func TestSerializedVerifierFormat(t *testing.T) {
	// Expected serialized verifier from C reference (W0 || L)
	expectedSerialized := append(testSpake2p01W0, testSpake2p01L...)

	verifier, err := GenerateVerifier(testSpake2p01PinCode, testSpake2p01Salt, testSpake2p01IterationCount)
	if err != nil {
		t.Fatalf("GenerateVerifier failed: %v", err)
	}

	serialized := verifier.Serialize()
	if !bytes.Equal(serialized, expectedSerialized) {
		t.Errorf("Serialized verifier mismatch:\ngot:  %x\nwant: %x", serialized, expectedSerialized)
	}

	// Verify deserialization
	deserialized, err := DeserializeVerifier(expectedSerialized)
	if err != nil {
		t.Fatalf("DeserializeVerifier failed: %v", err)
	}

	if !bytes.Equal(deserialized.W0, testSpake2p01W0) {
		t.Error("Deserialized W0 mismatch")
	}
	if !bytes.Equal(deserialized.L, testSpake2p01L) {
		t.Error("Deserialized L mismatch")
	}
}

func TestDeserializeVerifierInvalidLength(t *testing.T) {
	// Too short
	_, err := DeserializeVerifier(make([]byte, 96))
	if err == nil {
		t.Error("Expected error for too-short verifier")
	}

	// Too long
	_, err = DeserializeVerifier(make([]byte, 98))
	if err == nil {
		t.Error("Expected error for too-long verifier")
	}
}
