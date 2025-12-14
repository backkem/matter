package fabric

import (
	"encoding/hex"
	"testing"
)

// TestCompressedFabricID_SpecVector tests the compressed fabric ID computation
// using the exact test vector from Matter Specification Section 4.3.2.2.
func TestCompressedFabricID_SpecVector(t *testing.T) {
	// Root public key from spec (with 0x04 prefix):
	// 04:4a:9f:42:b1:ca:48:40:d3:72:92:bb:c7:f6:a7:e1:
	// 1e:22:20:0c:97:6f:c9:00:db:c9:8a:7a:38:3a:64:1c:
	// b8:25:4a:2e:56:d4:e2:95:a8:47:94:3b:4e:38:97:c4:
	// a7:73:e9:30:27:7b:4d:9f:be:de:8a:05:26:86:bf:ac:
	// fa
	rootPublicKeyHex := "044a9f42b1ca4840d37292bbc7f6a7e11e22200c976fc900dbc98a7a383a641cb8254a2e56d4e295a847943b4e3897c4a773e930277b4d9fbede8a052686bfacfa"
	rootPublicKey, err := hex.DecodeString(rootPublicKeyHex)
	if err != nil {
		t.Fatalf("failed to decode root public key: %v", err)
	}

	// Fabric ID from spec: 0x2906_C908_D115_D362
	fabricID := FabricID(0x2906C908D115D362)

	// Expected compressed fabric ID from spec: 0x87E1_B004_E235_A130
	// As bytes (big-endian): 87:e1:b0:04:e2:35:a1:30
	expectedHex := "87e1b004e235a130"
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		t.Fatalf("failed to decode expected: %v", err)
	}

	// Compute compressed fabric ID
	result, err := CompressedFabricID(rootPublicKey, fabricID)
	if err != nil {
		t.Fatalf("CompressedFabricID failed: %v", err)
	}

	// Verify result matches expected
	if hex.EncodeToString(result[:]) != expectedHex {
		t.Errorf("CompressedFabricID mismatch:\n  got:      %s\n  expected: %s",
			hex.EncodeToString(result[:]), expectedHex)
	}

	// Also verify byte-by-byte
	for i := 0; i < CompressedFabricIDSize; i++ {
		if result[i] != expected[i] {
			t.Errorf("byte %d mismatch: got 0x%02x, expected 0x%02x", i, result[i], expected[i])
		}
	}
}

// TestCompressedFabricID_WithoutPrefix tests that we can pass the 64-byte key
// without the 0x04 prefix.
func TestCompressedFabricID_WithoutPrefix(t *testing.T) {
	// Root public key WITHOUT 0x04 prefix (64 bytes)
	rootPublicKeyHex := "4a9f42b1ca4840d37292bbc7f6a7e11e22200c976fc900dbc98a7a383a641cb8254a2e56d4e295a847943b4e3897c4a773e930277b4d9fbede8a052686bfacfa"
	rootPublicKey, err := hex.DecodeString(rootPublicKeyHex)
	if err != nil {
		t.Fatalf("failed to decode root public key: %v", err)
	}

	fabricID := FabricID(0x2906C908D115D362)
	expectedHex := "87e1b004e235a130"

	result, err := CompressedFabricID(rootPublicKey, fabricID)
	if err != nil {
		t.Fatalf("CompressedFabricID failed: %v", err)
	}

	if hex.EncodeToString(result[:]) != expectedHex {
		t.Errorf("CompressedFabricID mismatch:\n  got:      %s\n  expected: %s",
			hex.EncodeToString(result[:]), expectedHex)
	}
}

// TestCompressedFabricID_InvalidInputs tests error handling for invalid inputs.
func TestCompressedFabricID_InvalidInputs(t *testing.T) {
	validKey := make([]byte, 65)
	validKey[0] = 0x04

	tests := []struct {
		name      string
		key       []byte
		fabricID  FabricID
		wantError error
	}{
		{
			name:      "invalid fabric ID (zero)",
			key:       validKey,
			fabricID:  FabricIDInvalid,
			wantError: ErrInvalidFabricID,
		},
		{
			name:      "key too short",
			key:       make([]byte, 32),
			fabricID:  FabricID(1),
			wantError: ErrInvalidRootPublicKey,
		},
		{
			name:      "key too long",
			key:       make([]byte, 128),
			fabricID:  FabricID(1),
			wantError: ErrInvalidRootPublicKey,
		},
		{
			name:      "65-byte key with wrong prefix",
			key:       make([]byte, 65), // starts with 0x00, not 0x04
			fabricID:  FabricID(1),
			wantError: ErrInvalidRootPublicKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CompressedFabricID(tt.key, tt.fabricID)
			if err != tt.wantError {
				t.Errorf("expected error %v, got %v", tt.wantError, err)
			}
		})
	}
}

// TestCompressedFabricIDFromCert tests the convenience function for cert keys.
func TestCompressedFabricIDFromCert(t *testing.T) {
	// Root public key with 0x04 prefix
	rootPublicKeyHex := "044a9f42b1ca4840d37292bbc7f6a7e11e22200c976fc900dbc98a7a383a641cb8254a2e56d4e295a847943b4e3897c4a773e930277b4d9fbede8a052686bfacfa"
	keyBytes, _ := hex.DecodeString(rootPublicKeyHex)

	var rootPublicKey [RootPublicKeySize]byte
	copy(rootPublicKey[:], keyBytes)

	fabricID := FabricID(0x2906C908D115D362)
	expectedHex := "87e1b004e235a130"

	result, err := CompressedFabricIDFromCert(rootPublicKey, fabricID)
	if err != nil {
		t.Fatalf("CompressedFabricIDFromCert failed: %v", err)
	}

	if hex.EncodeToString(result[:]) != expectedHex {
		t.Errorf("CompressedFabricIDFromCert mismatch:\n  got:      %s\n  expected: %s",
			hex.EncodeToString(result[:]), expectedHex)
	}
}
