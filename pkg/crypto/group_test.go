package crypto

import (
	"bytes"
	"testing"
)

// Test vectors from Matter SDK TestChipCryptoPAL.cpp TestGroup_OperationalKeyDerivation.
// These test operational group key derivation from epoch keys.

var (
	// Compressed Fabric ID for vectors 1 and 2
	testCompressedFabricID1 = []byte{0x29, 0x06, 0xC9, 0x08, 0xD1, 0x15, 0xD3, 0x62}

	// Compressed Fabric ID for vector 3 (spec example)
	testCompressedFabricID2 = []byte{0x87, 0xe1, 0xb0, 0x04, 0xe2, 0x35, 0xa1, 0x30}

	// Epoch Key 1
	testEpochKey1 = []byte{
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
		0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	}

	// Epoch Key 2
	testEpochKey2 = []byte{
		0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
		0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	}

	// Epoch Key 3 (from spec example Section 4.17.2)
	testEpochKey3 = []byte{
		0x23, 0x5b, 0xf7, 0xe6, 0x28, 0x23, 0xd3, 0x58,
		0xdc, 0xa4, 0xba, 0x50, 0xb1, 0x53, 0x5f, 0x4b,
	}

	// Expected Operational Group Key 1
	testOperationalKey1 = []byte{
		0x1f, 0x19, 0xed, 0x3c, 0xef, 0x8a, 0x21, 0x1b,
		0xaf, 0x30, 0x6f, 0xae, 0xee, 0xe7, 0xaa, 0xc6,
	}

	// Expected Operational Group Key 2
	testOperationalKey2 = []byte{
		0xaa, 0x97, 0x9a, 0x48, 0xbd, 0x8c, 0xdf, 0x29,
		0x3a, 0x07, 0x09, 0xb9, 0xc1, 0xeb, 0x19, 0x30,
	}

	// Expected Operational Group Key 3 (from spec example)
	testOperationalKey3 = []byte{
		0xa6, 0xf5, 0x30, 0x6b, 0xaf, 0x6d, 0x05, 0x0a,
		0xf2, 0x3b, 0xa4, 0xbd, 0x6b, 0x9d, 0xd9, 0x60,
	}

	// Expected Group Session IDs
	testGroupSessionID1 uint16 = 0x6c80
	testGroupSessionID2 uint16 = 0x0c48
)

func TestDeriveGroupOperationalKeyV1(t *testing.T) {
	tests := []struct {
		name               string
		epochKey           []byte
		compressedFabricID []byte
		wantKey            []byte
	}{
		{
			name:               "SDK Vector 1",
			epochKey:           testEpochKey1,
			compressedFabricID: testCompressedFabricID1,
			wantKey:            testOperationalKey1,
		},
		{
			name:               "SDK Vector 2",
			epochKey:           testEpochKey2,
			compressedFabricID: testCompressedFabricID1,
			wantKey:            testOperationalKey2,
		},
		{
			name:               "Spec Example (Section 4.17.2)",
			epochKey:           testEpochKey3,
			compressedFabricID: testCompressedFabricID2,
			wantKey:            testOperationalKey3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DeriveGroupOperationalKeyV1(tc.epochKey, tc.compressedFabricID)
			if err != nil {
				t.Fatalf("DeriveGroupOperationalKeyV1 failed: %v", err)
			}

			if len(got) != SymmetricKeySize {
				t.Errorf("operational key length = %d, want %d", len(got), SymmetricKeySize)
			}

			if !bytes.Equal(got, tc.wantKey) {
				t.Errorf("operational key mismatch:\n  got:  %x\n  want: %x", got, tc.wantKey)
			}
		})
	}
}

func TestDeriveGroupOperationalKeyV1InvalidInput(t *testing.T) {
	validEpochKey := make([]byte, SymmetricKeySize)
	validFabricID := make([]byte, CompressedFabricIDSize)

	// Invalid epoch key - nil
	_, err := DeriveGroupOperationalKeyV1(nil, validFabricID)
	if err != ErrInvalidEpochKeySize {
		t.Errorf("expected ErrInvalidEpochKeySize for nil epoch key, got %v", err)
	}

	// Invalid epoch key - too short
	_, err = DeriveGroupOperationalKeyV1(make([]byte, 15), validFabricID)
	if err != ErrInvalidEpochKeySize {
		t.Errorf("expected ErrInvalidEpochKeySize for 15-byte epoch key, got %v", err)
	}

	// Invalid epoch key - too long
	_, err = DeriveGroupOperationalKeyV1(make([]byte, 17), validFabricID)
	if err != ErrInvalidEpochKeySize {
		t.Errorf("expected ErrInvalidEpochKeySize for 17-byte epoch key, got %v", err)
	}

	// Invalid compressed fabric ID - nil
	_, err = DeriveGroupOperationalKeyV1(validEpochKey, nil)
	if err != ErrInvalidCompressedFabricIDSize {
		t.Errorf("expected ErrInvalidCompressedFabricIDSize for nil fabric ID, got %v", err)
	}

	// Invalid compressed fabric ID - too short
	_, err = DeriveGroupOperationalKeyV1(validEpochKey, make([]byte, 7))
	if err != ErrInvalidCompressedFabricIDSize {
		t.Errorf("expected ErrInvalidCompressedFabricIDSize for 7-byte fabric ID, got %v", err)
	}

	// Invalid compressed fabric ID - too long
	_, err = DeriveGroupOperationalKeyV1(validEpochKey, make([]byte, 9))
	if err != ErrInvalidCompressedFabricIDSize {
		t.Errorf("expected ErrInvalidCompressedFabricIDSize for 9-byte fabric ID, got %v", err)
	}
}

func TestDeriveGroupSessionIDV1(t *testing.T) {
	tests := []struct {
		name           string
		operationalKey []byte
		wantSessionID  uint16
	}{
		{
			name:           "SDK Vector 1",
			operationalKey: testOperationalKey1,
			wantSessionID:  testGroupSessionID1,
		},
		{
			name:           "SDK Vector 2",
			operationalKey: testOperationalKey2,
			wantSessionID:  testGroupSessionID2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DeriveGroupSessionIDV1(tc.operationalKey)
			if err != nil {
				t.Fatalf("DeriveGroupSessionIDV1 failed: %v", err)
			}

			if got != tc.wantSessionID {
				t.Errorf("session ID = 0x%04x, want 0x%04x", got, tc.wantSessionID)
			}
		})
	}
}

func TestDeriveGroupSessionIDV1InvalidInput(t *testing.T) {
	// Invalid operational key - nil
	_, err := DeriveGroupSessionIDV1(nil)
	if err != ErrInvalidOperationalKeySize {
		t.Errorf("expected ErrInvalidOperationalKeySize for nil key, got %v", err)
	}

	// Invalid operational key - too short
	_, err = DeriveGroupSessionIDV1(make([]byte, 15))
	if err != ErrInvalidOperationalKeySize {
		t.Errorf("expected ErrInvalidOperationalKeySize for 15-byte key, got %v", err)
	}

	// Invalid operational key - too long
	_, err = DeriveGroupSessionIDV1(make([]byte, 17))
	if err != ErrInvalidOperationalKeySize {
		t.Errorf("expected ErrInvalidOperationalKeySize for 17-byte key, got %v", err)
	}
}

func TestDeriveGroupCredentialsV1(t *testing.T) {
	// Test with SDK Vector 1
	creds, err := DeriveGroupCredentialsV1(testEpochKey1, testCompressedFabricID1)
	if err != nil {
		t.Fatalf("DeriveGroupCredentialsV1 failed: %v", err)
	}

	// Verify encryption key
	if !bytes.Equal(creds.EncryptionKey, testOperationalKey1) {
		t.Errorf("encryption key mismatch:\n  got:  %x\n  want: %x", creds.EncryptionKey, testOperationalKey1)
	}

	// Verify session ID
	if creds.SessionID != testGroupSessionID1 {
		t.Errorf("session ID = 0x%04x, want 0x%04x", creds.SessionID, testGroupSessionID1)
	}

	// Verify privacy key (should match what DerivePrivacyKey produces)
	expectedPrivacyKey, err := DerivePrivacyKey(testOperationalKey1)
	if err != nil {
		t.Fatalf("DerivePrivacyKey failed: %v", err)
	}
	if !bytes.Equal(creds.PrivacyKey, expectedPrivacyKey) {
		t.Errorf("privacy key mismatch:\n  got:  %x\n  want: %x", creds.PrivacyKey, expectedPrivacyKey)
	}
}

func TestDeriveGroupCredentialsV1SpecExample(t *testing.T) {
	// Test with spec example (Section 4.17.2)
	creds, err := DeriveGroupCredentialsV1(testEpochKey3, testCompressedFabricID2)
	if err != nil {
		t.Fatalf("DeriveGroupCredentialsV1 failed: %v", err)
	}

	// Verify encryption key matches spec example
	if !bytes.Equal(creds.EncryptionKey, testOperationalKey3) {
		t.Errorf("encryption key mismatch:\n  got:  %x\n  want: %x", creds.EncryptionKey, testOperationalKey3)
	}
}

// TestGroupConstants verifies that constants match the spec.
func TestGroupConstants(t *testing.T) {
	if CompressedFabricIDSize != 8 {
		t.Errorf("CompressedFabricIDSize = %d, want 8", CompressedFabricIDSize)
	}
	if GroupSessionIDSize != 2 {
		t.Errorf("GroupSessionIDSize = %d, want 2", GroupSessionIDSize)
	}

	// Verify group key info string matches spec Section 4.17.2.1
	expectedInfo := []byte{0x47, 0x72, 0x6f, 0x75, 0x70, 0x4b, 0x65, 0x79, 0x20, 0x76, 0x31, 0x2e, 0x30}
	if !bytes.Equal(groupKeyInfo, expectedInfo) {
		t.Errorf("groupKeyInfo mismatch:\n  got:  %x\n  want: %x", groupKeyInfo, expectedInfo)
	}

	// Verify group key hash info string
	expectedHashInfo := []byte{0x47, 0x72, 0x6f, 0x75, 0x70, 0x4b, 0x65, 0x79, 0x48, 0x61, 0x73, 0x68}
	if !bytes.Equal(groupKeyHashInfo, expectedHashInfo) {
		t.Errorf("groupKeyHashInfo mismatch:\n  got:  %x\n  want: %x", groupKeyHashInfo, expectedHashInfo)
	}
}
