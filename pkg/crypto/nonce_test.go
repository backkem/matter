package crypto

import (
	"bytes"
	"testing"
)

// Test vectors for AEAD nonce construction.
// The nonce format is: SecurityFlags (1) || MessageCounter (4 LE) || SourceNodeID (8 LE)
func TestBuildAEADNonce(t *testing.T) {
	tests := []struct {
		name          string
		securityFlags uint8
		messageCounter uint32
		sourceNodeID  uint64
		wantNonce     []byte
	}{
		{
			name:          "Zero values",
			securityFlags: 0x00,
			messageCounter: 0,
			sourceNodeID:  0,
			wantNonce: []byte{
				0x00,                   // Security Flags
				0x00, 0x00, 0x00, 0x00, // Message Counter (LE)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source Node ID (LE)
			},
		},
		{
			name:          "Typical unicast session",
			securityFlags: 0x00, // Session type 0 (unicast)
			messageCounter: 1,
			sourceNodeID:  0, // Unspecified for PASE
			wantNonce: []byte{
				0x00,                   // Security Flags
				0x01, 0x00, 0x00, 0x00, // Message Counter = 1 (LE)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Unspecified Node ID
			},
		},
		{
			name:          "Group session with node ID",
			securityFlags: 0x01, // Session type 1 (group)
			messageCounter: 0x12345678,
			sourceNodeID:  0x0102030405060708,
			wantNonce: []byte{
				0x01,                   // Security Flags
				0x78, 0x56, 0x34, 0x12, // Message Counter (LE)
				0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // Source Node ID (LE)
			},
		},
		{
			name:          "Max counter value",
			securityFlags: 0xFF,
			messageCounter: 0xFFFFFFFF,
			sourceNodeID:  0xFFFFFFFFFFFFFFFF,
			wantNonce: []byte{
				0xFF,                   // Security Flags
				0xFF, 0xFF, 0xFF, 0xFF, // Message Counter (LE)
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Source Node ID (LE)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildAEADNonce(tc.securityFlags, tc.messageCounter, tc.sourceNodeID)

			if len(got) != NonceSize {
				t.Errorf("nonce length = %d, want %d", len(got), NonceSize)
			}

			if !bytes.Equal(got, tc.wantNonce) {
				t.Errorf("nonce mismatch:\n  got:  %x\n  want: %x", got, tc.wantNonce)
			}
		})
	}
}

// Test vectors for Privacy Key derivation from Matter SDK.
// These test vectors come from TestChipCryptoPAL.cpp TestGroup_PrivacyKeyDerivation.
func TestDerivePrivacyKey(t *testing.T) {
	tests := []struct {
		name           string
		encryptionKey  []byte
		wantPrivacyKey []byte
	}{
		{
			name: "SDK Vector 1 (GroupOperationalKey1)",
			encryptionKey: []byte{
				0x1f, 0x19, 0xed, 0x3c, 0xef, 0x8a, 0x21, 0x1b,
				0xaf, 0x30, 0x6f, 0xae, 0xee, 0xe7, 0xaa, 0xc6,
			},
			wantPrivacyKey: []byte{
				0xb8, 0x27, 0x9f, 0x89, 0x62, 0x1e, 0xd3, 0x27,
				0xa9, 0xc3, 0x9f, 0x6a, 0x27, 0x24, 0x73, 0x58,
			},
		},
		{
			name: "SDK Vector 2 (GroupOperationalKey2)",
			encryptionKey: []byte{
				0xaa, 0x97, 0x9a, 0x48, 0xbd, 0x8c, 0xdf, 0x29,
				0x3a, 0x07, 0x09, 0xb9, 0xc1, 0xeb, 0x19, 0x30,
			},
			wantPrivacyKey: []byte{
				0xf7, 0x25, 0x70, 0xc3, 0xc0, 0x89, 0xa0, 0xfe,
				0x28, 0x75, 0x83, 0x57, 0xaf, 0xff, 0xb8, 0xd2,
			},
		},
		{
			name: "SDK Vector 3 (GroupOperationalKey3 - spec example)",
			encryptionKey: []byte{
				0xa6, 0xf5, 0x30, 0x6b, 0xaf, 0x6d, 0x05, 0x0a,
				0xf2, 0x3b, 0xa4, 0xbd, 0x6b, 0x9d, 0xd9, 0x60,
			},
			wantPrivacyKey: []byte{
				0x01, 0xf8, 0xd1, 0x92, 0x71, 0x26, 0xf1, 0x94,
				0x08, 0x25, 0x72, 0xd4, 0x9b, 0x1f, 0xdc, 0x73,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DerivePrivacyKey(tc.encryptionKey)
			if err != nil {
				t.Fatalf("DerivePrivacyKey failed: %v", err)
			}

			if len(got) != SymmetricKeySize {
				t.Errorf("privacy key length = %d, want %d", len(got), SymmetricKeySize)
			}

			if !bytes.Equal(got, tc.wantPrivacyKey) {
				t.Errorf("privacy key mismatch:\n  got:  %x\n  want: %x", got, tc.wantPrivacyKey)
			}
		})
	}
}

func TestDerivePrivacyKeyInvalidInput(t *testing.T) {
	// Empty key
	_, err := DerivePrivacyKey(nil)
	if err != ErrInvalidKeySize {
		t.Errorf("expected ErrInvalidKeySize for nil key, got %v", err)
	}

	// Too short
	_, err = DerivePrivacyKey(make([]byte, 15))
	if err != ErrInvalidKeySize {
		t.Errorf("expected ErrInvalidKeySize for 15-byte key, got %v", err)
	}

	// Too long
	_, err = DerivePrivacyKey(make([]byte, 17))
	if err != ErrInvalidKeySize {
		t.Errorf("expected ErrInvalidKeySize for 17-byte key, got %v", err)
	}
}

// Test vector for Privacy Nonce from Matter Specification Section 4.9.2.
// This is the example directly from the spec.
func TestBuildPrivacyNonce(t *testing.T) {
	tests := []struct {
		name             string
		sessionID        uint16
		mic              []byte
		wantPrivacyNonce []byte
	}{
		{
			// Example from Matter Specification Section 4.9.2:
			// Session ID = 42 (0x002A)
			// MIC = c5:a0:06:3a:d5:d2:51:81:91:40:0d:d6:8c:5c:16:3b
			// MIC[5..15] = d2:51:81:91:40:0d:d6:8c:5c:16:3b
			// PrivacyNonce = 00:2a:d2:51:81:91:40:0d:d6:8c:5c:16:3b
			name:      "Spec example (Section 4.9.2)",
			sessionID: 0x002A,
			mic: []byte{
				0xc5, 0xa0, 0x06, 0x3a, 0xd5, // bytes 0-4 (not used)
				0xd2, 0x51, 0x81, 0x91, 0x40, 0x0d, 0xd6, 0x8c, 0x5c, 0x16, 0x3b, // bytes 5-15 (used)
			},
			wantPrivacyNonce: []byte{
				0x00, 0x2a, // Session ID (big-endian)
				0xd2, 0x51, 0x81, 0x91, 0x40, 0x0d, 0xd6, 0x8c, 0x5c, 0x16, 0x3b, // MIC[5..15]
			},
		},
		{
			name:      "Zero session ID",
			sessionID: 0x0000,
			mic: []byte{
				0x00, 0x01, 0x02, 0x03, 0x04, // bytes 0-4
				0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // bytes 5-15
			},
			wantPrivacyNonce: []byte{
				0x00, 0x00, // Session ID (big-endian)
				0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			},
		},
		{
			name:      "Max session ID",
			sessionID: 0xFFFF,
			mic: []byte{
				0xff, 0xff, 0xff, 0xff, 0xff,
				0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
			},
			wantPrivacyNonce: []byte{
				0xff, 0xff, // Session ID (big-endian)
				0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildPrivacyNonce(tc.sessionID, tc.mic)
			if err != nil {
				t.Fatalf("BuildPrivacyNonce failed: %v", err)
			}

			if len(got) != NonceSize {
				t.Errorf("privacy nonce length = %d, want %d", len(got), NonceSize)
			}

			if !bytes.Equal(got, tc.wantPrivacyNonce) {
				t.Errorf("privacy nonce mismatch:\n  got:  %x\n  want: %x", got, tc.wantPrivacyNonce)
			}
		})
	}
}

func TestBuildPrivacyNonceInvalidInput(t *testing.T) {
	// Empty MIC
	_, err := BuildPrivacyNonce(0, nil)
	if err != ErrInvalidMICSize {
		t.Errorf("expected ErrInvalidMICSize for nil MIC, got %v", err)
	}

	// Too short
	_, err = BuildPrivacyNonce(0, make([]byte, 15))
	if err != ErrInvalidMICSize {
		t.Errorf("expected ErrInvalidMICSize for 15-byte MIC, got %v", err)
	}

	// Too long
	_, err = BuildPrivacyNonce(0, make([]byte, 17))
	if err != ErrInvalidMICSize {
		t.Errorf("expected ErrInvalidMICSize for 17-byte MIC, got %v", err)
	}
}

// TestNonceConstants verifies that constants match the spec.
func TestNonceConstants(t *testing.T) {
	if NonceSize != 13 {
		t.Errorf("NonceSize = %d, want 13", NonceSize)
	}
	if SymmetricKeySize != 16 {
		t.Errorf("SymmetricKeySize = %d, want 16", SymmetricKeySize)
	}
	if MICSize != 16 {
		t.Errorf("MICSize = %d, want 16", MICSize)
	}
	if PrivacyNonceMICOffset != 5 {
		t.Errorf("PrivacyNonceMICOffset = %d, want 5", PrivacyNonceMICOffset)
	}
	if PrivacyNonceMICLength != 11 {
		t.Errorf("PrivacyNonceMICLength = %d, want 11", PrivacyNonceMICLength)
	}
	// Verify MIC offset + length = MIC size
	if PrivacyNonceMICOffset+PrivacyNonceMICLength != MICSize {
		t.Errorf("PrivacyNonceMICOffset + PrivacyNonceMICLength = %d, want %d",
			PrivacyNonceMICOffset+PrivacyNonceMICLength, MICSize)
	}
}
