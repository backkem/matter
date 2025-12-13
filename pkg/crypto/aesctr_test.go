package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Matter SDK test vectors for AES-CTR-128 encryption/decryption.
// From connectedhomeip/src/crypto/tests/TestChipCryptoPAL.cpp
//
// Sourced from RFC 3686 Section 6, modified to use Matter's counter format:
// IV = flags byte (L-1) | 13 byte nonce | u16 counter
// This matches NIST 800-38C Appendix A.3 counter generation with q=2.
var matterSDKCTRTestVectors = []struct {
	name       string
	key        string // AES-128 key (hex, 16 bytes)
	nonce      string // Nonce (hex, 13 bytes)
	plaintext  string // Plaintext (hex)
	ciphertext string // Ciphertext (hex)
}{
	// RFC 3686 Test Vector #1 (modified for Matter counter format)
	// Original: AES-CTR with 32-bit block counter
	// Modified: Uses Matter's 13-byte nonce + 2-byte counter format
	{
		name:       "SDK_RFC3686_Vector1",
		key:        "ae6852f8121067cc4bf7a5765577f39e",
		nonce:      "00000030000000000000000000",
		plaintext:  "53696e676c6520626c6f636b206d7367", // "Single block msg"
		ciphertext: "0d0a6b6dc1f69b4d14ca4c15422242c4",
	},
	// RFC 3686 Test Vector #2 (modified for Matter counter format)
	// 32 bytes (2 blocks)
	{
		name:       "SDK_RFC3686_Vector2",
		key:        "7e24067817fae0d743d6ce1f32539163",
		nonce:      "006cb6dbc0543b59da48d90b00",
		plaintext:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		ciphertext: "4f3df94915884de0dc0e30950de7a6e95a917e1d064222db2f6ec73d994ad95f",
	},
}


func TestAESCTRConstants(t *testing.T) {
	if AESCTRKeySize != 16 {
		t.Errorf("AESCTRKeySize = %d, want 16", AESCTRKeySize)
	}
	if AESCTRNonceSize != 13 {
		t.Errorf("AESCTRNonceSize = %d, want 13", AESCTRNonceSize)
	}
}

func TestNewAESCTR(t *testing.T) {
	// Valid key
	key := make([]byte, AESCTRKeySize)
	_, err := NewAESCTR(key)
	if err != nil {
		t.Errorf("NewAESCTR with valid key failed: %v", err)
	}

	// Invalid key sizes
	invalidSizes := []int{0, 8, 15, 17, 24, 32}
	for _, size := range invalidSizes {
		key := make([]byte, size)
		_, err := NewAESCTR(key)
		if err != ErrAESCTRInvalidKeySize {
			t.Errorf("NewAESCTR with %d-byte key: got error %v, want ErrAESCTRInvalidKeySize", size, err)
		}
	}
}

func TestAESCTRRoundtrip(t *testing.T) {
	key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	nonce := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c}
	plaintext := []byte("Hello, Matter Protocol Privacy!")

	ctr, err := NewAESCTR(key)
	if err != nil {
		t.Fatalf("NewAESCTR failed: %v", err)
	}

	// Encrypt
	ciphertext, err := ctr.Encrypt(nonce, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify ciphertext length equals plaintext length
	if len(ciphertext) != len(plaintext) {
		t.Errorf("ciphertext length = %d, want %d", len(ciphertext), len(plaintext))
	}

	// Verify ciphertext is different from plaintext
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should be different from plaintext")
	}

	// Decrypt
	decrypted, err := ctr.Decrypt(nonce, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text mismatch\ngot:  %x\nwant: %x", decrypted, plaintext)
	}
}

func TestAESCTRRoundtripEmpty(t *testing.T) {
	key := make([]byte, AESCTRKeySize)
	nonce := make([]byte, AESCTRNonceSize)
	plaintext := []byte{}

	ctr, err := NewAESCTR(key)
	if err != nil {
		t.Fatalf("NewAESCTR failed: %v", err)
	}

	ciphertext, err := ctr.Encrypt(nonce, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(ciphertext) != 0 {
		t.Errorf("ciphertext length = %d, want 0", len(ciphertext))
	}

	decrypted, err := ctr.Decrypt(nonce, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("decrypted length = %d, want 0", len(decrypted))
	}
}

func TestAESCTRInvalidNonce(t *testing.T) {
	key := make([]byte, AESCTRKeySize)
	ctr, err := NewAESCTR(key)
	if err != nil {
		t.Fatalf("NewAESCTR failed: %v", err)
	}

	invalidNonces := []int{0, 7, 12, 14, 16}
	for _, size := range invalidNonces {
		nonce := make([]byte, size)
		_, err := ctr.Encrypt(nonce, []byte("test"))
		if err != ErrAESCTRInvalidNonceSize {
			t.Errorf("Encrypt with %d-byte nonce: got error %v, want ErrAESCTRInvalidNonceSize", size, err)
		}

		_, err = ctr.Decrypt(nonce, []byte("test"))
		if err != ErrAESCTRInvalidNonceSize {
			t.Errorf("Decrypt with %d-byte nonce: got error %v, want ErrAESCTRInvalidNonceSize", size, err)
		}
	}
}

func TestAESCTRConvenienceFunctions(t *testing.T) {
	key := make([]byte, AESCTRKeySize)
	nonce := make([]byte, AESCTRNonceSize)
	plaintext := []byte("test convenience functions for privacy")

	ciphertext, err := AESCTREncrypt(key, nonce, plaintext)
	if err != nil {
		t.Fatalf("AESCTREncrypt failed: %v", err)
	}

	decrypted, err := AESCTRDecrypt(key, nonce, ciphertext)
	if err != nil {
		t.Fatalf("AESCTRDecrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text mismatch")
	}
}

// TestAESCTRSDKVectors tests against Matter SDK test vectors.
// These are from RFC 3686, modified for Matter's counter format.
func TestAESCTRSDKVectors(t *testing.T) {
	for _, tc := range matterSDKCTRTestVectors {
		t.Run(tc.name, func(t *testing.T) {
			key, err := hex.DecodeString(tc.key)
			if err != nil {
				t.Fatalf("failed to decode key: %v", err)
			}

			nonce, err := hex.DecodeString(tc.nonce)
			if err != nil {
				t.Fatalf("failed to decode nonce: %v", err)
			}

			plaintext, err := hex.DecodeString(tc.plaintext)
			if err != nil {
				t.Fatalf("failed to decode plaintext: %v", err)
			}

			expectedCiphertext, err := hex.DecodeString(tc.ciphertext)
			if err != nil {
				t.Fatalf("failed to decode expected ciphertext: %v", err)
			}

			// Encrypt
			ciphertext, err := AESCTREncrypt(key, nonce, plaintext)
			if err != nil {
				t.Fatalf("AESCTREncrypt failed: %v", err)
			}

			if !bytes.Equal(ciphertext, expectedCiphertext) {
				t.Errorf("ciphertext mismatch\ngot:  %x\nwant: %x", ciphertext, expectedCiphertext)
			}

			// Decrypt
			decrypted, err := AESCTRDecrypt(key, nonce, ciphertext)
			if err != nil {
				t.Fatalf("AESCTRDecrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("decrypted text mismatch\ngot:  %x\nwant: %x", decrypted, plaintext)
			}
		})
	}
}


func BenchmarkAESCTREncrypt(b *testing.B) {
	key := make([]byte, AESCTRKeySize)
	nonce := make([]byte, AESCTRNonceSize)
	plaintext := make([]byte, 256)

	ctr, _ := NewAESCTR(key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ctr.Encrypt(nonce, plaintext)
	}
}

func BenchmarkAESCTRDecrypt(b *testing.B) {
	key := make([]byte, AESCTRKeySize)
	nonce := make([]byte, AESCTRNonceSize)
	plaintext := make([]byte, 256)

	ctr, _ := NewAESCTR(key)
	ciphertext, _ := ctr.Encrypt(nonce, plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ctr.Decrypt(nonce, ciphertext)
	}
}
