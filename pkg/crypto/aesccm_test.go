package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// RFC 3610 test vectors from Section 8.
// https://datatracker.ietf.org/doc/html/rfc3610
//
// These vectors have 13-byte nonces with 8-byte tags (M=8).
// L=2 (length field is 2 bytes since 15-13=2)
var rfc3610TestVectors = []struct {
	name       string
	key        string // AES key (hex)
	nonce      string // 13-byte nonce (hex)
	aad        string // Additional authenticated data (hex)
	plaintext  string // Plaintext to encrypt (hex)
	ciphertext string // Ciphertext without AAD (hex)
	tag        string // 8-byte tag (hex)
	nonceSize  int    // Nonce size (7-13)
	tagSize    int    // Tag size (4, 6, 8, 10, 12, 14, or 16)
}{
	// Packet Vector #1 (M=8, L=2)
	// From RFC 3610 Section 8:
	// Input: AAD (8 bytes) + plaintext (23 bytes) = 31 bytes
	// Output: AAD (8 bytes) + ciphertext (23 bytes) + tag (8 bytes) = 39 bytes
	{
		name:       "RFC3610_Vector1",
		key:        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
		nonce:      "00000003020100a0a1a2a3a4a5",
		aad:        "0001020304050607",
		plaintext:  "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
		ciphertext: "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384",
		tag:        "17e8d12cfdf926e0",
		nonceSize:  13,
		tagSize:    8,
	},
	// Packet Vector #2 (M=8, L=2)
	// Input: AAD (8 bytes) + plaintext (24 bytes) = 32 bytes
	// Output: AAD (8 bytes) + ciphertext (24 bytes) + tag (8 bytes) = 40 bytes
	{
		name:       "RFC3610_Vector2",
		key:        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
		nonce:      "00000004030201a0a1a2a3a4a5",
		aad:        "0001020304050607",
		plaintext:  "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		ciphertext: "72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3b",
		tag:        "a091d56e10400916",
		nonceSize:  13,
		tagSize:    8,
	},
	// Packet Vector #7 (M=10, L=2) - 10-byte tag
	// Input: AAD (8 bytes) + plaintext (23 bytes) = 31 bytes
	// Output: AAD (8 bytes) + ciphertext (23 bytes) + tag (10 bytes) = 41 bytes
	{
		name:       "RFC3610_Vector7",
		key:        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
		nonce:      "00000009080706a0a1a2a3a4a5",
		aad:        "0001020304050607",
		plaintext:  "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
		ciphertext: "0135d1b2c95f41d5d1d4fec185d166b8094e999dfed96c",
		tag:        "048c56602c97acbb7490",
		nonceSize:  13,
		tagSize:    10,
	},
}

// Matter SDK test vectors with 13-byte nonce and 16-byte tag
// These are from connectedhomeip/src/crypto/tests/AES_CCM_128_test_vectors.h
var matterSDKTestVectors = []struct {
	name       string
	key        string // AES-128 key (hex)
	nonce      string // 13-byte nonce (hex)
	aad        string // Additional authenticated data (hex)
	plaintext  string // Plaintext (hex)
	ciphertext string // Ciphertext (hex, same length as plaintext)
	tag        string // 16-byte authentication tag (hex)
}{
	// tcId=38: Empty plaintext with 13-byte nonce and 16-byte tag
	{
		name:       "SDK_empty_plaintext",
		key:        "404142434445464748494a4b4c4d4e4f",
		nonce:      "101112131415161718191a1b1c",
		aad:        "",
		plaintext:  "",
		ciphertext: "",
		tag:        "32d6f8243a26d0bd98d01b0f448e7773",
	},
	// aesccm128_matter_2ef53070ae20_test_vector_0: 13-byte plaintext
	{
		name:       "SDK_matter_2ef53070ae20",
		key:        "0953fa93e7caac9638f58820220a398e",
		nonce:      "00800000011201000012345678",
		aad:        "",
		plaintext:  "fffd034b50057e400000010000",
		ciphertext: "b5e5bfdacbaf6cb7fb6bff871f",
		tag:        "b0d6dd827d35bf372fa6425dcd17d356",
	},
	// aesccm128_matter_91c8d337cf46_test_vector_1: 9-byte plaintext
	{
		name:       "SDK_matter_91c8d337cf46",
		key:        "0953fa93e7caac9638f58820220a398e",
		nonce:      "00800148202345000012345678",
		aad:        "",
		plaintext:  "120104320308ba072f",
		ciphertext: "79d7dbc0c9b4d43eeb",
		tag:        "281508e50d58dbbd27c39597800f4733",
	},
}

// Matter Spec Appendix F.4 Check-In Protocol test vectors
// These test vectors exercise the full encryption/decryption flow.
var matterCheckInTestVectors = []struct {
	name        string
	key         string // Symmetric key (hex, colon-separated in spec)
	counter     string // Server counter (hex, little-endian)
	appData     string // Application data (ASCII or hex)
	nonce       string // Generated nonce (hex)
	ciphertext  string // Expected ciphertext (hex)
	tag         string // Expected tag (hex)
	fullPayload string // Full Check-In message payload (hex)
}{
	// Test 1: Empty application data
	{
		name:        "CheckIn_Test1_Empty",
		key:         "d90e13180d00baadd20cf5ed4913d3ff",
		counter:     "0c000000",
		appData:     "",
		nonce:       "4580d2c6f1310dc4eb64f1f8e8",
		ciphertext:  "bdc21fb5",
		tag:         "195d747dd2879b2b0d43ce5b1c565078",
		fullPayload: "4580d2c6f1310dc4eb64f1f8e8bdc21fb5195d747dd2879b2b0d43ce5b1c565078",
	},
	// Test 2: Application data "This"
	{
		name:        "CheckIn_Test2_This",
		key:         "18fdbceaef01955b0ec875eda3ae6ee8",
		counter:     "0f000000",
		appData:     "This",
		nonce:       "9b02ed21ee0c7b49198550e37",
		ciphertext:  "2dbd7b3f8b4f8e3c",
		tag:         "5ad994193f9f41a8d609938c67a86d65",
		fullPayload: "9b02ed21ee0c7b4919855002e372dbd7b3f8b4f8e3c5ad994193f9f41a8d609938c67a86d65",
	},
}

func TestAESCCMConstants(t *testing.T) {
	if AESCCMKeySize != 16 {
		t.Errorf("AESCCMKeySize = %d, want 16", AESCCMKeySize)
	}
	if AESCCMTagSize != 16 {
		t.Errorf("AESCCMTagSize = %d, want 16", AESCCMTagSize)
	}
	if AESCCMNonceSize != 13 {
		t.Errorf("AESCCMNonceSize = %d, want 13", AESCCMNonceSize)
	}
}

func TestNewAESCCM(t *testing.T) {
	// Valid key
	key := make([]byte, AESCCMKeySize)
	_, err := NewAESCCM(key)
	if err != nil {
		t.Errorf("NewAESCCM with valid key failed: %v", err)
	}

	// Invalid key sizes
	invalidSizes := []int{0, 8, 15, 17, 24, 32}
	for _, size := range invalidSizes {
		key := make([]byte, size)
		_, err := NewAESCCM(key)
		if err != ErrAESCCMInvalidKeySize {
			t.Errorf("NewAESCCM with %d-byte key: got error %v, want ErrAESCCMInvalidKeySize", size, err)
		}
	}
}

func TestAESCCMRoundtrip(t *testing.T) {
	key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	nonce := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c}
	plaintext := []byte("Hello, Matter Protocol!")
	aad := []byte("additional authenticated data")

	ccm, err := NewAESCCM(key)
	if err != nil {
		t.Fatalf("NewAESCCM failed: %v", err)
	}

	// Encrypt
	ciphertext, err := ccm.Seal(nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Verify ciphertext length
	expectedLen := len(plaintext) + AESCCMTagSize
	if len(ciphertext) != expectedLen {
		t.Errorf("ciphertext length = %d, want %d", len(ciphertext), expectedLen)
	}

	// Decrypt
	decrypted, err := ccm.Open(nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text mismatch\ngot:  %x\nwant: %x", decrypted, plaintext)
	}
}

func TestAESCCMRoundtripEmptyPlaintext(t *testing.T) {
	key := make([]byte, AESCCMKeySize)
	nonce := make([]byte, AESCCMNonceSize)
	plaintext := []byte{}
	aad := []byte("some aad")

	ccm, err := NewAESCCM(key)
	if err != nil {
		t.Fatalf("NewAESCCM failed: %v", err)
	}

	ciphertext, err := ccm.Seal(nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Ciphertext should be just the tag
	if len(ciphertext) != AESCCMTagSize {
		t.Errorf("ciphertext length = %d, want %d", len(ciphertext), AESCCMTagSize)
	}

	decrypted, err := ccm.Open(nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("decrypted length = %d, want 0", len(decrypted))
	}
}

func TestAESCCMRoundtripNoAAD(t *testing.T) {
	key := make([]byte, AESCCMKeySize)
	nonce := make([]byte, AESCCMNonceSize)
	plaintext := []byte("test message without aad")
	aad := []byte{} // No AAD

	ccm, err := NewAESCCM(key)
	if err != nil {
		t.Fatalf("NewAESCCM failed: %v", err)
	}

	ciphertext, err := ccm.Seal(nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	decrypted, err := ccm.Open(nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text mismatch")
	}
}

func TestAESCCMAuthenticationFailure(t *testing.T) {
	key := make([]byte, AESCCMKeySize)
	nonce := make([]byte, AESCCMNonceSize)
	plaintext := []byte("test message")
	aad := []byte("aad")

	ccm, err := NewAESCCM(key)
	if err != nil {
		t.Fatalf("NewAESCCM failed: %v", err)
	}

	ciphertext, err := ccm.Seal(nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Tamper with ciphertext
	tamperedCiphertext := make([]byte, len(ciphertext))
	copy(tamperedCiphertext, ciphertext)
	tamperedCiphertext[0] ^= 0x01

	_, err = ccm.Open(nonce, tamperedCiphertext, aad)
	if err != ErrAESCCMAuthFailed {
		t.Errorf("Open with tampered ciphertext: got error %v, want ErrAESCCMAuthFailed", err)
	}

	// Tamper with tag
	tamperedTag := make([]byte, len(ciphertext))
	copy(tamperedTag, ciphertext)
	tamperedTag[len(tamperedTag)-1] ^= 0x01

	_, err = ccm.Open(nonce, tamperedTag, aad)
	if err != ErrAESCCMAuthFailed {
		t.Errorf("Open with tampered tag: got error %v, want ErrAESCCMAuthFailed", err)
	}

	// Wrong AAD
	_, err = ccm.Open(nonce, ciphertext, []byte("wrong aad"))
	if err != ErrAESCCMAuthFailed {
		t.Errorf("Open with wrong AAD: got error %v, want ErrAESCCMAuthFailed", err)
	}
}

func TestAESCCMInvalidNonce(t *testing.T) {
	key := make([]byte, AESCCMKeySize)
	ccm, err := NewAESCCM(key)
	if err != nil {
		t.Fatalf("NewAESCCM failed: %v", err)
	}

	invalidNonces := []int{0, 7, 12, 14, 16}
	for _, size := range invalidNonces {
		nonce := make([]byte, size)
		_, err := ccm.Seal(nonce, []byte("test"), nil)
		if err != ErrAESCCMInvalidNonceSize {
			t.Errorf("Seal with %d-byte nonce: got error %v, want ErrAESCCMInvalidNonceSize", size, err)
		}

		_, err = ccm.Open(nonce, make([]byte, AESCCMTagSize), nil)
		if err != ErrAESCCMInvalidNonceSize {
			t.Errorf("Open with %d-byte nonce: got error %v, want ErrAESCCMInvalidNonceSize", size, err)
		}
	}
}

func TestAESCCMCiphertextTooShort(t *testing.T) {
	key := make([]byte, AESCCMKeySize)
	nonce := make([]byte, AESCCMNonceSize)

	ccm, err := NewAESCCM(key)
	if err != nil {
		t.Fatalf("NewAESCCM failed: %v", err)
	}

	// Ciphertext shorter than tag size
	shortCiphertext := make([]byte, AESCCMTagSize-1)
	_, err = ccm.Open(nonce, shortCiphertext, nil)
	if err != ErrAESCCMCiphertextTooShort {
		t.Errorf("Open with short ciphertext: got error %v, want ErrAESCCMCiphertextTooShort", err)
	}
}

func TestAESCCMConvenienceFunctions(t *testing.T) {
	key := make([]byte, AESCCMKeySize)
	nonce := make([]byte, AESCCMNonceSize)
	plaintext := []byte("test convenience functions")
	aad := []byte("aad")

	ciphertext, err := AESCCM128Encrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("AESCCM128Encrypt failed: %v", err)
	}

	decrypted, err := AESCCM128Decrypt(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("AESCCM128Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text mismatch")
	}
}

// TestAESCCMSDKVectors tests against known test vectors from the Matter SDK
func TestAESCCMSDKVectors(t *testing.T) {
	for _, tc := range matterSDKTestVectors {
		t.Run(tc.name, func(t *testing.T) {
			key, err := hex.DecodeString(tc.key)
			if err != nil {
				t.Fatalf("failed to decode key: %v", err)
			}

			nonce, err := hex.DecodeString(tc.nonce)
			if err != nil {
				t.Fatalf("failed to decode nonce: %v", err)
			}

			var aad []byte
			if tc.aad != "" {
				aad, err = hex.DecodeString(tc.aad)
				if err != nil {
					t.Fatalf("failed to decode aad: %v", err)
				}
			}

			plaintext, err := hex.DecodeString(tc.plaintext)
			if err != nil {
				t.Fatalf("failed to decode plaintext: %v", err)
			}

			expectedCiphertext, err := hex.DecodeString(tc.ciphertext)
			if err != nil {
				t.Fatalf("failed to decode expected ciphertext: %v", err)
			}

			expectedTag, err := hex.DecodeString(tc.tag)
			if err != nil {
				t.Fatalf("failed to decode expected tag: %v", err)
			}

			// Encrypt
			result, err := AESCCM128Encrypt(key, nonce, plaintext, aad)
			if err != nil {
				t.Fatalf("AESCCM128Encrypt failed: %v", err)
			}

			// Split result into ciphertext and tag
			gotCiphertext := result[:len(result)-AESCCMTagSize]
			gotTag := result[len(result)-AESCCMTagSize:]

			if !bytes.Equal(gotCiphertext, expectedCiphertext) {
				t.Errorf("ciphertext mismatch\ngot:  %x\nwant: %x", gotCiphertext, expectedCiphertext)
			}

			if !bytes.Equal(gotTag, expectedTag) {
				t.Errorf("tag mismatch\ngot:  %x\nwant: %x", gotTag, expectedTag)
			}

			// Decrypt
			decrypted, err := AESCCM128Decrypt(key, nonce, result, aad)
			if err != nil {
				t.Fatalf("AESCCM128Decrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("decrypted text mismatch\ngot:  %x\nwant: %x", decrypted, plaintext)
			}
		})
	}
}

// TestAESCCMRFC3610Vectors tests against authoritative RFC 3610 test vectors
// https://datatracker.ietf.org/doc/html/rfc3610
func TestAESCCMRFC3610Vectors(t *testing.T) {
	for _, tc := range rfc3610TestVectors {
		t.Run(tc.name, func(t *testing.T) {
			key, err := hex.DecodeString(tc.key)
			if err != nil {
				t.Fatalf("failed to decode key: %v", err)
			}

			nonce, err := hex.DecodeString(tc.nonce)
			if err != nil {
				t.Fatalf("failed to decode nonce: %v", err)
			}

			aad, err := hex.DecodeString(tc.aad)
			if err != nil {
				t.Fatalf("failed to decode aad: %v", err)
			}

			plaintext, err := hex.DecodeString(tc.plaintext)
			if err != nil {
				t.Fatalf("failed to decode plaintext: %v", err)
			}

			expectedCiphertext, err := hex.DecodeString(tc.ciphertext)
			if err != nil {
				t.Fatalf("failed to decode expected ciphertext: %v", err)
			}

			expectedTag, err := hex.DecodeString(tc.tag)
			if err != nil {
				t.Fatalf("failed to decode expected tag: %v", err)
			}

			// Create CCM cipher with RFC 3610 parameters
			ccm, err := NewAESCCMWithParams(key, tc.nonceSize, tc.tagSize)
			if err != nil {
				t.Fatalf("NewAESCCMWithParams failed: %v", err)
			}

			// Encrypt
			result, err := ccm.Seal(nonce, plaintext, aad)
			if err != nil {
				t.Fatalf("Seal failed: %v", err)
			}

			// Split result into ciphertext and tag
			gotCiphertext := result[:len(result)-tc.tagSize]
			gotTag := result[len(result)-tc.tagSize:]

			if !bytes.Equal(gotCiphertext, expectedCiphertext) {
				t.Errorf("ciphertext mismatch\ngot:  %x\nwant: %x", gotCiphertext, expectedCiphertext)
			}

			if !bytes.Equal(gotTag, expectedTag) {
				t.Errorf("tag mismatch\ngot:  %x\nwant: %x", gotTag, expectedTag)
			}

			// Decrypt
			decrypted, err := ccm.Open(nonce, result, aad)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("decrypted text mismatch\ngot:  %x\nwant: %x", decrypted, plaintext)
			}
		})
	}
}

func BenchmarkAESCCMSeal(b *testing.B) {
	key := make([]byte, AESCCMKeySize)
	nonce := make([]byte, AESCCMNonceSize)
	plaintext := make([]byte, 256)
	aad := make([]byte, 32)

	ccm, _ := NewAESCCM(key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ccm.Seal(nonce, plaintext, aad)
	}
}

func BenchmarkAESCCMOpen(b *testing.B) {
	key := make([]byte, AESCCMKeySize)
	nonce := make([]byte, AESCCMNonceSize)
	plaintext := make([]byte, 256)
	aad := make([]byte, 32)

	ccm, _ := NewAESCCM(key)
	ciphertext, _ := ccm.Seal(nonce, plaintext, aad)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ccm.Open(nonce, ciphertext, aad)
	}
}
