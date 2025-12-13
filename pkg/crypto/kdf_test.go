package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors from RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
// https://datatracker.ietf.org/doc/html/rfc5869#appendix-A
//
// We only use the SHA-256 test cases (Test Cases 1, 2, 3).
var hkdfSHA256TestVectors = []struct {
	name   string
	ikm    string // Input Keying Material (hex)
	salt   string // Salt (hex)
	info   string // Info (hex)
	length int    // Output length in bytes
	prk    string // Expected PRK (hex) - for testing Extract
	okm    string // Expected Output Keying Material (hex)
}{
	// RFC 5869 Test Case 1 - Basic test case with SHA-256
	{
		name:   "RFC5869_TC1",
		ikm:    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		salt:   "000102030405060708090a0b0c",
		info:   "f0f1f2f3f4f5f6f7f8f9",
		length: 42,
		prk:    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
		okm:    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
	},
	// RFC 5869 Test Case 2 - Test with SHA-256 and longer inputs/outputs
	{
		name:   "RFC5869_TC2",
		ikm:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
		salt:   "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
		info:   "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		length: 82,
		prk:    "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
		okm:    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
	},
	// RFC 5869 Test Case 3 - Test with SHA-256 and zero-length salt/info
	{
		name:   "RFC5869_TC3",
		ikm:    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		salt:   "",
		info:   "",
		length: 42,
		prk:    "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
		okm:    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
	},
}

func TestHKDFSHA256(t *testing.T) {
	for _, tc := range hkdfSHA256TestVectors {
		t.Run(tc.name, func(t *testing.T) {
			ikm, err := hex.DecodeString(tc.ikm)
			if err != nil {
				t.Fatalf("failed to decode ikm: %v", err)
			}

			var salt []byte
			if tc.salt != "" {
				salt, err = hex.DecodeString(tc.salt)
				if err != nil {
					t.Fatalf("failed to decode salt: %v", err)
				}
			}

			var info []byte
			if tc.info != "" {
				info, err = hex.DecodeString(tc.info)
				if err != nil {
					t.Fatalf("failed to decode info: %v", err)
				}
			}

			expected, err := hex.DecodeString(tc.okm)
			if err != nil {
				t.Fatalf("failed to decode expected okm: %v", err)
			}

			result, err := HKDFSHA256(ikm, salt, info, tc.length)
			if err != nil {
				t.Fatalf("HKDFSHA256 failed: %v", err)
			}

			if !bytes.Equal(result, expected) {
				t.Errorf("OKM mismatch\ngot:  %x\nwant: %x", result, expected)
			}
		})
	}
}

func TestHKDFExtractSHA256(t *testing.T) {
	for _, tc := range hkdfSHA256TestVectors {
		t.Run(tc.name, func(t *testing.T) {
			ikm, err := hex.DecodeString(tc.ikm)
			if err != nil {
				t.Fatalf("failed to decode ikm: %v", err)
			}

			var salt []byte
			if tc.salt != "" {
				salt, err = hex.DecodeString(tc.salt)
				if err != nil {
					t.Fatalf("failed to decode salt: %v", err)
				}
			}

			expected, err := hex.DecodeString(tc.prk)
			if err != nil {
				t.Fatalf("failed to decode expected prk: %v", err)
			}

			result := HKDFExtractSHA256(ikm, salt)

			if !bytes.Equal(result, expected) {
				t.Errorf("PRK mismatch\ngot:  %x\nwant: %x", result, expected)
			}
		})
	}
}

func TestHKDFExpandSHA256(t *testing.T) {
	for _, tc := range hkdfSHA256TestVectors {
		t.Run(tc.name, func(t *testing.T) {
			prk, err := hex.DecodeString(tc.prk)
			if err != nil {
				t.Fatalf("failed to decode prk: %v", err)
			}

			var info []byte
			if tc.info != "" {
				info, err = hex.DecodeString(tc.info)
				if err != nil {
					t.Fatalf("failed to decode info: %v", err)
				}
			}

			expected, err := hex.DecodeString(tc.okm)
			if err != nil {
				t.Fatalf("failed to decode expected okm: %v", err)
			}

			result, err := HKDFExpandSHA256(prk, info, tc.length)
			if err != nil {
				t.Fatalf("HKDFExpandSHA256 failed: %v", err)
			}

			if !bytes.Equal(result, expected) {
				t.Errorf("OKM mismatch\ngot:  %x\nwant: %x", result, expected)
			}
		})
	}
}

// Test vectors from RFC 6070: PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2) Test Vectors
// https://datatracker.ietf.org/doc/html/rfc6070
//
// Note: RFC 6070 uses PBKDF2-HMAC-SHA1. For PBKDF2-HMAC-SHA256, we use vectors from
// various sources including the Matter SDK test vectors.
var pbkdf2SHA256TestVectors = []struct {
	name       string
	password   string // Password (ASCII)
	salt       string // Salt (hex or ASCII)
	saltIsHex  bool
	iterations int
	keyLen     int
	expected   string // Expected derived key (hex)
}{
	// Test vector from draft-josefsson-scrypt-kdf-00 (PBKDF2-HMAC-SHA256)
	{
		name:       "scrypt_kdf_00_TC1",
		password:   "passwd",
		salt:       "salt",
		saltIsHex:  false,
		iterations: 1,
		keyLen:     64,
		expected:   "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
	},
	// Test vector from draft-josefsson-scrypt-kdf-00 (PBKDF2-HMAC-SHA256)
	{
		name:       "scrypt_kdf_00_TC2",
		password:   "Password",
		salt:       "NaCl",
		saltIsHex:  false,
		iterations: 80000,
		keyLen:     64,
		expected:   "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
	},
	// Additional test: empty password
	{
		name:       "empty_password",
		password:   "",
		salt:       "salt",
		saltIsHex:  false,
		iterations: 1000,
		keyLen:     32,
		expected:   "94fb56af3ea22e5d3ed1b054085b136ca301b75d8b406c802c489479f27387c6",
	},
	// Matter-specific test: typical PASE parameters
	{
		name:       "matter_pase_typical",
		password:   "20202021", // Common test passcode as string
		salt:       "53504b453250204b65792053616c74", // "SPAKE2P Key Salt" in hex
		saltIsHex:  true,
		iterations: 1000,
		keyLen:     80, // w0s || w1s = 40 + 40 bytes
		expected:   "20cc08a176cab591e0b7879fe21eb87e752dea88bbf00e10faa7a0f0092ea45ef901b63a73ef1e51b31dbef037842d984484f3c55452c2a290061ae293ed06011babe3f81c251e655a8f42d634fdf3d0",
	},
}

func TestPBKDF2SHA256(t *testing.T) {
	for _, tc := range pbkdf2SHA256TestVectors {
		t.Run(tc.name, func(t *testing.T) {
			password := []byte(tc.password)

			var salt []byte
			var err error
			if tc.saltIsHex {
				salt, err = hex.DecodeString(tc.salt)
				if err != nil {
					t.Fatalf("failed to decode salt hex: %v", err)
				}
			} else {
				salt = []byte(tc.salt)
			}

			expected, err := hex.DecodeString(tc.expected)
			if err != nil {
				t.Fatalf("failed to decode expected: %v", err)
			}

			result := PBKDF2SHA256(password, salt, tc.iterations, tc.keyLen)

			if !bytes.Equal(result, expected) {
				t.Errorf("derived key mismatch\ngot:  %x\nwant: %x", result, expected)
			}
		})
	}
}

func TestPBKDF2SHA256Constants(t *testing.T) {
	// Verify constants match Matter spec
	if PBKDF2IterationsMin != 1000 {
		t.Errorf("PBKDF2IterationsMin = %d, want 1000", PBKDF2IterationsMin)
	}
	if PBKDF2IterationsMax != 100000 {
		t.Errorf("PBKDF2IterationsMax = %d, want 100000", PBKDF2IterationsMax)
	}
}

func TestHKDFSHA256_MultipleKeys(t *testing.T) {
	// Test deriving multiple keys from the same input (as described in spec section 3.8)
	ikm := []byte("input key material for testing")
	salt := []byte("salt value")
	info := []byte("application info")

	// Derive 48 bytes (3 x 16-byte keys)
	keys, err := HKDFSHA256(ikm, salt, info, 48)
	if err != nil {
		t.Fatalf("HKDFSHA256 failed: %v", err)
	}

	if len(keys) != 48 {
		t.Errorf("expected 48 bytes, got %d", len(keys))
	}

	// Split into three keys
	key1 := keys[0:16]
	key2 := keys[16:32]
	key3 := keys[32:48]

	// Verify keys are different from each other
	if bytes.Equal(key1, key2) || bytes.Equal(key2, key3) || bytes.Equal(key1, key3) {
		t.Error("derived keys should be different")
	}
}

func BenchmarkHKDFSHA256(b *testing.B) {
	ikm := make([]byte, 32)
	salt := make([]byte, 32)
	info := make([]byte, 32)
	for i := range ikm {
		ikm[i] = byte(i)
		salt[i] = byte(i + 32)
		info[i] = byte(i + 64)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = HKDFSHA256(ikm, salt, info, 32)
	}
}

func BenchmarkPBKDF2SHA256_1000iter(b *testing.B) {
	password := []byte("password")
	salt := []byte("salt1234salt1234")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PBKDF2SHA256(password, salt, 1000, 32)
	}
}
