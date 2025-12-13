package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// PBKDF2 iteration limits from Matter Specification Section 3.9.
const (
	// PBKDF2IterationsMin is the minimum allowed iterations (CRYPTO_PBKDF_ITERATIONS_MIN).
	PBKDF2IterationsMin = 1000

	// PBKDF2IterationsMax is the maximum allowed iterations (CRYPTO_PBKDF_ITERATIONS_MAX).
	PBKDF2IterationsMax = 100000
)

// HKDFSHA256 derives key material using HKDF-SHA256 (RFC 5869).
// This implements Crypto_KDF() from Matter Specification Section 3.8.
//
// Parameters:
//   - inputKey: Input keying material (IKM)
//   - salt: Optional salt value (can be nil or empty)
//   - info: Optional context/application-specific info (can be nil or empty)
//   - length: Number of bytes to derive
//
// Returns the derived key material of the specified length.
func HKDFSHA256(inputKey, salt, info []byte, length int) ([]byte, error) {
	// HKDF = HKDF-Expand(PRK := HKDF-Extract(salt, IKM), info, L)
	reader := hkdf.New(sha256.New, inputKey, salt, info)
	result := make([]byte, length)
	if _, err := io.ReadFull(reader, result); err != nil {
		return nil, err
	}
	return result, nil
}

// HKDFExtractSHA256 performs only the HKDF-Extract operation.
// This extracts a pseudorandom key (PRK) from the input keying material.
//
// Parameters:
//   - inputKey: Input keying material (IKM)
//   - salt: Optional salt value (can be nil, defaults to zero-filled HashLen bytes)
//
// Returns a 32-byte pseudorandom key.
func HKDFExtractSHA256(inputKey, salt []byte) []byte {
	return hkdf.Extract(sha256.New, inputKey, salt)
}

// HKDFExpandSHA256 performs only the HKDF-Expand operation.
// This expands a pseudorandom key into output keying material.
//
// Parameters:
//   - prk: Pseudorandom key (from HKDFExtract or other source)
//   - info: Optional context/application-specific info
//   - length: Number of bytes to derive
//
// Returns the derived key material.
func HKDFExpandSHA256(prk, info []byte, length int) ([]byte, error) {
	reader := hkdf.Expand(sha256.New, prk, info)
	result := make([]byte, length)
	if _, err := io.ReadFull(reader, result); err != nil {
		return nil, err
	}
	return result, nil
}

// PBKDF2SHA256 derives a key from a password using PBKDF2-HMAC-SHA256 (NIST 800-132).
// This implements Crypto_PBKDF() from Matter Specification Section 3.9.
//
// Parameters:
//   - password: The password/passcode to derive from
//   - salt: Salt value (Matter requires 16-32 bytes)
//   - iterations: Number of iterations (Matter: 1000-100000)
//   - keyLen: Number of bytes to derive
//
// Returns the derived key material.
func PBKDF2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
}
