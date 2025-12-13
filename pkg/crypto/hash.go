// Package crypto provides cryptographic primitives for the Matter protocol.
// This implements the cryptographic functions defined in Matter Specification Chapter 3.
package crypto

import (
	"crypto/sha256"
	"hash"
)

// SHA-256 constants from Matter Specification Section 3.3.
const (
	// SHA256LenBits is the SHA-256 output length in bits (CRYPTO_HASH_LEN_BITS).
	SHA256LenBits = 256

	// SHA256LenBytes is the SHA-256 output length in bytes (CRYPTO_HASH_LEN_BYTES).
	SHA256LenBytes = 32
)

// SHA256 computes the SHA-256 cryptographic hash of a message.
// This implements Crypto_Hash() from Matter Specification Section 3.3.
//
// Returns a 32-byte (256-bit) hash digest.
func SHA256(message []byte) [SHA256LenBytes]byte {
	return sha256.Sum256(message)
}

// SHA256Slice computes the SHA-256 hash and returns it as a slice.
// This is a convenience function for cases where a slice is preferred.
func SHA256Slice(message []byte) []byte {
	h := sha256.Sum256(message)
	return h[:]
}

// NewSHA256 returns a new hash.Hash for computing SHA-256 digests incrementally.
// This is useful for hashing large data or streaming data.
//
// Usage:
//
//	h := crypto.NewSHA256()
//	h.Write(data1)
//	h.Write(data2)
//	digest := h.Sum(nil)
func NewSHA256() hash.Hash {
	return sha256.New()
}
