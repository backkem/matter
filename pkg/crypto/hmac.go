package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// HMACSHA256 computes the HMAC-SHA256 of a message using the given key.
// This implements Crypto_HMAC() from Matter Specification Section 3.4.
//
// Returns a 32-byte (256-bit) MAC.
func HMACSHA256(key, message []byte) [SHA256LenBytes]byte {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	var result [SHA256LenBytes]byte
	copy(result[:], h.Sum(nil))
	return result
}

// HMACSHA256Slice computes the HMAC-SHA256 and returns it as a slice.
// This is a convenience function for cases where a slice is preferred.
func HMACSHA256Slice(key, message []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil)
}

// NewHMACSHA256 returns a new hash.Hash for computing HMAC-SHA256 incrementally.
// This is useful for computing MACs over streaming data.
//
// Usage:
//
//	h := crypto.NewHMACSHA256(key)
//	h.Write(data1)
//	h.Write(data2)
//	mac := h.Sum(nil)
func NewHMACSHA256(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

// HMACEqual compares two MACs for equality in constant time.
// This should be used instead of bytes.Equal to prevent timing attacks.
func HMACEqual(mac1, mac2 []byte) bool {
	return hmac.Equal(mac1, mac2)
}
