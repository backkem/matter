package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Test vectors from RFC 4231: Identifiers and Test Vectors for HMAC-SHA-224,
// HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512.
// https://datatracker.ietf.org/doc/html/rfc4231
//
// We only use the HMAC-SHA-256 expected values.
var hmacSHA256TestVectors = []struct {
	name     string
	key      string // hex-encoded
	data     string // hex-encoded
	expected string // hex-encoded HMAC-SHA-256
}{
	// RFC 4231 Test Case 1
	{
		name:     "RFC4231_TC1",
		key:      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", // 20 bytes
		data:     "4869205468657265",                         // "Hi There"
		expected: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
	},
	// RFC 4231 Test Case 2 - Test with a key shorter than the length of the HMAC output
	{
		name:     "RFC4231_TC2",
		key:      "4a656665",                                                                                                                                                                                                                                                 // "Jefe"
		data:     "7768617420646f2079612077616e7420666f72206e6f7468696e673f",                                                                                                                                                                                                 // "what do ya want for nothing?"
		expected: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
	},
	// RFC 4231 Test Case 3 - Test with a combined length of key and data that is larger than 64 bytes
	{
		name:     "RFC4231_TC3",
		key:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",                                                                 // 20 bytes of 0xaa
		data:     "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", // 50 bytes of 0xdd
		expected: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
	},
	// RFC 4231 Test Case 4
	{
		name:     "RFC4231_TC4",
		key:      "0102030405060708090a0b0c0d0e0f10111213141516171819",                                                       // 25 bytes
		data:     "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", // 50 bytes of 0xcd
		expected: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
	},
	// RFC 4231 Test Case 5 - Test with a truncation of output to 128 bits (we still compute full 256 bits)
	{
		name:     "RFC4231_TC5",
		key:      "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", // 20 bytes
		data:     "546573742057697468205472756e636174696f6e", // "Test With Truncation"
		expected: "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5",
	},
	// RFC 4231 Test Case 6 - Test with a key larger than 128 bytes (= block-size of SHA-256)
	{
		name: "RFC4231_TC6",
		key: strings.Repeat("aa", 131), // 131 bytes of 0xaa
		data:     "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", // "Test Using Larger Than Block-Size Key - Hash Key First"
		expected: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
	},
	// RFC 4231 Test Case 7 - Test with a key and data that is larger than 128 bytes
	{
		name: "RFC4231_TC7",
		key: strings.Repeat("aa", 131), // 131 bytes of 0xaa
		data:     "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", // "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
		expected: "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
	},
}

func TestHMACSHA256(t *testing.T) {
	for _, tc := range hmacSHA256TestVectors {
		t.Run(tc.name, func(t *testing.T) {
			key, err := hex.DecodeString(tc.key)
			if err != nil {
				t.Fatalf("failed to decode key hex: %v", err)
			}

			data, err := hex.DecodeString(tc.data)
			if err != nil {
				t.Fatalf("failed to decode data hex: %v", err)
			}

			expected, err := hex.DecodeString(tc.expected)
			if err != nil {
				t.Fatalf("failed to decode expected hex: %v", err)
			}

			result := HMACSHA256(key, data)

			if !bytes.Equal(result[:], expected) {
				t.Errorf("HMAC mismatch\ngot:  %x\nwant: %x", result[:], expected)
			}
		})
	}
}

func TestHMACSHA256Slice(t *testing.T) {
	for _, tc := range hmacSHA256TestVectors {
		t.Run(tc.name, func(t *testing.T) {
			key, err := hex.DecodeString(tc.key)
			if err != nil {
				t.Fatalf("failed to decode key hex: %v", err)
			}

			data, err := hex.DecodeString(tc.data)
			if err != nil {
				t.Fatalf("failed to decode data hex: %v", err)
			}

			expected, err := hex.DecodeString(tc.expected)
			if err != nil {
				t.Fatalf("failed to decode expected hex: %v", err)
			}

			result := HMACSHA256Slice(key, data)

			if !bytes.Equal(result, expected) {
				t.Errorf("HMAC mismatch\ngot:  %x\nwant: %x", result, expected)
			}
		})
	}
}

func TestNewHMACSHA256_Incremental(t *testing.T) {
	key := []byte("test-key-1234567890")
	data := []byte("This is a test message for incremental HMAC computation")

	// One-shot
	expected := HMACSHA256(key, data)

	// Incremental - split at various points
	h := NewHMACSHA256(key)
	h.Write(data[:10])
	h.Write(data[10:30])
	h.Write(data[30:])
	result := h.Sum(nil)

	if !bytes.Equal(result, expected[:]) {
		t.Errorf("incremental HMAC mismatch\ngot:  %x\nwant: %x", result, expected[:])
	}
}

func TestHMACEqual(t *testing.T) {
	mac1 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	mac2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	mac3 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17} // Different last byte

	if !HMACEqual(mac1, mac2) {
		t.Error("HMACEqual returned false for equal MACs")
	}

	if HMACEqual(mac1, mac3) {
		t.Error("HMACEqual returned true for different MACs")
	}

	if HMACEqual(mac1, mac1[:15]) {
		t.Error("HMACEqual returned true for different length MACs")
	}
}

func TestHMACSHA256_EmptyInputs(t *testing.T) {
	// Empty message with non-empty key
	t.Run("empty_message", func(t *testing.T) {
		key := []byte("key")
		result := HMACSHA256(key, nil)
		// Just verify it doesn't panic and produces 32 bytes
		if len(result) != SHA256LenBytes {
			t.Errorf("expected %d bytes, got %d", SHA256LenBytes, len(result))
		}
	})

	// Empty key with non-empty message
	t.Run("empty_key", func(t *testing.T) {
		data := []byte("data")
		result := HMACSHA256(nil, data)
		// Just verify it doesn't panic and produces 32 bytes
		if len(result) != SHA256LenBytes {
			t.Errorf("expected %d bytes, got %d", SHA256LenBytes, len(result))
		}
	})

	// Both empty
	t.Run("both_empty", func(t *testing.T) {
		result := HMACSHA256(nil, nil)
		if len(result) != SHA256LenBytes {
			t.Errorf("expected %d bytes, got %d", SHA256LenBytes, len(result))
		}
	})
}

func BenchmarkHMACSHA256(b *testing.B) {
	key := make([]byte, 32)
	message := make([]byte, 1024)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range message {
		message[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HMACSHA256(key, message)
	}
}
