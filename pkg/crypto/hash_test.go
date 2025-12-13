package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors from NIST FIPS 180-4 and NIST CAVP (Cryptographic Algorithm Validation Program).
// These are the official SHA-256 test vectors.
var sha256TestVectors = []struct {
	name     string
	message  string // hex-encoded input
	expected string // hex-encoded expected hash
}{
	// NIST FIPS 180-4 Example B.1 - One Block Message (256 bits)
	{
		name:     "FIPS180-4_B1_abc",
		message:  "616263", // "abc"
		expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	},
	// NIST FIPS 180-4 Example B.2 - Two Block Message (448 bits)
	{
		name:     "FIPS180-4_B2_448bit",
		message:  "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071", // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
		expected: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
	},
	// NIST CAVP Short Message Test Vector - Empty string
	{
		name:     "CAVP_empty",
		message:  "",
		expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	},
	// NIST CAVP Short Message Test Vector - 8 bits
	{
		name:     "CAVP_8bit",
		message:  "d3",
		expected: "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1",
	},
	// NIST CAVP Short Message Test Vector - 16 bits
	{
		name:     "CAVP_16bit",
		message:  "11af",
		expected: "5ca7133fa735326081558ac312c620eeca9970d1e70a4b95533d956f072d1f98",
	},
	// NIST CAVP Short Message Test Vector - 24 bits
	{
		name:     "CAVP_24bit",
		message:  "b4190e",
		expected: "dff2e73091f6c05e528896c4c831b9448653dc2ff043528f6769437bc7b975c2",
	},
	// NIST CAVP Short Message Test Vector - 32 bits
	{
		name:     "CAVP_32bit",
		message:  "74ba2521",
		expected: "b16aa56be3880d18cd41e68384cf1ec8c17680c45a02b1575dc1518923ae8b0e",
	},
	// NIST CAVP Short Message Test Vector - 40 bits
	{
		name:     "CAVP_40bit",
		message:  "c299209682",
		expected: "f0887fe961c9cd3beab957e8222494abb969b1ce4c6557976df8b0f6d20e9166",
	},
	// NIST CAVP Short Message Test Vector - 48 bits
	{
		name:     "CAVP_48bit",
		message:  "e1dc724d5621",
		expected: "eca0a060b489636225b4fa64d267dabbe44273067ac679f20820bddc6b6a90ac",
	},
	// NIST CAVP Short Message Test Vector - 64 bits
	{
		name:     "CAVP_64bit",
		message:  "06e076f5a442d5",
		expected: "3fd877e27450e6bbd5d74bb82f9870c64c66e109418baa8e6bbcff355e287926",
	},
	// Additional test: 512 bits (one full block)
	{
		name:     "CAVP_512bit",
		message:  "5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509",
		expected: "42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa",
	},
}

func TestSHA256(t *testing.T) {
	for _, tc := range sha256TestVectors {
		t.Run(tc.name, func(t *testing.T) {
			message, err := hex.DecodeString(tc.message)
			if err != nil {
				t.Fatalf("failed to decode message hex: %v", err)
			}

			expected, err := hex.DecodeString(tc.expected)
			if err != nil {
				t.Fatalf("failed to decode expected hex: %v", err)
			}

			result := SHA256(message)

			if !bytes.Equal(result[:], expected) {
				t.Errorf("hash mismatch\ngot:  %x\nwant: %x", result[:], expected)
			}
		})
	}
}

func TestSHA256Slice(t *testing.T) {
	for _, tc := range sha256TestVectors {
		t.Run(tc.name, func(t *testing.T) {
			message, err := hex.DecodeString(tc.message)
			if err != nil {
				t.Fatalf("failed to decode message hex: %v", err)
			}

			expected, err := hex.DecodeString(tc.expected)
			if err != nil {
				t.Fatalf("failed to decode expected hex: %v", err)
			}

			result := SHA256Slice(message)

			if !bytes.Equal(result, expected) {
				t.Errorf("hash mismatch\ngot:  %x\nwant: %x", result, expected)
			}
		})
	}
}

func TestNewSHA256_Incremental(t *testing.T) {
	// Test that incremental hashing produces the same result as one-shot
	message := []byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")

	// One-shot
	expected := SHA256(message)

	// Incremental - split at various points
	h := NewSHA256()
	h.Write(message[:10])
	h.Write(message[10:30])
	h.Write(message[30:])
	result := h.Sum(nil)

	if !bytes.Equal(result, expected[:]) {
		t.Errorf("incremental hash mismatch\ngot:  %x\nwant: %x", result, expected[:])
	}
}

func TestNewSHA256_Reset(t *testing.T) {
	h := NewSHA256()
	h.Write([]byte("first message"))
	h.Reset()
	h.Write([]byte("abc"))
	result := h.Sum(nil)

	expected := SHA256([]byte("abc"))

	if !bytes.Equal(result, expected[:]) {
		t.Errorf("hash after reset mismatch\ngot:  %x\nwant: %x", result, expected[:])
	}
}

func TestSHA256Constants(t *testing.T) {
	// Verify constants match expected values from spec
	if SHA256LenBits != 256 {
		t.Errorf("SHA256LenBits = %d, want 256", SHA256LenBits)
	}
	if SHA256LenBytes != 32 {
		t.Errorf("SHA256LenBytes = %d, want 32", SHA256LenBytes)
	}
	if SHA256LenBits/8 != SHA256LenBytes {
		t.Errorf("SHA256LenBits/8 (%d) != SHA256LenBytes (%d)", SHA256LenBits/8, SHA256LenBytes)
	}
}

func BenchmarkSHA256(b *testing.B) {
	message := make([]byte, 1024)
	for i := range message {
		message[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SHA256(message)
	}
}
