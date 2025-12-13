package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// ECDH test vectors from RFC 5903 Section 8.1 "256-Bit Random ECP Group"
// https://datatracker.ietf.org/doc/html/rfc5903#section-8.1
var ecdhP256TestVectors = []struct {
	name         string
	privateKeyA  string // Party A's private key (hex)
	publicKeyA   string // Party A's public key, uncompressed (hex)
	privateKeyB  string // Party B's private key (hex)
	publicKeyB   string // Party B's public key, uncompressed (hex)
	sharedSecret string // Expected shared secret (hex) - x-coordinate of shared point
}{
	// RFC 5903 Section 8.1 - 256-Bit Random ECP Group (P-256)
	// Initiator = Party A, Responder = Party B
	{
		name: "RFC5903_P256",
		// i (initiator private key)
		privateKeyA: "c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433",
		// g^i = (gix, giy) - initiator public key
		publicKeyA: "04" +
			"dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180" + // gix
			"5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3", // giy
		// r (responder private key)
		privateKeyB: "c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53",
		// g^r = (grx, gry) - responder public key
		publicKeyB: "04" +
			"d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63" + // grx
			"56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab", // gry
		// g^ir x-coordinate (shared secret)
		sharedSecret: "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de",
	},
}

// ECDSA test vectors from RFC 6979 Section A.2.5 "ECDSA, 256 Bits (Prime Field)"
// https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.2.5
// Note: RFC 6979 defines deterministic ECDSA. Go's ecdsa.Sign uses random k,
// so we can only use these vectors for verification testing, not signature generation.
var ecdsaP256TestVectors = []struct {
	name       string
	privateKey string // Private key (hex)
	publicKey  string // Public key, uncompressed (hex)
	message    string // Message (ASCII, will be converted to bytes)
	signature  string // Valid signature (hex) - r || s, 64 bytes
}{
	// RFC 6979 A.2.5 - With SHA-256, message = "sample"
	{
		name:       "RFC6979_P256_SHA256_sample",
		privateKey: "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
		publicKey: "04" +
			"60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" + // Ux
			"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299", // Uy
		message: "sample",
		signature: "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716" + // r
			"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8", // s
	},
	// RFC 6979 A.2.5 - With SHA-256, message = "test"
	{
		name:       "RFC6979_P256_SHA256_test",
		privateKey: "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
		publicKey: "04" +
			"60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" + // Ux
			"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299", // Uy
		message: "test",
		signature: "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367" + // r
			"019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083", // s
	},
}

func TestP256GenerateKeyPair(t *testing.T) {
	kp, err := P256GenerateKeyPair()
	if err != nil {
		t.Fatalf("P256GenerateKeyPair failed: %v", err)
	}

	// Verify private key is 32 bytes
	priv := kp.P256PrivateKey()
	if len(priv) != P256GroupSizeBytes {
		t.Errorf("private key length = %d, want %d", len(priv), P256GroupSizeBytes)
	}

	// Verify public key is 65 bytes and starts with 0x04
	pub := kp.P256PublicKey()
	if len(pub) != P256PublicKeySizeBytes {
		t.Errorf("public key length = %d, want %d", len(pub), P256PublicKeySizeBytes)
	}
	if pub[0] != 0x04 {
		t.Errorf("public key prefix = 0x%02x, want 0x04", pub[0])
	}

	// Verify compressed public key is 33 bytes
	compressed := kp.P256PublicKeyCompressed()
	if len(compressed) != P256CompressedPublicKeySizeBytes {
		t.Errorf("compressed public key length = %d, want %d", len(compressed), P256CompressedPublicKeySizeBytes)
	}
	if compressed[0] != 0x02 && compressed[0] != 0x03 {
		t.Errorf("compressed public key prefix = 0x%02x, want 0x02 or 0x03", compressed[0])
	}

	// Verify public key is valid
	if err := P256ValidatePublicKey(pub); err != nil {
		t.Errorf("generated public key validation failed: %v", err)
	}
}

func TestP256KeyPairFromPrivateKey(t *testing.T) {
	// Generate a key pair
	original, err := P256GenerateKeyPair()
	if err != nil {
		t.Fatalf("P256GenerateKeyPair failed: %v", err)
	}

	// Recreate from private key
	restored, err := P256KeyPairFromPrivateKey(original.P256PrivateKey())
	if err != nil {
		t.Fatalf("P256KeyPairFromPrivateKey failed: %v", err)
	}

	// Verify public keys match
	if !bytes.Equal(original.P256PublicKey(), restored.P256PublicKey()) {
		t.Error("restored public key does not match original")
	}
}

func TestP256ECDH(t *testing.T) {
	for _, tc := range ecdhP256TestVectors {
		t.Run(tc.name, func(t *testing.T) {
			privA, err := hex.DecodeString(tc.privateKeyA)
			if err != nil {
				t.Fatalf("failed to decode privateKeyA: %v", err)
			}

			pubB, err := hex.DecodeString(tc.publicKeyB)
			if err != nil {
				t.Fatalf("failed to decode publicKeyB: %v", err)
			}

			expected, err := hex.DecodeString(tc.sharedSecret)
			if err != nil {
				t.Fatalf("failed to decode expected shared secret: %v", err)
			}

			kpA, err := P256KeyPairFromPrivateKey(privA)
			if err != nil {
				t.Fatalf("failed to create key pair A: %v", err)
			}

			secret, err := P256ECDH(kpA, pubB)
			if err != nil {
				t.Fatalf("P256ECDH failed: %v", err)
			}

			if !bytes.Equal(secret, expected) {
				t.Errorf("shared secret mismatch\ngot:  %x\nwant: %x", secret, expected)
			}
		})
	}
}

func TestP256ECDH_Symmetric(t *testing.T) {
	// Generate two key pairs
	kpA, err := P256GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair A: %v", err)
	}

	kpB, err := P256GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair B: %v", err)
	}

	// Compute shared secret both ways
	secretAB, err := P256ECDH(kpA, kpB.P256PublicKey())
	if err != nil {
		t.Fatalf("ECDH(A, pubB) failed: %v", err)
	}

	secretBA, err := P256ECDH(kpB, kpA.P256PublicKey())
	if err != nil {
		t.Fatalf("ECDH(B, pubA) failed: %v", err)
	}

	// Verify they match
	if !bytes.Equal(secretAB, secretBA) {
		t.Errorf("ECDH is not symmetric\nA->B: %x\nB->A: %x", secretAB, secretBA)
	}

	// Verify length
	if len(secretAB) != P256GroupSizeBytes {
		t.Errorf("shared secret length = %d, want %d", len(secretAB), P256GroupSizeBytes)
	}
}

func TestP256Sign(t *testing.T) {
	// Generate a key pair
	kp, err := P256GenerateKeyPair()
	if err != nil {
		t.Fatalf("P256GenerateKeyPair failed: %v", err)
	}

	message := []byte("This is a test message for ECDSA signing")

	// Sign the message
	sig, err := P256Sign(kp, message)
	if err != nil {
		t.Fatalf("P256Sign failed: %v", err)
	}

	// Verify signature length
	if len(sig) != P256SignatureSizeBytes {
		t.Errorf("signature length = %d, want %d", len(sig), P256SignatureSizeBytes)
	}

	// Verify the signature
	valid, err := P256Verify(kp.P256PublicKey(), message, sig)
	if err != nil {
		t.Fatalf("P256Verify failed: %v", err)
	}
	if !valid {
		t.Error("signature verification failed for valid signature")
	}
}

func TestP256Verify(t *testing.T) {
	for _, tc := range ecdsaP256TestVectors {
		t.Run(tc.name, func(t *testing.T) {
			pubKey, err := hex.DecodeString(tc.publicKey)
			if err != nil {
				t.Fatalf("failed to decode public key: %v", err)
			}

			// Message is ASCII string per RFC 6979
			message := []byte(tc.message)

			signature, err := hex.DecodeString(tc.signature)
			if err != nil {
				t.Fatalf("failed to decode signature: %v", err)
			}

			valid, err := P256Verify(pubKey, message, signature)
			if err != nil {
				t.Fatalf("P256Verify failed: %v", err)
			}
			if !valid {
				t.Error("expected signature to be valid")
			}
		})
	}
}

func TestP256Verify_InvalidSignature(t *testing.T) {
	kp, err := P256GenerateKeyPair()
	if err != nil {
		t.Fatalf("P256GenerateKeyPair failed: %v", err)
	}

	message := []byte("original message")
	sig, err := P256Sign(kp, message)
	if err != nil {
		t.Fatalf("P256Sign failed: %v", err)
	}

	// Modify the message
	tamperedMessage := []byte("tampered message")
	valid, err := P256Verify(kp.P256PublicKey(), tamperedMessage, sig)
	if err != nil {
		t.Fatalf("P256Verify failed: %v", err)
	}
	if valid {
		t.Error("signature should be invalid for tampered message")
	}

	// Modify the signature
	tamperedSig := make([]byte, len(sig))
	copy(tamperedSig, sig)
	tamperedSig[0] ^= 0x01 // Flip a bit
	valid, err = P256Verify(kp.P256PublicKey(), message, tamperedSig)
	if err != nil {
		t.Fatalf("P256Verify failed: %v", err)
	}
	if valid {
		t.Error("signature should be invalid for tampered signature")
	}
}

func TestP256PublicKeyFromCompressed(t *testing.T) {
	// Generate a key pair
	kp, err := P256GenerateKeyPair()
	if err != nil {
		t.Fatalf("P256GenerateKeyPair failed: %v", err)
	}

	original := kp.P256PublicKey()
	compressed := kp.P256PublicKeyCompressed()

	// Decompress
	decompressed, err := P256PublicKeyFromCompressed(compressed)
	if err != nil {
		t.Fatalf("P256PublicKeyFromCompressed failed: %v", err)
	}

	// Verify it matches the original
	if !bytes.Equal(original, decompressed) {
		t.Errorf("decompressed key mismatch\ngot:  %x\nwant: %x", decompressed, original)
	}
}

func TestP256ValidatePublicKey(t *testing.T) {
	// Valid key
	kp, err := P256GenerateKeyPair()
	if err != nil {
		t.Fatalf("P256GenerateKeyPair failed: %v", err)
	}
	if err := P256ValidatePublicKey(kp.P256PublicKey()); err != nil {
		t.Errorf("valid public key rejected: %v", err)
	}

	// Invalid: wrong length
	if err := P256ValidatePublicKey(make([]byte, 32)); err == nil {
		t.Error("expected error for wrong length key")
	}

	// Invalid: wrong prefix
	badPrefix := make([]byte, P256PublicKeySizeBytes)
	badPrefix[0] = 0x05 // Should be 0x04
	if err := P256ValidatePublicKey(badPrefix); err == nil {
		t.Error("expected error for wrong prefix")
	}

	// Invalid: point not on curve
	notOnCurve := make([]byte, P256PublicKeySizeBytes)
	notOnCurve[0] = 0x04
	notOnCurve[1] = 0x01 // X = 1
	notOnCurve[33] = 0x01 // Y = 1 (not a valid point)
	if err := P256ValidatePublicKey(notOnCurve); err == nil {
		t.Error("expected error for point not on curve")
	}
}

func TestP256Constants(t *testing.T) {
	if P256GroupSizeBits != 256 {
		t.Errorf("P256GroupSizeBits = %d, want 256", P256GroupSizeBits)
	}
	if P256GroupSizeBytes != 32 {
		t.Errorf("P256GroupSizeBytes = %d, want 32", P256GroupSizeBytes)
	}
	if P256PublicKeySizeBytes != 65 {
		t.Errorf("P256PublicKeySizeBytes = %d, want 65", P256PublicKeySizeBytes)
	}
	if P256CompressedPublicKeySizeBytes != 33 {
		t.Errorf("P256CompressedPublicKeySizeBytes = %d, want 33", P256CompressedPublicKeySizeBytes)
	}
	if P256SignatureSizeBytes != 64 {
		t.Errorf("P256SignatureSizeBytes = %d, want 64", P256SignatureSizeBytes)
	}
}

func BenchmarkP256GenerateKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = P256GenerateKeyPair()
	}
}

func BenchmarkP256Sign(b *testing.B) {
	kp, _ := P256GenerateKeyPair()
	message := []byte("benchmark message for signing")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = P256Sign(kp, message)
	}
}

func BenchmarkP256Verify(b *testing.B) {
	kp, _ := P256GenerateKeyPair()
	message := []byte("benchmark message for verification")
	sig, _ := P256Sign(kp, message)
	pub := kp.P256PublicKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = P256Verify(pub, message, sig)
	}
}

func BenchmarkP256ECDH(b *testing.B) {
	kpA, _ := P256GenerateKeyPair()
	kpB, _ := P256GenerateKeyPair()
	pubB := kpB.P256PublicKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = P256ECDH(kpA, pubB)
	}
}
