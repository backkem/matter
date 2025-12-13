package crypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// P-256 constants from Matter Specification Section 3.5.1.
const (
	// P256GroupSizeBits is the group size in bits (CRYPTO_GROUP_SIZE_BITS).
	P256GroupSizeBits = 256

	// P256GroupSizeBytes is the group size in bytes (CRYPTO_GROUP_SIZE_BYTES).
	P256GroupSizeBytes = 32

	// P256PublicKeySizeBytes is the uncompressed public key size (CRYPTO_PUBLIC_KEY_SIZE_BYTES).
	// Format: 0x04 || X (32 bytes) || Y (32 bytes) = 65 bytes
	P256PublicKeySizeBytes = 65

	// P256CompressedPublicKeySizeBytes is the compressed public key size.
	// Format: 0x02/0x03 || X (32 bytes) = 33 bytes
	P256CompressedPublicKeySizeBytes = 33

	// P256SignatureSizeBytes is the signature size (r || s).
	P256SignatureSizeBytes = 64
)

// P256KeyPair represents a P-256 key pair.
// This implements the KeyPair type from Matter Specification Section 3.5.1.
type P256KeyPair struct {
	ecdhPrivate  *ecdh.PrivateKey
	ecdsaPrivate *ecdsa.PrivateKey
}

// P256PublicKey returns the public key in uncompressed format (65 bytes).
// Format: 0x04 || X (32 bytes) || Y (32 bytes)
func (kp *P256KeyPair) P256PublicKey() []byte {
	return kp.ecdhPrivate.PublicKey().Bytes()
}

// P256PublicKeyCompressed returns the public key in compressed format (33 bytes).
// Format: 0x02 (even Y) or 0x03 (odd Y) || X (32 bytes)
func (kp *P256KeyPair) P256PublicKeyCompressed() []byte {
	pub := kp.ecdsaPrivate.PublicKey
	return elliptic.MarshalCompressed(elliptic.P256(), pub.X, pub.Y)
}

// P256PrivateKey returns the private key as a 32-byte scalar.
func (kp *P256KeyPair) P256PrivateKey() []byte {
	return kp.ecdhPrivate.Bytes()
}

// P256GenerateKeyPair generates a new P-256 key pair.
// This implements Crypto_GenerateKeyPair() from Matter Specification Section 3.5.2.
func P256GenerateKeyPair() (*P256KeyPair, error) {
	// Generate using crypto/ecdh (preferred for ECDH operations)
	ecdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDH key: %w", err)
	}

	// Also create an ECDSA key for signing operations
	// We need to convert from ecdh to ecdsa
	ecdsaPriv, err := ecdhToECDSA(ecdhPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to ECDSA key: %w", err)
	}

	return &P256KeyPair{
		ecdhPrivate:  ecdhPriv,
		ecdsaPrivate: ecdsaPriv,
	}, nil
}

// P256KeyPairFromPrivateKey creates a key pair from an existing private key scalar.
func P256KeyPairFromPrivateKey(privateKey []byte) (*P256KeyPair, error) {
	if len(privateKey) != P256GroupSizeBytes {
		return nil, fmt.Errorf("private key must be %d bytes, got %d", P256GroupSizeBytes, len(privateKey))
	}

	ecdhPriv, err := ecdh.P256().NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	ecdsaPriv, err := ecdhToECDSA(ecdhPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to ECDSA key: %w", err)
	}

	return &P256KeyPair{
		ecdhPrivate:  ecdhPriv,
		ecdsaPrivate: ecdsaPriv,
	}, nil
}

// ecdhToECDSA converts an ecdh.PrivateKey to an ecdsa.PrivateKey.
func ecdhToECDSA(ecdhKey *ecdh.PrivateKey) (*ecdsa.PrivateKey, error) {
	// Get the raw private key bytes
	privBytes := ecdhKey.Bytes()

	// Create ECDSA private key
	d := new(big.Int).SetBytes(privBytes)

	// Get public key coordinates from the ecdh public key
	pubBytes := ecdhKey.PublicKey().Bytes()
	if len(pubBytes) != P256PublicKeySizeBytes || pubBytes[0] != 0x04 {
		return nil, errors.New("unexpected public key format")
	}

	x := new(big.Int).SetBytes(pubBytes[1:33])
	y := new(big.Int).SetBytes(pubBytes[33:65])

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
		D: d,
	}, nil
}

// P256Sign signs a message using ECDSA with SHA-256.
// This implements Crypto_Sign() from Matter Specification Section 3.5.3.
//
// The message is hashed internally using SHA-256 before signing.
// Returns a 64-byte signature (r || s), each component zero-padded to 32 bytes.
func P256Sign(keyPair *P256KeyPair, message []byte) ([]byte, error) {
	// Hash the message with SHA-256 (as per spec: ECDSASign uses Crypto_Hash)
	hash := SHA256(message)

	// Sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, keyPair.ecdsaPrivate, hash[:])
	if err != nil {
		return nil, fmt.Errorf("ECDSA sign failed: %w", err)
	}

	// Convert to fixed-size format (r || s, each 32 bytes)
	sig := make([]byte, P256SignatureSizeBytes)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Zero-pad and copy r (right-aligned in first 32 bytes)
	copy(sig[P256GroupSizeBytes-len(rBytes):P256GroupSizeBytes], rBytes)
	// Zero-pad and copy s (right-aligned in second 32 bytes)
	copy(sig[P256SignatureSizeBytes-len(sBytes):], sBytes)

	return sig, nil
}

// P256Verify verifies an ECDSA signature on a message.
// This implements Crypto_Verify() from Matter Specification Section 3.5.3.
//
// Parameters:
//   - publicKey: 65-byte uncompressed public key (0x04 || X || Y)
//   - message: The original message that was signed
//   - signature: 64-byte signature (r || s)
//
// Returns true if the signature is valid, false otherwise.
func P256Verify(publicKey, message, signature []byte) (bool, error) {
	// Parse the public key
	if len(publicKey) != P256PublicKeySizeBytes {
		return false, fmt.Errorf("public key must be %d bytes, got %d", P256PublicKeySizeBytes, len(publicKey))
	}
	if publicKey[0] != 0x04 {
		return false, errors.New("public key must be in uncompressed format (starting with 0x04)")
	}

	x := new(big.Int).SetBytes(publicKey[1:33])
	y := new(big.Int).SetBytes(publicKey[33:65])

	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// Verify the point is on the curve
	if !pub.Curve.IsOnCurve(x, y) {
		return false, errors.New("public key point is not on the P-256 curve")
	}

	// Parse the signature
	if len(signature) != P256SignatureSizeBytes {
		return false, fmt.Errorf("signature must be %d bytes, got %d", P256SignatureSizeBytes, len(signature))
	}

	r := new(big.Int).SetBytes(signature[:P256GroupSizeBytes])
	s := new(big.Int).SetBytes(signature[P256GroupSizeBytes:])

	// Hash the message
	hash := SHA256(message)

	// Verify
	return ecdsa.Verify(pub, hash[:], r, s), nil
}

// P256ECDH computes the ECDH shared secret.
// This implements Crypto_ECDH() from Matter Specification Section 3.5.4.
//
// Parameters:
//   - keyPair: Our private key
//   - peerPublicKey: Peer's 65-byte uncompressed public key (0x04 || X || Y)
//
// Returns the 32-byte shared secret (x-coordinate of the shared point).
func P256ECDH(keyPair *P256KeyPair, peerPublicKey []byte) ([]byte, error) {
	// Parse peer's public key
	if len(peerPublicKey) != P256PublicKeySizeBytes {
		return nil, fmt.Errorf("peer public key must be %d bytes, got %d", P256PublicKeySizeBytes, len(peerPublicKey))
	}

	peerPub, err := ecdh.P256().NewPublicKey(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid peer public key: %w", err)
	}

	// Compute shared secret
	secret, err := keyPair.ecdhPrivate.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH computation failed: %w", err)
	}

	return secret, nil
}

// P256ECDHFromPrivateKey computes ECDH using raw private key bytes.
// This is a convenience function when you have the private key as bytes.
func P256ECDHFromPrivateKey(privateKey, peerPublicKey []byte) ([]byte, error) {
	kp, err := P256KeyPairFromPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return P256ECDH(kp, peerPublicKey)
}

// P256PublicKeyFromCompressed decompresses a compressed public key.
// Input: 33-byte compressed key (0x02/0x03 || X)
// Output: 65-byte uncompressed key (0x04 || X || Y)
func P256PublicKeyFromCompressed(compressed []byte) ([]byte, error) {
	if len(compressed) != P256CompressedPublicKeySizeBytes {
		return nil, fmt.Errorf("compressed key must be %d bytes, got %d", P256CompressedPublicKeySizeBytes, len(compressed))
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil {
		return nil, errors.New("failed to decompress public key")
	}

	result := make([]byte, P256PublicKeySizeBytes)
	result[0] = 0x04
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	copy(result[1+P256GroupSizeBytes-len(xBytes):1+P256GroupSizeBytes], xBytes)
	copy(result[1+P256GroupSizeBytes+P256GroupSizeBytes-len(yBytes):], yBytes)

	return result, nil
}

// P256ValidatePublicKey validates that a public key is valid and on the curve.
func P256ValidatePublicKey(publicKey []byte) error {
	if len(publicKey) != P256PublicKeySizeBytes {
		return fmt.Errorf("public key must be %d bytes, got %d", P256PublicKeySizeBytes, len(publicKey))
	}
	if publicKey[0] != 0x04 {
		return errors.New("public key must be in uncompressed format (starting with 0x04)")
	}

	x := new(big.Int).SetBytes(publicKey[1:33])
	y := new(big.Int).SetBytes(publicKey[33:65])

	if !elliptic.P256().IsOnCurve(x, y) {
		return errors.New("public key point is not on the P-256 curve")
	}

	return nil
}
