package fabric

import (
	"encoding/binary"
	"errors"

	"github.com/backkem/matter/pkg/crypto"
)

// compressedFabricInfo is the info string for compressed fabric ID derivation.
// Spec Section 4.3.2.2: "CompressedFabric" (16 bytes)
var compressedFabricInfo = []byte{
	0x43, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73,
	0x65, 0x64, 0x46, 0x61, 0x62, 0x72, 0x69, 0x63,
}

// Errors for compressed fabric ID computation.
var (
	// ErrInvalidRootPublicKey is returned when the root public key has invalid length.
	ErrInvalidRootPublicKey = errors.New("fabric: invalid root public key length")
	// ErrInvalidFabricID is returned when the fabric ID is invalid (zero).
	ErrInvalidFabricID = errors.New("fabric: invalid fabric ID")
)

// CompressedFabricID computes the 64-bit compressed fabric identifier.
//
// The compressed fabric ID is used in DNS-SD operational discovery to provide
// a shorter representation of the full fabric reference (root CA + fabric ID).
//
// Spec Section 4.3.2.2:
//
//	CompressedFabricIdentifier = Crypto_KDF(
//	    inputKey = TargetOperationalRootPublicKey (64 bytes, without 0x04 prefix),
//	    salt = TargetOperationalFabricID (8 bytes, big-endian),
//	    info = "CompressedFabric",
//	    len = 64 bits
//	)
//
// Parameters:
//   - rootPublicKey: The raw 64-byte public key (X || Y coordinates) WITHOUT the
//     0x04 uncompressed point prefix. If a 65-byte key with prefix is provided,
//     the prefix is automatically stripped.
//   - fabricID: The 64-bit fabric ID.
//
// Returns the 8-byte compressed fabric identifier.
func CompressedFabricID(rootPublicKey []byte, fabricID FabricID) ([CompressedFabricIDSize]byte, error) {
	var result [CompressedFabricIDSize]byte

	// Validate fabric ID
	if !fabricID.IsValid() {
		return result, ErrInvalidFabricID
	}

	// Handle root public key - strip 0x04 prefix if present
	var keyBytes []byte
	switch len(rootPublicKey) {
	case 64:
		// Already stripped, use as-is
		keyBytes = rootPublicKey
	case 65:
		// Has 0x04 prefix, strip it
		if rootPublicKey[0] != 0x04 {
			return result, ErrInvalidRootPublicKey
		}
		keyBytes = rootPublicKey[1:]
	default:
		return result, ErrInvalidRootPublicKey
	}

	// Convert fabric ID to big-endian bytes (salt)
	salt := make([]byte, 8)
	binary.BigEndian.PutUint64(salt, uint64(fabricID))

	// Derive compressed fabric ID using HKDF-SHA256
	// inputKey = rootPublicKey (64 bytes)
	// salt = fabricID (8 bytes, big-endian)
	// info = "CompressedFabric"
	// length = 8 bytes
	derived, err := crypto.HKDFSHA256(keyBytes, salt, compressedFabricInfo, CompressedFabricIDSize)
	if err != nil {
		return result, err
	}

	copy(result[:], derived)
	return result, nil
}

// CompressedFabricIDFromCert computes the compressed fabric ID from a 65-byte
// uncompressed public key (with 0x04 prefix) and fabric ID.
//
// This is a convenience function for use with public keys extracted from
// certificates, which include the 0x04 uncompressed point format prefix.
func CompressedFabricIDFromCert(rootPublicKey [RootPublicKeySize]byte, fabricID FabricID) ([CompressedFabricIDSize]byte, error) {
	return CompressedFabricID(rootPublicKey[:], fabricID)
}
