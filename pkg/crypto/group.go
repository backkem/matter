// Group key derivation for Matter operational groups.
// This implements Matter Specification Section 4.17.2 "Operational Group Key Derivation".

package crypto

import (
	"encoding/binary"
	"errors"
)

// Group key derivation constants.
const (
	// CompressedFabricIDSize is the size of compressed fabric identifier (8 bytes).
	CompressedFabricIDSize = 8

	// GroupSessionIDSize is the size of the group session ID (2 bytes).
	GroupSessionIDSize = 2
)

// Group key derivation info strings from Section 4.17.2.1.
// "GroupKey v1.0" = 0x47 0x72 0x6f 0x75 0x70 0x4b 0x65 0x79 0x20 0x76 0x31 0x2e 0x30
var groupKeyInfo = []byte("GroupKey v1.0")

// Group key hash info string for session ID derivation.
// "GroupKeyHash" = 0x47 0x72 0x6f 0x75 0x70 0x4b 0x65 0x79 0x48 0x61 0x73 0x68
var groupKeyHashInfo = []byte("GroupKeyHash")

// Errors for group key operations.
var (
	ErrInvalidEpochKeySize            = errors.New("group: invalid epoch key size, must be 16 bytes")
	ErrInvalidCompressedFabricIDSize  = errors.New("group: invalid compressed fabric ID size, must be 8 bytes")
	ErrInvalidOperationalKeySize      = errors.New("group: invalid operational key size, must be 16 bytes")
)

// DeriveGroupOperationalKeyV1 derives an operational group key from an epoch key.
// This implements Section 4.17.2 "Operational Group Key Derivation" using the
// "GroupKey v1.0" info string. Future protocol versions may use different info strings.
//
// OperationalGroupKey = HKDF-SHA256(
//
//	InputKey = EpochKey,
//	Salt = CompressedFabricIdentifier,
//	Info = "GroupKey v1.0",
//	Length = CRYPTO_SYMMETRIC_KEY_LENGTH_BITS
//
// )
//
// Parameters:
//   - epochKey: The 16-byte epoch key from a group key set
//   - compressedFabricID: The 8-byte compressed fabric identifier
//
// Returns the 16-byte operational group key used for message encryption.
func DeriveGroupOperationalKeyV1(epochKey, compressedFabricID []byte) ([]byte, error) {
	if len(epochKey) != SymmetricKeySize {
		return nil, ErrInvalidEpochKeySize
	}
	if len(compressedFabricID) != CompressedFabricIDSize {
		return nil, ErrInvalidCompressedFabricIDSize
	}

	// HKDF with compressed fabric ID as salt and "GroupKey v1.0" as info
	return HKDFSHA256(epochKey, compressedFabricID, groupKeyInfo, SymmetricKeySize)
}

// DeriveGroupSessionIDV1 derives a group session ID from an operational group key.
// This is used to identify messages encrypted with a particular group key.
// Uses HKDF-SHA256 with "GroupKeyHash" info string.
//
// GKH = HKDF-SHA256(
//
//	InputKey = OperationalGroupKey,
//	Salt = [],
//	Info = "GroupKeyHash",
//	Length = 2
//
// )
// GroupSessionID = BigEndian.Get16(GKH[0:2])
//
// Parameters:
//   - operationalKey: The 16-byte operational group key
//
// Returns the 16-bit group session ID.
func DeriveGroupSessionIDV1(operationalKey []byte) (uint16, error) {
	if len(operationalKey) != SymmetricKeySize {
		return 0, ErrInvalidOperationalKeySize
	}

	// HKDF with empty salt and "GroupKeyHash" as info
	// We only need 2 bytes but derive them via HKDF
	hash, err := HKDFSHA256(operationalKey, nil, groupKeyHashInfo, GroupSessionIDSize)
	if err != nil {
		return 0, err
	}

	// Session ID is big-endian encoded
	return binary.BigEndian.Uint16(hash), nil
}

// GroupOperationalCredentials holds all derived credentials for a group.
type GroupOperationalCredentials struct {
	// EncryptionKey is the 16-byte operational group key for AES-CCM encryption.
	EncryptionKey []byte

	// PrivacyKey is the 16-byte privacy key for AES-CTR privacy encryption.
	PrivacyKey []byte

	// SessionID is the 16-bit group session ID.
	SessionID uint16
}

// DeriveGroupCredentialsV1 derives all group operational credentials from an epoch key.
// This is a convenience function that combines DeriveGroupOperationalKeyV1,
// DerivePrivacyKey, and DeriveGroupSessionIDV1.
//
// Parameters:
//   - epochKey: The 16-byte epoch key from a group key set
//   - compressedFabricID: The 8-byte compressed fabric identifier
//
// Returns a GroupOperationalCredentials struct with all derived keys and session ID.
func DeriveGroupCredentialsV1(epochKey, compressedFabricID []byte) (*GroupOperationalCredentials, error) {
	// Derive operational (encryption) key
	encryptionKey, err := DeriveGroupOperationalKeyV1(epochKey, compressedFabricID)
	if err != nil {
		return nil, err
	}

	// Derive privacy key from encryption key
	privacyKey, err := DerivePrivacyKey(encryptionKey)
	if err != nil {
		return nil, err
	}

	// Derive session ID from encryption key
	sessionID, err := DeriveGroupSessionIDV1(encryptionKey)
	if err != nil {
		return nil, err
	}

	return &GroupOperationalCredentials{
		EncryptionKey: encryptionKey,
		PrivacyKey:    privacyKey,
		SessionID:     sessionID,
	}, nil
}
