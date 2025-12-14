// Nonce construction and key derivation for Matter message security.
// This implements helpers from Matter Specification Sections 4.8 and 4.9.

package crypto

import (
	"encoding/binary"
	"errors"
)

// Message security constants from Matter Specification.
const (
	// NonceSize is the AEAD nonce length (CRYPTO_AEAD_NONCE_LENGTH_BYTES).
	// Used for both AES-CCM message encryption and AES-CTR privacy encryption.
	NonceSize = 13

	// SymmetricKeySize is the symmetric key length (CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES).
	SymmetricKeySize = 16

	// MICSize is the Message Integrity Check length (CRYPTO_AEAD_MIC_LENGTH_BYTES).
	MICSize = 16

	// PrivacyNonceMICOffset is the starting offset in the MIC for privacy nonce (5).
	PrivacyNonceMICOffset = 5

	// PrivacyNonceMICLength is the length of MIC fragment used in privacy nonce (11).
	PrivacyNonceMICLength = 11
)

// Privacy key derivation info string.
var privacyKeyInfo = []byte("PrivacyKey")

// Errors for nonce operations.
var (
	ErrInvalidKeySize = errors.New("nonce: invalid key size, must be 16 bytes")
	ErrInvalidMICSize = errors.New("nonce: invalid MIC size, must be 16 bytes")
)

// BuildAEADNonce constructs a 13-byte nonce for AEAD encryption/decryption.
// This implements the nonce format from Matter Specification Section 4.8.1.1 (Table 17).
//
// Format: SecurityFlags (1 byte) || MessageCounter (4 bytes LE) || SourceNodeID (8 bytes LE)
//
// Parameters:
//   - securityFlags: Security flags byte from the message header
//   - messageCounter: Message counter (32-bit, little-endian in nonce)
//   - sourceNodeID: Source node ID (64-bit, little-endian in nonce)
//     For PASE sessions, use UnspecifiedNodeID (0).
//     For CASE sessions, use the Operational Node ID.
//     For Group sessions, use the Source Node ID from the message.
//
// Returns a 13-byte nonce suitable for AES-CCM operations.
func BuildAEADNonce(securityFlags uint8, messageCounter uint32, sourceNodeID uint64) []byte {
	nonce := make([]byte, NonceSize)

	// Byte 0: Security Flags
	nonce[0] = securityFlags

	// Bytes 1-4: Message Counter (little-endian)
	binary.LittleEndian.PutUint32(nonce[1:5], messageCounter)

	// Bytes 5-12: Source Node ID (little-endian)
	binary.LittleEndian.PutUint64(nonce[5:13], sourceNodeID)

	return nonce
}

// DerivePrivacyKey derives a privacy key from an encryption key.
// This implements Section 4.9.1 "Privacy Key" derivation.
//
// PrivacyKey = Crypto_KDF(
//
//	InputKey = EncryptionKey,
//	Salt = [],
//	Info = "PrivacyKey",
//	Length = CRYPTO_SYMMETRIC_KEY_LENGTH_BITS
//
// )
//
// Parameters:
//   - encryptionKey: The 16-byte session encryption key
//
// Returns the 16-byte privacy key for use with AES-CTR privacy encryption.
func DerivePrivacyKey(encryptionKey []byte) ([]byte, error) {
	if len(encryptionKey) != SymmetricKeySize {
		return nil, ErrInvalidKeySize
	}

	// HKDF with empty salt and "PrivacyKey" info
	return HKDFSHA256(encryptionKey, nil, privacyKeyInfo, SymmetricKeySize)
}

// BuildPrivacyNonce constructs a 13-byte nonce for privacy encryption/decryption.
// This implements Section 4.9.2 "Privacy Nonce".
//
// Format: SessionID (2 bytes BE) || MIC[5..15] (11 bytes)
//
// The privacy nonce uses the session ID in big-endian format concatenated with
// the lower 11 bytes of the MIC (bytes at indices 5 through 15 inclusive).
//
// Parameters:
//   - sessionID: The 16-bit session identifier
//   - mic: The 16-byte Message Integrity Check (tag) from AEAD encryption
//
// Returns a 13-byte nonce suitable for AES-CTR privacy operations.
func BuildPrivacyNonce(sessionID uint16, mic []byte) ([]byte, error) {
	if len(mic) != MICSize {
		return nil, ErrInvalidMICSize
	}

	nonce := make([]byte, NonceSize)

	// Bytes 0-1: Session ID (big-endian)
	binary.BigEndian.PutUint16(nonce[0:2], sessionID)

	// Bytes 2-12: MIC[5..15] (11 bytes from offset 5)
	copy(nonce[2:13], mic[PrivacyNonceMICOffset:PrivacyNonceMICOffset+PrivacyNonceMICLength])

	return nonce, nil
}
