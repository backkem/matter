package message

import (
	"github.com/backkem/matter/pkg/crypto"
)

// Codec handles message encoding and decoding for a specific session.
// It manages encryption keys and provides methods for secure message processing.
type Codec struct {
	encryptionKey []byte // 16-byte AES-128 key
	privacyKey    []byte // Derived privacy key (cached)
	sourceNodeID  uint64 // Node ID for nonce construction
}

// NewCodec creates a new codec with the given encryption key and source node ID.
// The encryption key must be exactly 16 bytes (AES-128).
// For PASE sessions, sourceNodeID should be UnspecifiedNodeID (0).
// For CASE sessions, sourceNodeID should be the operational node ID.
func NewCodec(encryptionKey []byte, sourceNodeID uint64) (*Codec, error) {
	if len(encryptionKey) != crypto.SymmetricKeySize {
		return nil, ErrInvalidKey
	}

	// Pre-derive privacy key
	privacyKey, err := crypto.DerivePrivacyKey(encryptionKey)
	if err != nil {
		return nil, err
	}

	return &Codec{
		encryptionKey: encryptionKey,
		privacyKey:    privacyKey,
		sourceNodeID:  sourceNodeID,
	}, nil
}

// Encode encrypts a frame for transmission.
// This implements Spec Section 4.8.2 (Security Processing of Outgoing Messages)
// and optionally 4.9.3 (Privacy Processing of Outgoing Messages).
//
// Parameters:
//   - header: Message header (will be modified with security flags)
//   - protocol: Protocol header to encrypt
//   - payload: Application payload to encrypt
//   - privacy: Whether to apply privacy obfuscation (sets P flag)
//
// Returns the complete encoded message ready for transmission.
func (c *Codec) Encode(header *MessageHeader, protocol *ProtocolHeader, payload []byte, privacy bool) ([]byte, error) {
	// Set privacy flag
	header.Privacy = privacy

	// Build plaintext: protocol header + application payload
	protocolBytes := protocol.Encode()
	plaintext := make([]byte, len(protocolBytes)+len(payload))
	copy(plaintext, protocolBytes)
	copy(plaintext[len(protocolBytes):], payload)

	// Build AAD (Additional Authenticated Data) = message header
	aad := header.Encode()

	// Build nonce per Spec 4.8.1.1
	nonce := crypto.BuildAEADNonce(header.securityFlags(), header.MessageCounter, c.sourceNodeID)

	// Encrypt with AES-CCM
	ciphertext, err := crypto.AESCCM128Encrypt(c.encryptionKey, nonce, plaintext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	// ciphertext includes the MIC at the end
	// Split into encrypted payload and MIC for privacy processing
	encryptedPayload := ciphertext[:len(ciphertext)-MICSize]
	mic := ciphertext[len(ciphertext)-MICSize:]

	// Apply privacy obfuscation if requested
	var headerBytes []byte
	if privacy {
		headerBytes, err = c.applyPrivacy(header, mic)
		if err != nil {
			return nil, err
		}
	} else {
		headerBytes = aad
	}

	// Build final message: header || encrypted payload || MIC
	result := make([]byte, len(headerBytes)+len(encryptedPayload)+MICSize)
	copy(result, headerBytes)
	copy(result[len(headerBytes):], encryptedPayload)
	copy(result[len(headerBytes)+len(encryptedPayload):], mic)

	return result, nil
}

// applyPrivacy applies privacy obfuscation to the message header.
// Implements Spec Section 4.9.3.
func (c *Codec) applyPrivacy(header *MessageHeader, mic []byte) ([]byte, error) {
	// Get the full header bytes
	headerBytes := header.Encode()

	// Privacy nonce = SessionID (BE) || MIC[5..15]
	privacyNonce, err := crypto.BuildPrivacyNonce(header.SessionID, mic)
	if err != nil {
		return nil, err
	}

	// The obfuscated portion: Message Counter || [Source ID] || [Destination ID]
	// Starts at offset 4 (after Message Flags + Session ID + Security Flags)
	privacyOffset := header.PrivacyHeaderOffset()
	privacyLen := header.PrivacyObfuscatedSize()

	if privacyLen == 0 {
		// Nothing to obfuscate
		return headerBytes, nil
	}

	// Encrypt the obfuscated portion with AES-CTR
	obfuscated, err := crypto.AESCTREncrypt(c.privacyKey, privacyNonce, headerBytes[privacyOffset:privacyOffset+privacyLen])
	if err != nil {
		return nil, err
	}

	// Replace the original bytes with obfuscated bytes
	copy(headerBytes[privacyOffset:], obfuscated)

	return headerBytes, nil
}

// Decode decrypts a received secure message.
// This implements Spec Section 4.8.3 (Security Processing of Incoming Messages)
// and optionally 4.9.4 (Privacy Processing of Incoming Messages).
//
// Parameters:
//   - data: Complete received message bytes
//   - sourceNodeID: Source node ID for nonce construction (from header or session context)
//
// Returns the decoded frame with decrypted payload.
func (c *Codec) Decode(data []byte, sourceNodeID uint64) (*Frame, error) {
	// Parse raw frame to get header and encrypted payload
	raw, err := DecodeRaw(data)
	if err != nil {
		return nil, err
	}

	// Verify this is a secure message
	if !raw.Header.IsSecure() {
		return nil, ErrDecryptionFailed
	}

	// Deobfuscate header if privacy is enabled
	headerBytes := make([]byte, raw.Header.Size())
	if raw.Header.Privacy {
		// Need to reconstruct original header bytes from data
		copy(headerBytes, data[:raw.Header.Size()])

		err = c.removePrivacy(headerBytes, &raw.Header, raw.MIC)
		if err != nil {
			return nil, err
		}

		// Re-decode header after deobfuscation
		if _, err := raw.Header.Decode(headerBytes); err != nil {
			return nil, err
		}
	} else {
		raw.Header.EncodeTo(headerBytes)
	}

	// Build nonce
	nonce := crypto.BuildAEADNonce(raw.Header.securityFlags(), raw.Header.MessageCounter, sourceNodeID)

	// Reconstruct ciphertext = encrypted payload || MIC
	ciphertext := make([]byte, len(raw.EncryptedPayload)+MICSize)
	copy(ciphertext, raw.EncryptedPayload)
	copy(ciphertext[len(raw.EncryptedPayload):], raw.MIC)

	// Decrypt with AES-CCM
	plaintext, err := crypto.AESCCM128Decrypt(c.encryptionKey, nonce, ciphertext, headerBytes)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	// Parse decrypted plaintext into protocol header + payload
	frame := &Frame{
		Header: raw.Header,
	}

	protocolLen, err := frame.Protocol.Decode(plaintext)
	if err != nil {
		return nil, err
	}

	if len(plaintext) > protocolLen {
		frame.Payload = make([]byte, len(plaintext)-protocolLen)
		copy(frame.Payload, plaintext[protocolLen:])
	}

	return frame, nil
}

// removePrivacy removes privacy obfuscation from header bytes.
// Implements Spec Section 4.9.4.
func (c *Codec) removePrivacy(headerBytes []byte, header *MessageHeader, mic []byte) error {
	// Privacy nonce = SessionID (BE) || MIC[5..15]
	privacyNonce, err := crypto.BuildPrivacyNonce(header.SessionID, mic)
	if err != nil {
		return err
	}

	// The obfuscated portion starts at offset 4
	privacyOffset := header.PrivacyHeaderOffset()
	privacyLen := header.PrivacyObfuscatedSize()

	if privacyLen == 0 {
		return nil
	}

	// Decrypt the obfuscated portion with AES-CTR
	deobfuscated, err := crypto.AESCTRDecrypt(c.privacyKey, privacyNonce, headerBytes[privacyOffset:privacyOffset+privacyLen])
	if err != nil {
		return err
	}

	// Replace the obfuscated bytes with original bytes
	copy(headerBytes[privacyOffset:], deobfuscated)

	return nil
}

// DecodeWithKey is a convenience function to decode a message with a given key.
// This creates a temporary codec and decodes the message.
func DecodeWithKey(data []byte, encryptionKey []byte, sourceNodeID uint64) (*Frame, error) {
	codec, err := NewCodec(encryptionKey, sourceNodeID)
	if err != nil {
		return nil, err
	}
	return codec.Decode(data, sourceNodeID)
}

// UnsecuredCodec provides encoding/decoding for unsecured session messages.
// These messages are not encrypted and have no MIC.
type UnsecuredCodec struct{}

// NewUnsecuredCodec creates a codec for unsecured messages.
func NewUnsecuredCodec() *UnsecuredCodec {
	return &UnsecuredCodec{}
}

// Encode creates an unsecured message frame.
func (u *UnsecuredCodec) Encode(header *MessageHeader, protocol *ProtocolHeader, payload []byte) []byte {
	frame := &Frame{
		Header:   *header,
		Protocol: *protocol,
		Payload:  payload,
	}
	return frame.EncodeUnsecured()
}

// Decode parses an unsecured message frame.
func (u *UnsecuredCodec) Decode(data []byte) (*Frame, error) {
	return DecodeUnsecured(data)
}
