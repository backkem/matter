// AES-CCM implementation for Matter protocol.
// This implements AES-128-CCM as defined in NIST 800-38C and RFC 3610.
// Matter Specification Section 3.6 requires AES-CCM with:
//   - Key length: 128 bits (16 bytes)
//   - MIC/Tag length: 128 bits (16 bytes)
//   - Nonce length: 13 bytes
//   - q = 2 (length field size)

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// AES-CCM constants from Matter Specification Section 3.6.
const (
	// AESCCMKeySize is the AES-128 key size in bytes (CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES).
	AESCCMKeySize = 16

	// AESCCMTagSize is the authentication tag size in bytes (CRYPTO_AEAD_MIC_LENGTH_BYTES).
	// Matter mandates 128-bit tags.
	AESCCMTagSize = 16

	// AESCCMNonceSize is the nonce size in bytes (CRYPTO_AEAD_NONCE_LENGTH_BYTES).
	// Matter mandates 13-byte nonces.
	AESCCMNonceSize = 13

	// aesBlockSize is the AES block size (always 16 bytes).
	aesBlockSize = 16
)

// Errors
var (
	ErrAESCCMInvalidKeySize     = errors.New("aesccm: invalid key size, must be 16 bytes")
	ErrAESCCMInvalidNonceSize   = errors.New("aesccm: invalid nonce size")
	ErrAESCCMInvalidTagSize     = errors.New("aesccm: invalid tag size, must be 4, 6, 8, 10, 12, 14, or 16")
	ErrAESCCMPlaintextTooLong   = errors.New("aesccm: plaintext too long")
	ErrAESCCMCiphertextTooShort = errors.New("aesccm: ciphertext too short")
	ErrAESCCMAuthFailed         = errors.New("aesccm: message authentication failed")
)

// AESCCM represents an AES-128-CCM cipher instance with configurable parameters.
type AESCCM struct {
	block    cipher.Block
	tagSize  int // M: authentication tag size (4, 6, 8, 10, 12, 14, or 16)
	lenSize  int // L: length field size (15 - nonceSize), typically 2-8
}

// NewAESCCM creates a new AES-128-CCM cipher with Matter-compliant parameters.
// The key must be exactly 16 bytes (128 bits).
// Uses 13-byte nonce and 16-byte tag as required by Matter Specification Section 3.6.
func NewAESCCM(key []byte) (*AESCCM, error) {
	return NewAESCCMWithParams(key, AESCCMNonceSize, AESCCMTagSize)
}

// NewAESCCMWithParams creates a new AES-128-CCM cipher with configurable parameters.
// This allows testing with RFC 3610 vectors which use different nonce and tag sizes.
//
// Parameters:
//   - key: 16-byte AES-128 key
//   - nonceSize: nonce length in bytes (7-13 per NIST 800-38C)
//   - tagSize: authentication tag length in bytes (4, 6, 8, 10, 12, 14, or 16)
func NewAESCCMWithParams(key []byte, nonceSize, tagSize int) (*AESCCM, error) {
	if len(key) != AESCCMKeySize {
		return nil, ErrAESCCMInvalidKeySize
	}

	// Validate nonce size: L = 15 - n, where 2 <= L <= 8
	lenSize := 15 - nonceSize
	if lenSize < 2 || lenSize > 8 {
		return nil, ErrAESCCMInvalidNonceSize
	}

	// Validate tag size: must be even and between 4-16
	if tagSize < 4 || tagSize > 16 || tagSize%2 != 0 {
		return nil, ErrAESCCMInvalidTagSize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &AESCCM{
		block:   block,
		tagSize: tagSize,
		lenSize: lenSize,
	}, nil
}

// NonceSize returns the required nonce size for this cipher.
func (c *AESCCM) NonceSize() int {
	return 15 - c.lenSize
}

// TagSize returns the authentication tag size for this cipher.
func (c *AESCCM) TagSize() int {
	return c.tagSize
}

// Seal encrypts and authenticates plaintext with associated data.
// This implements Crypto_AEAD_GenerateEncrypt from Matter Specification Section 3.6.1.
//
// Parameters:
//   - nonce: nonce of the configured size (must be unique for each encryption with the same key)
//   - plaintext: data to encrypt
//   - aad: additional authenticated data (not encrypted, but authenticated)
//
// Returns ciphertext || tag (plaintext length + tagSize bytes for tag).
func (c *AESCCM) Seal(nonce, plaintext, aad []byte) ([]byte, error) {
	if len(nonce) != c.NonceSize() {
		return nil, ErrAESCCMInvalidNonceSize
	}

	// Maximum plaintext length with L bytes for length field
	maxPlaintextLen := (1 << (8 * c.lenSize)) - 1
	if len(plaintext) > maxPlaintextLen {
		return nil, ErrAESCCMPlaintextTooLong
	}

	// Compute the authentication tag (T)
	tag := c.computeTag(nonce, plaintext, aad)

	// Generate the keystream and encrypt
	ciphertext := make([]byte, len(plaintext)+c.tagSize)

	// Encrypt the tag with S_0
	s0 := c.generateS0(nonce)
	for i := 0; i < c.tagSize; i++ {
		ciphertext[len(plaintext)+i] = tag[i] ^ s0[i]
	}

	// Encrypt the plaintext with CTR mode starting from counter 1
	c.ctrEncrypt(nonce, ciphertext[:len(plaintext)], plaintext)

	return ciphertext, nil
}

// Open decrypts and verifies ciphertext with associated data.
// This implements Crypto_AEAD_DecryptVerify from Matter Specification Section 3.6.2.
//
// Parameters:
//   - nonce: nonce of the configured size (same as used for encryption)
//   - ciphertext: encrypted data with tag (minimum tagSize bytes for tag)
//   - aad: additional authenticated data
//
// Returns the decrypted plaintext, or an error if authentication fails.
func (c *AESCCM) Open(nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != c.NonceSize() {
		return nil, ErrAESCCMInvalidNonceSize
	}

	if len(ciphertext) < c.tagSize {
		return nil, ErrAESCCMCiphertextTooShort
	}

	// Split ciphertext and encrypted tag
	encryptedData := ciphertext[:len(ciphertext)-c.tagSize]
	encryptedTag := ciphertext[len(ciphertext)-c.tagSize:]

	// Decrypt the tag with S_0
	s0 := c.generateS0(nonce)
	receivedTag := make([]byte, c.tagSize)
	for i := 0; i < c.tagSize; i++ {
		receivedTag[i] = encryptedTag[i] ^ s0[i]
	}

	// Decrypt the plaintext with CTR mode
	plaintext := make([]byte, len(encryptedData))
	c.ctrEncrypt(nonce, plaintext, encryptedData)

	// Compute the expected tag
	expectedTag := c.computeTag(nonce, plaintext, aad)

	// Verify the tag using constant-time comparison
	if subtle.ConstantTimeCompare(receivedTag, expectedTag[:c.tagSize]) != 1 {
		return nil, ErrAESCCMAuthFailed
	}

	return plaintext, nil
}

// computeTag computes the CBC-MAC authentication tag.
// This follows NIST 800-38C Section 6.1 and RFC 3610 Section 2.2.
func (c *AESCCM) computeTag(nonce, plaintext, aad []byte) []byte {
	// Build B_0 (first block)
	// Flags = Reserved(1) || Adata(1) || M'(3) || L'(3)
	// M' = (tagSize - 2) / 2
	// L' = L - 1
	var b0 [aesBlockSize]byte
	flags := byte(0)
	if len(aad) > 0 {
		flags |= 1 << 6 // Adata flag
	}
	flags |= byte((c.tagSize-2)/2) << 3 // M' in bits 3-5
	flags |= byte(c.lenSize - 1)        // L' in bits 0-2

	b0[0] = flags
	nonceSize := c.NonceSize()
	copy(b0[1:1+nonceSize], nonce)
	// Last L bytes contain the message length (big-endian)
	c.putLength(b0[1+nonceSize:], len(plaintext))

	// Initialize CBC-MAC with B_0
	mac := make([]byte, aesBlockSize)
	c.block.Encrypt(mac, b0[:])

	// Process AAD if present
	if len(aad) > 0 {
		// AAD length encoding
		// For 0 < l(a) < 2^16 - 2^8: encode as 2 bytes
		// For 2^16 - 2^8 <= l(a) < 2^32: encode as 0xFFFE || 4 bytes
		// For 2^32 <= l(a) < 2^64: encode as 0xFFFF || 8 bytes
		var aadBlock [aesBlockSize]byte
		aadLen := len(aad)
		var headerLen int

		if aadLen < (1<<16)-(1<<8) {
			binary.BigEndian.PutUint16(aadBlock[0:2], uint16(aadLen))
			headerLen = 2
		} else if aadLen < (1 << 32) {
			aadBlock[0] = 0xFF
			aadBlock[1] = 0xFE
			binary.BigEndian.PutUint32(aadBlock[2:6], uint32(aadLen))
			headerLen = 6
		} else {
			aadBlock[0] = 0xFF
			aadBlock[1] = 0xFF
			binary.BigEndian.PutUint64(aadBlock[2:10], uint64(aadLen))
			headerLen = 10
		}

		// Copy as much AAD as fits in the first block
		firstBlockAAD := aesBlockSize - headerLen
		if firstBlockAAD > len(aad) {
			firstBlockAAD = len(aad)
		}
		copy(aadBlock[headerLen:], aad[:firstBlockAAD])

		// XOR and encrypt
		for i := 0; i < aesBlockSize; i++ {
			mac[i] ^= aadBlock[i]
		}
		c.block.Encrypt(mac, mac)

		// Process remaining AAD
		remaining := aad[firstBlockAAD:]
		for len(remaining) > 0 {
			var block [aesBlockSize]byte
			n := copy(block[:], remaining)
			remaining = remaining[n:]

			for i := 0; i < aesBlockSize; i++ {
				mac[i] ^= block[i]
			}
			c.block.Encrypt(mac, mac)
		}
	}

	// Process plaintext
	remaining := plaintext
	for len(remaining) > 0 {
		var block [aesBlockSize]byte
		n := copy(block[:], remaining)
		remaining = remaining[n:]

		for i := 0; i < aesBlockSize; i++ {
			mac[i] ^= block[i]
		}
		c.block.Encrypt(mac, mac)
	}

	return mac[:c.tagSize]
}

// generateS0 generates the S_0 keystream block for tag encryption.
// S_0 = E(K, A_0) where A_0 is the first counter block with counter = 0.
func (c *AESCCM) generateS0(nonce []byte) []byte {
	// A_0 format:
	// Flags = Reserved(2) || 0(3) || L'(3)
	// L' = L - 1
	var a0 [aesBlockSize]byte
	a0[0] = byte(c.lenSize - 1) // L' in bits 0-2, other bits are 0
	nonceSize := c.NonceSize()
	copy(a0[1:1+nonceSize], nonce)
	// Counter = 0 (last L bytes are zero)

	s0 := make([]byte, aesBlockSize)
	c.block.Encrypt(s0, a0[:])
	return s0
}

// ctrEncrypt encrypts/decrypts data using CTR mode starting from counter 1.
// This uses the counter generation function from NIST 800-38C Appendix A.3.
func (c *AESCCM) ctrEncrypt(nonce []byte, dst, src []byte) {
	// Build the initial counter block A_1
	var ctr [aesBlockSize]byte
	ctr[0] = byte(c.lenSize - 1) // L' in bits 0-2
	nonceSize := c.NonceSize()
	copy(ctr[1:1+nonceSize], nonce)
	// Start with counter = 1 in the last L bytes
	ctr[aesBlockSize-1] = 1

	var keystream [aesBlockSize]byte
	for i := 0; i < len(src); i += aesBlockSize {
		c.block.Encrypt(keystream[:], ctr[:])

		// XOR plaintext with keystream
		end := i + aesBlockSize
		if end > len(src) {
			end = len(src)
		}
		for j := i; j < end; j++ {
			dst[j] = src[j] ^ keystream[j-i]
		}

		// Increment counter (big-endian, last L bytes)
		incrementCounter(ctr[aesBlockSize-c.lenSize:])
	}
}

// putLength encodes the message length into dst as a big-endian value.
// dst must have at least c.lenSize bytes.
func (c *AESCCM) putLength(dst []byte, length int) {
	for i := c.lenSize - 1; i >= 0; i-- {
		dst[i] = byte(length)
		length >>= 8
	}
}

// incrementCounter increments a big-endian counter.
func incrementCounter(ctr []byte) {
	for i := len(ctr) - 1; i >= 0; i-- {
		ctr[i]++
		if ctr[i] != 0 {
			break
		}
	}
}

// AESCCM128Encrypt is a convenience function for AES-128-CCM encryption.
// This implements Crypto_AEAD_GenerateEncrypt from Matter Specification Section 3.6.1.
//
// Parameters:
//   - key: 16-byte AES-128 key
//   - nonce: 13-byte nonce
//   - plaintext: data to encrypt
//   - aad: additional authenticated data
//
// Returns ciphertext || tag.
func AESCCM128Encrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	ccm, err := NewAESCCM(key)
	if err != nil {
		return nil, err
	}
	return ccm.Seal(nonce, plaintext, aad)
}

// AESCCM128Decrypt is a convenience function for AES-128-CCM decryption.
// This implements Crypto_AEAD_DecryptVerify from Matter Specification Section 3.6.2.
//
// Parameters:
//   - key: 16-byte AES-128 key
//   - nonce: 13-byte nonce
//   - ciphertext: encrypted data with tag
//   - aad: additional authenticated data
//
// Returns the decrypted plaintext, or an error if authentication fails.
func AESCCM128Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	ccm, err := NewAESCCM(key)
	if err != nil {
		return nil, err
	}
	return ccm.Open(nonce, ciphertext, aad)
}
