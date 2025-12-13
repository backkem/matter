// AES-CTR implementation for Matter protocol privacy encryption.
// This implements AES-128-CTR as defined in NIST 800-38A Section 6.5.
// Matter Specification Section 3.7 requires AES-CTR with:
//   - Key length: 128 bits (16 bytes)
//   - Nonce length: 13 bytes (CRYPTO_PRIVACY_NONCE_LENGTH_BYTES)
//   - Counter generation per NIST 800-38C Appendix A.3 with q=2

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// AES-CTR constants from Matter Specification Section 3.7.
const (
	// AESCTRKeySize is the AES-128 key size in bytes.
	AESCTRKeySize = 16

	// AESCTRNonceSize is the nonce size in bytes (CRYPTO_PRIVACY_NONCE_LENGTH_BYTES).
	// Matter mandates 13-byte nonces for privacy encryption.
	AESCTRNonceSize = 13

	// aesCTRBlockSize is the AES block size (always 16 bytes).
	aesCTRBlockSize = 16

	// aesCTRLenSize is the length field size (L = 15 - nonceSize = 2).
	aesCTRLenSize = 2
)

// Errors for AES-CTR operations.
var (
	ErrAESCTRInvalidKeySize   = errors.New("aesctr: invalid key size, must be 16 bytes")
	ErrAESCTRInvalidNonceSize = errors.New("aesctr: invalid nonce size, must be 13 bytes")
)

// AESCTR represents an AES-128-CTR cipher instance for privacy encryption.
type AESCTR struct {
	block cipher.Block
}

// NewAESCTR creates a new AES-128-CTR cipher for Matter privacy encryption.
// The key must be exactly 16 bytes (128 bits).
func NewAESCTR(key []byte) (*AESCTR, error) {
	if len(key) != AESCTRKeySize {
		return nil, ErrAESCTRInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &AESCTR{block: block}, nil
}

// NonceSize returns the required nonce size for this cipher.
func (c *AESCTR) NonceSize() int {
	return AESCTRNonceSize
}

// Encrypt encrypts plaintext using AES-CTR mode.
// This implements Crypto_Privacy_Encrypt from Matter Specification Section 3.7.1.
//
// Parameters:
//   - nonce: 13-byte nonce
//   - plaintext: data to encrypt
//
// Returns ciphertext of the same length as plaintext.
func (c *AESCTR) Encrypt(nonce, plaintext []byte) ([]byte, error) {
	if len(nonce) != AESCTRNonceSize {
		return nil, ErrAESCTRInvalidNonceSize
	}

	ciphertext := make([]byte, len(plaintext))
	c.ctrXOR(nonce, ciphertext, plaintext)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-CTR mode.
// This implements Crypto_Privacy_Decrypt from Matter Specification Section 3.7.2.
//
// Parameters:
//   - nonce: 13-byte nonce (same as used for encryption)
//   - ciphertext: data to decrypt
//
// Returns plaintext of the same length as ciphertext.
func (c *AESCTR) Decrypt(nonce, ciphertext []byte) ([]byte, error) {
	if len(nonce) != AESCTRNonceSize {
		return nil, ErrAESCTRInvalidNonceSize
	}

	plaintext := make([]byte, len(ciphertext))
	c.ctrXOR(nonce, plaintext, ciphertext)
	return plaintext, nil
}

// ctrXOR performs CTR mode encryption/decryption (they are identical operations).
// Uses counter generation from NIST 800-38C Appendix A.3 with L=2.
//
// Note: The counter starts at 1, not 0. This is consistent with how Matter's
// AES-CCM uses CTR mode (counter 0 is reserved for S_0 tag encryption).
// The SDK implements AES_CTR_crypt by reusing AES_CCM_encrypt with empty AAD.
func (c *AESCTR) ctrXOR(nonce []byte, dst, src []byte) {
	if len(src) == 0 {
		return
	}

	// Build the initial counter block A_1
	// Format: Flags (1 byte) || Nonce (13 bytes) || Counter (2 bytes)
	// Flags = L-1 = 1 (since L=2 for 13-byte nonce)
	var ctr [aesCTRBlockSize]byte
	ctr[0] = aesCTRLenSize - 1 // L-1 = 1
	copy(ctr[1:1+AESCTRNonceSize], nonce)
	// Counter starts at 1 (consistent with CCM's CTR encryption)
	ctr[aesCTRBlockSize-1] = 1

	// Use Go's standard CTR mode
	stream := cipher.NewCTR(c.block, ctr[:])
	stream.XORKeyStream(dst, src)
}

// AESCTREncrypt is a convenience function for AES-128-CTR encryption.
// This implements Crypto_Privacy_Encrypt from Matter Specification Section 3.7.1.
//
// Parameters:
//   - key: 16-byte AES-128 key
//   - nonce: 13-byte nonce
//   - plaintext: data to encrypt
//
// Returns ciphertext of the same length as plaintext.
func AESCTREncrypt(key, nonce, plaintext []byte) ([]byte, error) {
	ctr, err := NewAESCTR(key)
	if err != nil {
		return nil, err
	}
	return ctr.Encrypt(nonce, plaintext)
}

// AESCTRDecrypt is a convenience function for AES-128-CTR decryption.
// This implements Crypto_Privacy_Decrypt from Matter Specification Section 3.7.2.
//
// Parameters:
//   - key: 16-byte AES-128 key
//   - nonce: 13-byte nonce
//   - ciphertext: data to decrypt
//
// Returns plaintext of the same length as ciphertext.
func AESCTRDecrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	ctr, err := NewAESCTR(key)
	if err != nil {
		return nil, err
	}
	return ctr.Decrypt(nonce, ciphertext)
}
