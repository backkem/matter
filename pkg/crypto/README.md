# crypto

Package `crypto` provides the core cryptographic primitives required by the Matter protocol.

It wraps standard Go crypto libraries and implements Matter-specific algorithms where necessary (e.g., SPAKE2+, privacy nonce construction).

## Features

*   **AES-CCM-128**: Authenticated encryption for message payloads (Spec 3.6).
*   **HKDF-SHA256**: Key derivation for session keys (Spec 3.8).
*   **NIST P-256**: Elliptic curve for signatures and ECDH (Spec 3.4).
*   **SPAKE2+**: Password-Authenticated Key Exchange for commissioning (Spec 3.10).

## Usage

This package is primarily a utility library for `pkg/session` and `pkg/securechannel`.

### Authenticated Encryption

```go
import "github.com/backkem/matter/pkg/crypto"

// Encrypt (Key must be 16 bytes)
ciphertext, err := crypto.AESCCM128Encrypt(key, nonce, plaintext, aad)

// Decrypt
plaintext, err := crypto.AESCCM128Decrypt(key, nonce, ciphertext, aad)
```

### Key Derivation

```go
// Derive keys using HKDF-SHA256
key := crypto.HKDF_SHA256(secret, salt, info, outputLen)
```