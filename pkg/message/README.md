# message

Package `message` handles the framing, encoding, and security processing of Matter messages (Spec Section 4).

It implements the logic for:
*   **Framing**: Constructing the Message Header (Session ID, Flags, Counter).
*   **Security**: AES-CCM encryption/decryption using Session Keys.
*   **Privacy**: Header obfuscation (AES-CTR) to hide source/destination.

## Architecture

*   **Codec**: The core worker. It is initialized with session keys and handles the transform between `Plaintext` <-> `Encrypted Frame`.
*   **Frame**: Represents a fully decoded message with accessible Payload and Headers.
*   **MessageHeader**: Struct representing the unencrypted (but potentially obfuscated) wire header.

## Usage

### Encryption (Sending)

This is typically handled by the `SessionManager`, but can be used directly:

```go
import "github.com/backkem/matter/pkg/message"

// 1. Create a Codec with the encryption key
codec, _ := message.NewCodec(sessionKey, localNodeID)

// 2. Prepare Headers
header := &message.MessageHeader{
    SessionID:      peerSessionID,
    MessageCounter: counter,
    // Flags are set automatically based on fields
}

// 3. Encrypt
// Result is the full byte slice ready for the wire
wireBytes, err := codec.Encode(header, protocolHeader, payload, true)
```

### Decryption (Receiving)

```go
// 1. Decode and Decrypt
frame, err := codec.Decode(receivedBytes, peerNodeID)
if err != nil {
    // Decryption failed (bad key or bad mic)
}

// 2. Access Data
fmt.Printf("Protocol: %d\n", frame.Protocol.ID)
fmt.Printf("Payload: %x\n", frame.Payload)
```

```
