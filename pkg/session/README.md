# session

Package `session` manages Secure Session Contexts for the node.

It is responsible for maintaining the state of all active encrypted sessions (PASE and CASE), including cryptographic keys, message counters, and replay protection.

## Architecture

```
                    ┌───────────────────────────┐
                    │      Session Manager      │
                    │                           │
                    │   FindSecureContext()     │
                    │   AddSecureContext()      │
                    └─────────────┬─────────────┘
                                  │
          ┌───────────────────────┴───────────────────────┐
          ▼                                               ▼
   ┌─────────────┐                                 ┌─────────────┐
   │ Secure      │ (PASE/CASE)                     │ Group Peer  │
   │ Context     │                                 │ Table       │
   ├─────────────┤                                 ├─────────────┤
   │ I2R/R2I Keys│                                 │ NodeID      │
   │ Peer NodeID │                                 │ FabricIdx   │
   │ FabricIndex │                                 │ MaxCounter  │
   └─────────────┘                                 └─────────────┘
```

## Usage

### Initialize Manager

```go
import "github.com/backkem/matter/pkg/session"

mgr := session.NewManager(session.ManagerConfig{
    MaxSessions: 16, // Default supported sessions
})
```

### Retrieve a Session

When a message arrives, the `Local Session ID` in the header is used to find the context.

```go
// header.SessionID comes from the wire
ctx := mgr.FindSecureContext(header.SessionID)
if ctx == nil {
    // Unknown session
}
```

### Decrypt a Message

The `SecureContext` handles decryption and replay protection (checking message counters).

```go
// Returns decrypted frame or error (e.g. replay detected)
frame, err := ctx.Decrypt(encryptedData)
```

### Lifecycle

*   **Creation**: Called by `pkg/securechannel` upon successful handshake.
*   **Removal**: Called when a session expires, is evicted, or the fabric is removed.