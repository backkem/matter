# securechannel

Manager for Matter Secure Channel Protocol (Spec Section 4.11-4.14).

## Architecture

```
                    ┌──────────────────────────────────────────┐
                    │              Manager                     │
                    │                                          │
                    │   Route(exchangeID, opcode, payload)     │
                    │          │                               │
                    │          ▼                               │
                    │   ┌──────────────────────────────┐       │
                    │   │   Opcode Router              │       │
                    │   │   0x20-0x24 → PASE           │       │
                    │   │   0x30-0x33 → CASE           │       │
                    │   │   0x40      → StatusReport   │       │
                    │   └──────────────────────────────┘       │
                    │          │                               │
                    │   ┌──────┴──────┐                        │
                    │   ▼             ▼                        │
                    │ pase/        case/                       │
                    │ Session      Session                     │
                    │                                          │
                    │          │                               │
                    │          ▼                               │
                    │   OnSessionEstablished(SecureContext)    │
                    └──────────────────────────────────────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    ▼                  ▼                  ▼
             pkg/session        pkg/fabric        pkg/credentials
             (SecureContext)    (FabricTable)     (CertValidator)
```

## Usage

### Create Manager

```go
mgr := securechannel.NewManager(sessionTable, fabricTable)
```

### Start PASE Handshake (Commissioner)

```go
pbkdfReq, err := mgr.StartPASE(exchangeID, passcode, salt, iterations, localSessionID)
// Send pbkdfReq to peer, then route responses through mgr.Route()
```

### Start CASE Handshake (Initiator)

```go
sigma1, err := mgr.StartCASE(exchangeID, fabricInfo, operationalKey, peerNodeID, localSessionID)
// Send sigma1 to peer, then route responses through mgr.Route()
```

### Route Incoming Messages

```go
response, err := mgr.Route(exchangeID, opcode, payload)
if response != nil {
    // Send response back to peer
}
// On completion, SecureContext is added to SessionTable
```

### Handle Responder Role

```go
// PASE responder
mgr.SetPASEResponder(verifier, salt, iterations)

// CASE responder
mgr.SetCASEResponder(fabricLookupFunc, certValidator)

// Then route incoming Sigma1/PBKDFParamRequest through mgr.Route()
```

### Certificate Validation

```go
// Production: full NOC → ICAC → RCAC chain validation
mgr := securechannel.NewManager(sessionTable, fabricTable)
// Uses NewCertValidator() by default

// Testing: skip validation
mgr := securechannel.NewManagerWithValidator(sessionTable, fabricTable,
    securechannel.NewSkipCertValidator())
```

## Message Flow

```
PASE:                                    CASE:
  I ── PBKDFParamRequest (0x20) ──▶ R      I ── Sigma1 (0x30) ──────────▶ R
  I ◀── PBKDFParamResponse (0x21) ── R      I ◀── Sigma2 (0x31) ────────── R
  I ── Pake1 (0x22) ───────────────▶ R      I ── Sigma3 (0x32) ──────────▶ R
  I ◀── Pake2 (0x23) ─────────────── R      I ◀── StatusReport (0x40) ──── R
  I ── Pake3 (0x24) ───────────────▶ R
  I ◀── StatusReport (0x40) ──────── R
```

## Session Keys

On successful handshake, both sides derive matching keys:

| Key | Size | Purpose |
|-----|------|---------|
| I2RKey | 16 bytes | Encrypt initiator → responder |
| R2IKey | 16 bytes | Encrypt responder → initiator |
| AttestationChallenge | 16 bytes | Device attestation binding |
