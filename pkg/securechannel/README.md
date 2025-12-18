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

## E2E Testing

Two paired `Manager` instances for deterministic handshake testing without real network I/O.

```
  Controller Manager                     Device Manager
  ──────────────────                     ──────────────
        │                                      │
        ▼                                      ▼
    StartPASE()                        SetPASEResponder()
        │                                      │
        │  PBKDFParamRequest                   │
        ├─────────────────────────────────────▶│
        │                                      │ Route()
        │  PBKDFParamResponse                  │
        │◀─────────────────────────────────────┤
  Route()                                      │
        │  Pake1                               │
        ├─────────────────────────────────────▶│
        │                             Route()  │
        │  Pake2                               │
        │◀─────────────────────────────────────┤
  Route()                                      │
        │  Pake3                               │
        ├─────────────────────────────────────▶│
        │                             Route()  │
        │  StatusReport                        │
        │◀─────────────────────────────────────┤
  Route()                                      │
        │                                      │
        ▼                                      ▼
  OnSessionEstablished()              OnSessionEstablished()
```

### PASE E2E Test

```go
// Setup
verifier, _ := pase.GenerateVerifier(passcode, salt, iterations)
controllerMgr := NewManager(ManagerConfig{SessionManager: controllerSessionMgr})
deviceMgr := NewManager(ManagerConfig{SessionManager: deviceSessionMgr})
deviceMgr.SetPASEResponder(verifier, salt, iterations)

// Handshake
exchangeID := uint16(1)
pbkdfReq, _ := controllerMgr.StartPASE(exchangeID, passcode)
pbkdfRespMsg, _ := deviceMgr.Route(exchangeID, &Message{OpcodePBKDFParamRequest, pbkdfReq})
pake1Msg, _ := controllerMgr.Route(exchangeID, &Message{OpcodePBKDFParamResponse, pbkdfRespMsg.Payload})
pake2Msg, _ := deviceMgr.Route(exchangeID, &Message{OpcodePASEPake1, pake1Msg.Payload})
pake3Msg, _ := controllerMgr.Route(exchangeID, &Message{OpcodePASEPake2, pake2Msg.Payload})
statusMsg, _ := deviceMgr.Route(exchangeID, &Message{OpcodePASEPake3, pake3Msg.Payload})
_, _ = controllerMgr.Route(exchangeID, &Message{OpcodeStatusReport, statusMsg.Payload})
// Both sides now have SecureContext with matching keys
```

### CASE E2E Test

```go
// Setup with fabric credentials
initiatorFabric, initiatorKey := createTestFabricInfo(t, fabricID, initiatorNodeID)
responderFabric, responderKey := createTestFabricInfo(t, fabricID, responderNodeID)

initiatorMgr := NewManager(ManagerConfig{
    SessionManager: initiatorSessionMgr,
    CertValidator:  certValidator,
    LocalNodeID:    initiatorNodeID,
})

responderCASE := casesession.NewResponder(fabricLookup, nil)
responderCASE.WithCertValidator(certValidator)

// Handshake
sigma1, _ := initiatorMgr.StartCASE(exchangeID, initiatorFabric, initiatorKey, responderNodeID, nil)
sigma2, _, _ := responderCASE.HandleSigma1(sigma1, responderLocalSessionID)
sigma3Msg, _ := initiatorMgr.Route(exchangeID, &Message{OpcodeCASESigma2, sigma2})
_ = responderCASE.HandleSigma3(sigma3Msg.Payload)
_, _ = initiatorMgr.Route(exchangeID, &Message{OpcodeStatusReport, Success().Encode()})
```

### Negative Tests

| Test | Scenario | Expected |
|------|----------|----------|
| WrongPasscode | Controller uses wrong passcode | `ErrConfirmationFailed` at Pake2 |
| CorruptedTLV | Malformed TLV in message | Decode error |
| TruncatedMessage | Empty/short payload | EOF or decode error |
| WindowClosed | No PASE responder configured | `PASE responder not configured` |
| InvalidState | Message in wrong state | `ErrInvalidState` |
| NoSharedRoot | Different fabric roots | `ErrNoSharedRoot` |
| ConfirmationMismatch | Corrupted Pake3 cA | `ErrConfirmationFailed` |

### Key Verification

```go
// Direct PASE session comparison
initiator, _ := pase.NewInitiator(passcode)
responder, _ := pase.NewResponder(verifier, salt, iterations)
// ... complete handshake ...

initiatorKeys := initiator.SessionKeys()
responderKeys := responder.SessionKeys()
// I2RKey, R2IKey, AttestationChallenge all match
```

### Encryption Round-Trip

```go
// After handshake, verify keys work with message.Codec
codec, _ := message.NewCodec(keys.I2RKey[:], 0)
encrypted, _ := codec.Encode(header, protocol, payload, false)
decrypted, _ := codec.Decode(encrypted, 0)
// decrypted.Payload == payload
```
