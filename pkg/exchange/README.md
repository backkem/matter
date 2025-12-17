# exchange

Exchange Manager with integrated MRP (Spec Section 4.10, 4.12).

## Architecture

```
              ┌──────────────────────────────────────────────────┐
              │                  Manager                         │
              │                                                  │
              │  OnMessageReceived(msg)                          │
              │         │                                        │
              │         ▼                                        │
              │  ┌─────────────────────────────────────────┐     │
              │  │ Exchange Matching (Spec 4.10.5.1)       │     │
              │  │ Key: {sessionID, exchangeID, role}      │     │
              │  └─────────────────────────────────────────┘     │
              │         │                                        │
              │    ┌────┴────┐                                   │
              │    ▼         ▼                                   │
              │ Existing   Unsolicited                           │
              │ Exchange   → Create new                          │
              │    │         │                                   │
              │    └────┬────┘                                   │
              │         ▼                                        │
              │  ┌─────────────────────────────────────────┐     │
              │  │ MRP Processing                          │     │
              │  │ A flag → AckTable.Remove()              │     │
              │  │ R flag → AckTable.Add() + timer         │     │
              │  └─────────────────────────────────────────┘     │
              │         │                                        │
              │         ▼                                        │
              │  ProtocolHandler.OnMessage()                     │
              └──────────────────────────────────────────────────┘
                        │
       ┌────────────────┼────────────────┐
       ▼                ▼                ▼
  pkg/session     pkg/transport   pkg/securechannel
  (Encrypt/       (Send/Recv)     (ProtocolHandler)
   Decrypt)
```

## Usage

### Create Manager

```go
mgr := exchange.NewManager(exchange.ManagerConfig{
    SessionManager:   sessionMgr,
    TransportManager: transportMgr,
})
```

### Register Protocol Handlers

```go
mgr.RegisterProtocol(message.ProtocolSecureChannel, scHandler)
mgr.RegisterProtocol(message.ProtocolInteractionModel, imHandler)
```

### Create Exchange (Initiator)

```go
ctx, err := mgr.NewExchange(session, localSessionID, peerAddr, protocolID, delegate)
ctx.SendMessage(opcode, payload, reliable)
```

### Handle Incoming Messages

```go
// Wire to transport callback
transportMgr.SetMessageHandler(func(msg *transport.ReceivedMessage) {
    mgr.OnMessageReceived(msg)
})
```

## MRP Parameters (Table 22)

| Parameter | Value | Description |
|-----------|-------|-------------|
| MRP_MAX_TRANSMISSIONS | 5 | Max send attempts |
| MRP_BACKOFF_BASE | 1.6 | Exponential base |
| MRP_BACKOFF_JITTER | 0.25 | Random jitter range |
| MRP_BACKOFF_MARGIN | 1.1 | Margin over peer interval |
| MRP_BACKOFF_THRESHOLD | 1 | Linear→exponential transition |
| MRP_STANDALONE_ACK_TIMEOUT | 200ms | Piggyback wait time |

## Backoff Timing (Table 21)

With 300ms base interval:

| Attempt | Min | Max | Cumulative Max |
|---------|-----|-----|----------------|
| 0 | 330ms | 413ms | 413ms |
| 1 | 330ms | 413ms | 825ms |
| 2 | 528ms | 660ms | 1485ms |
| 3 | 845ms | 1056ms | 2541ms |
| 4 | 1352ms | 1690ms | 4231ms |

## Exchange Lifecycle

```
Initiator:                              Responder:
  NewExchange()                           (unsolicited msg)
       │                                        │
       ▼                                        ▼
  ┌─────────┐    SendMessage()          ┌─────────┐
  │ Active  │ ◀────────────────────────▶│ Active  │
  └─────────┘    OnMessage()            └─────────┘
       │                                        │
       │ Close()                                │
       ▼                                        ▼
  ┌─────────┐    (flush ACKs,           ┌─────────┐
  │ Closing │     wait retransmit)      │ Closing │
  └─────────┘                           └─────────┘
       │                                        │
       ▼                                        ▼
  ┌─────────┐                           ┌─────────┐
  │ Closed  │                           │ Closed  │
  └─────────┘                           └─────────┘
```

## TestManagerPair for Testing

Two connected exchange managers for E2E tests without real network I/O.

```
  Manager 0                              Manager 1
  ─────────                              ─────────
      │                                      │
      ▼                                      ▼
  NewExchange()                         ProtocolHandler
      │                                      ▲
      │ SendMessage()                        │ OnUnsolicited()
      ▼                                      │
  transport ──────► Pipe ──────► transport ──┘
```

### Basic Usage

```go
pair, _ := NewTestManagerPair(TestManagerPairConfig{})
defer pair.Close()

// Manager 0 sends to Manager 1
ctx, _ := pair.Manager(0).NewExchange(
    pair.Session(0), 0, pair.PeerAddress(1, false),
    message.ProtocolSecureChannel, nil,
)
ctx.SendMessage(0x20, []byte("hello"), false)

// Wait for Manager 1's handler to receive
msg, ok := pair.WaitForMessage(1, time.Second)
// msg.Opcode, msg.Payload, msg.Unsolicited
```

### TCP Transport

```go
pair, _ := NewTestManagerPair(TestManagerPairConfig{
    UDP: false,
    TCP: true,
})
defer pair.Close()

ctx, _ := pair.Manager(0).NewExchange(
    pair.Session(0), 0, pair.PeerAddress(1, true), // tcp=true
    message.ProtocolSecureChannel, nil,
)
```

### Bidirectional

```go
// 0 → 1
ctx0, _ := pair.Manager(0).NewExchange(pair.Session(0), 0, pair.PeerAddress(1, false), ...)
ctx0.SendMessage(0x01, []byte("ping"), false)
msg1, _ := pair.WaitForMessage(1, time.Second)

// 1 → 0
ctx1, _ := pair.Manager(1).NewExchange(pair.Session(1), 0, pair.PeerAddress(0, false), ...)
ctx1.SendMessage(0x02, []byte("pong"), false)
msg0, _ := pair.WaitForMessage(0, time.Second)
```
