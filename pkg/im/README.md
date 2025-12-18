# im

Interaction Model engine for Matter (Spec Chapter 8, 10).

## Architecture

```
                    ┌──────────────────────────────────────────┐
                    │                Engine                     │
                    │                                          │
                    │   OnMessage(header, payload)             │
                    │          │                               │
                    │          ▼                               │
                    │   ┌──────────────────────────────┐       │
                    │   │   Opcode Router              │       │
                    │   │   0x02 → ReadHandler         │       │
                    │   │   0x06 → WriteHandler        │       │
                    │   │   0x08 → InvokeHandler       │       │
                    │   │   0x01 → StatusResponse      │       │
                    │   └──────────────────────────────┘       │
                    │          │                               │
                    │          ▼                               │
                    │   ┌──────────────────────────────┐       │
                    │   │   Dispatcher                 │       │
                    │   │   Routes to cluster impls    │       │
                    │   └──────────────────────────────┘       │
                    └──────────────────────────────────────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    ▼                  ▼                  ▼
             pkg/datamodel       pkg/acl           pkg/exchange
             (Cluster impls)     (ACL checks)      (ExchangeContext)
```

## Usage

### Create Engine

```go
engine := im.NewEngine(im.EngineConfig{
    Dispatcher: myDispatcher,
    ACLChecker: aclChecker,  // optional
    MaxPayload: 1280,        // optional, defaults to 1232
})
```

### Register with Exchange Manager

```go
exchangeManager.RegisterDelegate(im.ProtocolID, engine)
```

### Implement Dispatcher

```go
type MyDispatcher struct {
    router *datamodel.Router
}

func (d *MyDispatcher) ReadAttribute(ctx context.Context, req *im.AttributeReadRequest, w *tlv.Writer) error {
    cluster, err := d.router.GetCluster(req.Path.Endpoint, req.Path.Cluster)
    if err != nil {
        return im.ErrClusterNotFound
    }
    return cluster.ReadAttribute(ctx, req.ToDataModelRequest(), w)
}

func (d *MyDispatcher) WriteAttribute(ctx context.Context, req *im.AttributeWriteRequest, r *tlv.Reader) error {
    // Similar pattern...
}

func (d *MyDispatcher) InvokeCommand(ctx context.Context, req *im.CommandInvokeRequest, r *tlv.Reader) ([]byte, error) {
    // Similar pattern...
}
```

## Message Flow

```
Read:
  C ── ReadRequest (0x02) ──────▶ S
  C ◀── ReportData (0x05) ─────── S
  C ── StatusResponse (0x01) ───▶ S  (if chunked)

Write:
  C ── WriteRequest (0x06) ─────▶ S
  C ◀── WriteResponse (0x07) ──── S

Invoke:
  C ── InvokeRequest (0x08) ────▶ S
  C ◀── InvokeResponse (0x09) ─── S
```

## Handlers

| Handler | Opcode | State Machine |
|---------|--------|---------------|
| ReadHandler | 0x02 | Idle → Processing → SendingReport → Idle |
| WriteHandler | 0x06 | Idle → Processing → Idle |
| InvokeHandler | 0x08 | Idle → Processing → SendingResponse → Idle |

## Error Mapping

| Error | IM Status |
|-------|-----------|
| ErrClusterNotFound | UnsupportedCluster (0xC3) |
| ErrAttributeNotFound | UnsupportedAttribute (0x86) |
| ErrCommandNotFound | UnsupportedCommand (0x81) |
| ErrAccessDenied | UnsupportedAccess (0x7E) |
| ErrConstraintError | ConstraintError (0x87) |

## Chunking

Large payloads are split across multiple messages:

```go
// Assembler: receive chunked request
assembler := im.NewAssembler(im.ChunkTypeInvokeRequest)
for msg := range incomingMessages {
    complete, err := assembler.AddChunk(msg)
    if complete {
        fullPayload := assembler.Data()
        // Process complete request
    }
}

// Fragmenter: send chunked response
fragmenter := im.NewFragmenter(im.ChunkTypeInvokeResponse, maxPayload)
chunks := fragmenter.Fragment(largeResponse)
for _, chunk := range chunks {
    send(chunk)
    waitForStatusResponse()
}
```

## Events

```go
// Publish event
mgr := im.NewEventManager(im.EventManagerConfig{MaxEvents: 100})
mgr.PublishEvent(im.EventRecord{
    Path:        im.EventPath{Endpoint: 0, Cluster: 0x0028, Event: 0},
    EventNumber: mgr.NextEventNumber(),
    Priority:    im.EventPriorityCritical,
    Timestamp:   time.Now(),
    Data:        eventData,
})

// Build unsolicited report
reporter := im.NewEventReporter(mgr)
report := reporter.BuildUnsolicitedReport(fabricIndex, []im.EventPath{...})
```

## Test Infrastructure

### SecureTestIMPair

Two connected IM engines with encrypted sessions for E2E testing.

```
  Client (0)                          Server (1)
  ──────────                          ──────────
  im.Client                           im.Engine
      │                                   │
      ▼                                   ▼
  exchange.Manager ◀──── Pipe ────▶ exchange.Manager
      │                                   │
      ▼                                   ▼
  SecureContext(1,2)               SecureContext(2,1)
```

```go
pair, _ := im.NewSecureTestIMPair(im.SecureTestIMPairConfig{
    Dispatchers: [2]im.Dispatcher{nil, mockDispatcher},
})
defer pair.Close()

// Client sends InvokeRequest to Server
result, err := pair.Client(0).InvokeWithStatus(
    ctx,
    pair.Session(0),     // Client's secure session
    pair.PeerAddress(1), // Server's address
    1, 0x0006, 0x01,     // Endpoint, Cluster, Command
    nil,
)

// Verify server received
calls := mockDispatcher.InvokeCalls()
```

### MockDispatcher

Records IM operations for test verification.

```go
mock := im.NewMockDispatcher()

// Configure responses
mock.SetInvokeResult(responseData, nil)
mock.SetReadResult(true, nil)

// After test
calls := mock.InvokeCalls()   // []InvokeCall
reads := mock.ReadCalls()     // []ReadCall
mock.Reset()
```

### Bidirectional

```go
pair, _ := im.NewSecureTestIMPair(im.SecureTestIMPairConfig{
    Dispatchers: [2]im.Dispatcher{mockClient, mockServer},
})

// Client → Server
pair.Client(0).InvokeWithStatus(ctx, pair.Session(0), pair.PeerAddress(1), ...)

// Server → Client
pair.Client(1).InvokeWithStatus(ctx, pair.Session(1), pair.PeerAddress(0), ...)
```
