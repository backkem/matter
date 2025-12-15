# message

TLV wire encoding for Interaction Model messages (Spec Chapter 10).

## Message Types

| Opcode | Message | Direction |
|--------|---------|-----------|
| 0x01 | StatusResponseMessage | Both |
| 0x02 | ReadRequestMessage | C → S |
| 0x03 | SubscribeRequestMessage | C → S |
| 0x04 | SubscribeResponseMessage | S → C |
| 0x05 | ReportDataMessage | S → C |
| 0x06 | WriteRequestMessage | C → S |
| 0x07 | WriteResponseMessage | S → C |
| 0x08 | InvokeRequestMessage | C → S |
| 0x09 | InvokeResponseMessage | S → C |
| 0x0A | TimedRequestMessage | C → S |

## Path IBs

Path Information Blocks identify targets. Encoded as TLV Lists (0x17).

```go
// Attribute path (wildcard: nil fields)
path := message.AttributePathIB{
    Endpoint:  message.Ptr(message.EndpointID(1)),
    Cluster:   message.Ptr(message.ClusterID(0x0006)),
    Attribute: message.Ptr(message.AttributeID(0)),
}

// Command path (concrete only)
cmdPath := message.CommandPathIB{
    Endpoint: 1,
    Cluster:  0x0006,
    Command:  2,
}

// Event path
eventPath := message.EventPathIB{
    Endpoint: message.Ptr(message.EndpointID(0)),
    Cluster:  message.Ptr(message.ClusterID(0x0028)),
    Event:    message.Ptr(message.EventID(0)),
}
```

## Data IBs

| IB | Contains |
|----|----------|
| StatusIB | Status code + optional ClusterStatus |
| AttributeDataIB | Path + DataVersion + Data |
| AttributeStatusIB | Path + StatusIB |
| AttributeReportIB | AttributeData OR AttributeStatus |
| CommandDataIB | Path + Fields + optional Ref |
| CommandStatusIB | Path + StatusIB |
| InvokeResponseIB | Command OR Status |
| EventDataIB | Path + EventNumber + Priority + Timestamps + Data |

## Usage

### Encode Message

```go
req := &message.InvokeRequestMessage{
    SuppressResponse: false,
    TimedRequest:     false,
    InvokeRequests: []message.CommandDataIB{
        {
            Path: message.CommandPathIB{
                Endpoint: 1,
                Cluster:  0x0006,
                Command:  2, // Toggle
            },
        },
    },
}

var buf bytes.Buffer
w := tlv.NewWriter(&buf)
if err := req.Encode(w); err != nil {
    return err
}
encoded := buf.Bytes()
```

### Decode Message

```go
r := tlv.NewReader(bytes.NewReader(data))
var msg message.InvokeRequestMessage
if err := msg.Decode(r); err != nil {
    return err
}
```

## Status Codes

Key status codes (Spec 8.10):

| Code | Value | Meaning |
|------|-------|---------|
| Success | 0x00 | Operation succeeded |
| Failure | 0x01 | Generic failure |
| UnsupportedAccess | 0x7E | ACL denied |
| InvalidAction | 0x80 | Malformed request |
| UnsupportedCommand | 0x81 | Command not found |
| UnsupportedAttribute | 0x86 | Attribute not found |
| ConstraintError | 0x87 | Value constraint violated |
| UnsupportedWrite | 0x88 | Attribute is read-only |
| UnsupportedCluster | 0xC3 | Cluster not found |
| NeedsTimedInteraction | 0xC6 | Timed request required |

## TLV Encoding

Messages use anonymous structure tags (0x15). Paths use list tags (0x17).

```
InvokeRequestMessage:
  0x15                    // Struct start (anonymous)
    0x28 0x00             // Tag 0: SuppressResponse = false
    0x28 0x01             // Tag 1: TimedRequest = false
    0x36 0x02             // Tag 2: InvokeRequests array
      0x15                // CommandDataIB struct
        0x37 0x00         // Tag 0: CommandPath list
          ...
        0x18              // End CommandPath
      0x18                // End CommandDataIB
    0x18                  // End array
  0x18                    // End struct
```
