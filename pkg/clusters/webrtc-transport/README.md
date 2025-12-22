# webrtc-transport

WebRTC Transport Provider (0x0553) and Requestor (0x0554) clusters for Matter camera streaming (Spec Section 11.4).

## Architecture

```
Controller (Requestor)                    Device (Provider)
──────────────────────                    ─────────────────
       │                                         │
       │  ProvideOffer (SDP offer)               │
       ├────────────────────────────────────────▶│
       │                                         │ OnOfferReceived()
       │  ProvideOfferResponse (session ID)      │
       │◀────────────────────────────────────────┤
       │                                         │
       │  Answer (via Requestor cluster)         │
       │◀────────────────────────────────────────┤
       │                                         │
       │  ICECandidates (trickle ICE)            │
       │◀───────────────────────────────────────▶│
       │                                         │
       ▼                                         ▼
  PeerConnection ◀═══════ WebRTC ════════▶ PeerConnection
```

## Clusters

| Cluster | ID | Role | Commands |
|---------|------|------|----------|
| Provider | 0x0553 | Device/Camera | SolicitOffer, ProvideOffer, ProvideAnswer, ProvideICECandidates, EndSession |
| Requestor | 0x0554 | Controller | Offer, Answer, ICECandidates, End |

## Usage

### Device (Provider)

```go
delegate := &MyProviderDelegate{}
provider := webrtctransport.NewProvider(webrtctransport.ProviderConfig{
    EndpointID: 1,
    Delegate:   delegate,
})
endpoint.AddCluster(provider)
```

### Controller (Client-side encoding)

```go
// Encode ProvideOffer command
payload, _ := webrtctransport.EncodeProvideOffer(
    nil,                                    // new session
    sdpOffer,                               // SDP
    webrtctransport.StreamUsageLiveView,   // usage
    1,                                      // originating endpoint
    nil, nil,                               // stream IDs
    nil,                                    // ICE servers
    "",                                     // transport policy
    false,                                  // metadata
)

// Send via IM layer
result, _ := controller.SendCommand(ctx, session, addr, endpoint,
    webrtctransport.ProviderClusterID, webrtctransport.CmdProvideOffer, payload)

// Decode response
sessionID, videoID, audioID, _ := webrtctransport.DecodeProvideOfferResponse(result.ResponseData)
```

## Types

| Type | Description |
|------|-------------|
| `StreamUsageEnum` | Internal, Recording, Analysis, LiveView |
| `WebRTCEndReasonEnum` | ICEFailed, ICETimeout, UserHangup, ... |
| `ICEServerStruct` | STUN/TURN server config |
| `ICECandidateStruct` | ICE candidate with SDP attributes |
| `WebRTCSessionStruct` | Session state (fabric-scoped) |

## Signaling Flow

```
ProvideOffer Flow:
  C ── ProvideOffer (0x02) ─────────▶ D
  C ◀── ProvideOfferResponse (0x03) ── D
  C ◀── Answer (Requestor 0x01) ────── D
  C ◀─▶ ICECandidates ─────────────▶ D

SolicitOffer Flow:
  C ── SolicitOffer (0x00) ─────────▶ D
  C ◀── SolicitOfferResponse (0x01) ── D
  C ◀── Offer (Requestor 0x00) ─────── D
  C ── ProvideAnswer (0x04) ────────▶ D
  C ◀─▶ ICECandidates ─────────────▶ D
```

## Session Management

Sessions are fabric-scoped and tracked by both clusters:

```go
// Provider side
session := provider.GetSession(sessionID)
provider.EndSession(ctx, sessionID, webrtctransport.WebRTCEndReasonUserHangup)

// Requestor side
requestor.AddSession(session)
requestor.RemoveSession(sessionID)
```
