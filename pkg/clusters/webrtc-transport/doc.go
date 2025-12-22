// Package webrtctransport implements the WebRTC Transport Provider (0x0553)
// and WebRTC Transport Requestor (0x0554) clusters.
//
// These clusters provide WebRTC signaling over Matter, enabling peer-to-peer
// media streaming between Matter nodes. The Provider cluster is typically
// implemented by cameras/devices that produce streams, while the Requestor
// cluster is implemented by controllers/viewers that consume streams.
//
// # Architecture
//
// The clusters act as a "dumb pipe" for WebRTC signaling - they handle the
// Matter protocol encoding/decoding and session management, but delegate
// actual WebRTC operations (PeerConnection, ICE, SDP) to a JSEPDelegate
// provided by the application layer.
//
// # Signaling Flow (Normal/ProvideOffer)
//
//	Controller                              Device
//	──────────                              ──────
//	     │                                     │
//	     │─── ProvideOffer (SDP offer) ───────>│
//	     │<── ProvideOfferResponse ────────────│
//	     │<── Answer (SDP answer) ─────────────│
//	     │                                     │
//	     │─── ProvideICECandidates ───────────>│
//	     │<── ICECandidates ───────────────────│
//	     │                                     │
//	     │<═══ WebRTC Connection ═════════════>│
//
// # References
//
//   - Matter 1.5 Spec Chapter 11.4 (WebRTC Transport)
//   - Matter 1.5 Spec Chapter 11.5 (WebRTC Transport Provider Cluster)
//   - Matter 1.5 Spec Chapter 11.6 (WebRTC Transport Requestor Cluster)
//   - C++ Reference: src/app/clusters/webrtc-transport-provider-server/
package webrtctransport
