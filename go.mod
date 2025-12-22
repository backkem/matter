module github.com/backkem/matter

go 1.25.1

require (
	github.com/grandcat/zeroconf v1.0.1-0.20230119201135-e4f60f8407b1
	github.com/pion/logging v0.2.4
	github.com/pion/transport/v3 v3.1.1
	golang.org/x/crypto v0.46.0
)

require (
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/miekg/dns v1.1.41 // indirect
	github.com/pion/datachannel v1.5.10 // indirect
	github.com/pion/dtls/v3 v3.0.8 // indirect
	github.com/pion/ice/v4 v4.0.13 // indirect
	github.com/pion/interceptor v0.1.42 // indirect
	github.com/pion/mdns/v2 v2.1.0 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.16 // indirect
	github.com/pion/rtp v1.8.26 // indirect
	github.com/pion/sctp v1.8.41 // indirect
	github.com/pion/sdp/v3 v3.0.16 // indirect
	github.com/pion/srtp/v3 v3.0.9 // indirect
	github.com/pion/stun/v3 v3.0.2 // indirect
	github.com/pion/turn/v4 v4.1.3 // indirect
	github.com/pion/webrtc/v4 v4.1.8 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)

// Use local modified zeroconf with bug fixes
replace github.com/grandcat/zeroconf => ../zeroconf
