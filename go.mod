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
	github.com/miekg/dns v1.1.41 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)

// Use local modified zeroconf with bug fixes
replace github.com/grandcat/zeroconf => ../zeroconf
