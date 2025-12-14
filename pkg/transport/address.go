package transport

import (
	"fmt"
	"net"
)

// PeerAddress identifies a remote peer by network address and transport type.
type PeerAddress struct {
	// Addr is the network address of the peer.
	Addr net.Addr
	// TransportType identifies the transport protocol (UDP or TCP).
	TransportType TransportType
}

// String returns a human-readable representation of the peer address.
func (p PeerAddress) String() string {
	if p.Addr == nil {
		return fmt.Sprintf("%s:<nil>", p.TransportType)
	}
	return fmt.Sprintf("%s:%s", p.TransportType, p.Addr.String())
}

// IsValid returns true if the peer address has a valid transport type and address.
func (p PeerAddress) IsValid() bool {
	return p.TransportType.IsValid() && p.Addr != nil
}

// NewUDPPeerAddress creates a PeerAddress for a UDP peer.
func NewUDPPeerAddress(addr net.Addr) PeerAddress {
	return PeerAddress{
		Addr:          addr,
		TransportType: TransportTypeUDP,
	}
}

// NewTCPPeerAddress creates a PeerAddress for a TCP peer.
func NewTCPPeerAddress(addr net.Addr) PeerAddress {
	return PeerAddress{
		Addr:          addr,
		TransportType: TransportTypeTCP,
	}
}

// UDPAddrFromString parses an address string and creates a UDP PeerAddress.
func UDPAddrFromString(addr string) (PeerAddress, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return PeerAddress{}, err
	}
	return NewUDPPeerAddress(udpAddr), nil
}

// TCPAddrFromString parses an address string and creates a TCP PeerAddress.
func TCPAddrFromString(addr string) (PeerAddress, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return PeerAddress{}, err
	}
	return NewTCPPeerAddress(tcpAddr), nil
}
