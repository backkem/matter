package transport

// TransportType identifies the transport protocol used for a message.
type TransportType int

const (
	// TransportTypeUnknown is the zero value for unknown transport.
	TransportTypeUnknown TransportType = iota
	// TransportTypeUDP indicates UDP transport.
	TransportTypeUDP
	// TransportTypeTCP indicates TCP transport.
	TransportTypeTCP
)

// String returns the string representation of the transport type.
func (t TransportType) String() string {
	switch t {
	case TransportTypeUDP:
		return "UDP"
	case TransportTypeTCP:
		return "TCP"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the transport type is a known valid type.
func (t TransportType) IsValid() bool {
	return t == TransportTypeUDP || t == TransportTypeTCP
}
