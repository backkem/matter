// Package session implements Matter session context management.
//
// This package provides the security context layer that sits between raw network
// transport and the exchange layer. It stores session state (IDs, keys, counters)
// and handles encryption/decryption of message payloads.
//
// The package manages three types of session contexts:
//   - UnsecuredContext: For PASE/CASE handshake phase (no encryption)
//   - SecureContext: For established PASE/CASE sessions (encrypted unicast)
//   - GroupContext: For group messages (encrypted multicast)
//
// Spec References:
//   - Section 4.13: Unicast Communication
//   - Section 4.13.2.1: Unsecured Session Context
//   - Section 4.13.3.1: Secure Session Context
//   - Section 4.16.1: Groupcast Session Context
//   - Section 4.6: Message Counters
//   - Section 4.8: Message Security
package session

// SessionType identifies whether a session was established using PASE or CASE.
// This affects nonce construction for message encryption.
// See Spec Section 4.13.3.1 field 1.
type SessionType int

const (
	// SessionTypeUnknown indicates an uninitialized or invalid session type.
	SessionTypeUnknown SessionType = iota

	// SessionTypePASE indicates a Passcode-Authenticated Session Establishment.
	// PASE sessions use NodeID=0 in the encryption nonce.
	SessionTypePASE

	// SessionTypeCASE indicates a Certificate Authenticated Session Establishment.
	// CASE sessions use the actual peer NodeID in the encryption nonce.
	SessionTypeCASE
)

// String returns a human-readable name for the session type.
func (s SessionType) String() string {
	switch s {
	case SessionTypePASE:
		return "PASE"
	case SessionTypeCASE:
		return "CASE"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the session type is a defined value.
func (s SessionType) IsValid() bool {
	return s == SessionTypePASE || s == SessionTypeCASE
}

// SessionRole identifies whether the local node was the initiator or responder
// during session establishment. This determines which encryption key to use.
// See Spec Section 4.13.3.1 field 2.
type SessionRole int

const (
	// SessionRoleUnknown indicates an uninitialized or invalid role.
	SessionRoleUnknown SessionRole = iota

	// SessionRoleInitiator indicates the node that initiated the session.
	// Initiators use I2RKey for encryption and R2IKey for decryption.
	SessionRoleInitiator

	// SessionRoleResponder indicates the node that responded to session initiation.
	// Responders use R2IKey for encryption and I2RKey for decryption.
	SessionRoleResponder
)

// String returns a human-readable name for the session role.
func (r SessionRole) String() string {
	switch r {
	case SessionRoleInitiator:
		return "Initiator"
	case SessionRoleResponder:
		return "Responder"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the session role is a defined value.
func (r SessionRole) IsValid() bool {
	return r == SessionRoleInitiator || r == SessionRoleResponder
}
