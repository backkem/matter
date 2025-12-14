// Package exchange implements Matter message exchange management and reliability.
//
// The exchange layer sits between the session layer (pkg/session) and higher-level
// protocols (SecureChannel, InteractionModel). It provides:
//
//   - Exchange multiplexing: Track multiple concurrent conversations over a session
//   - Message Reliability Protocol (MRP): Retransmissions and acknowledgements for UDP
//   - Protocol dispatch: Route messages to appropriate handlers by Protocol ID
//
// An Exchange represents a single conversation (request/response pair or longer
// transaction) between two nodes. Each exchange is bound to exactly one session
// and identified by the tuple {Session Context, Exchange ID, Exchange Role}.
//
// Spec References:
//   - Section 4.10: Message Exchanges
//   - Section 4.12: Message Reliability Protocol (MRP)
package exchange

// ExchangeRole indicates whether a node is the initiator or responder for an exchange.
//
// IMPORTANT: ExchangeRole is distinct from session.SessionRole!
//   - SessionRole: Who initiated the PASE/CASE session (fixed for session lifetime)
//   - ExchangeRole: Who initiated THIS particular conversation (varies per exchange)
//
// Example: A node that was the responder during CASE session establishment can
// still be the initiator of a new exchange (e.g., starting a Read request).
//
// See Spec Section 4.10.1.
type ExchangeRole int

const (
	// ExchangeRoleUnknown indicates an uninitialized or invalid role.
	ExchangeRoleUnknown ExchangeRole = iota

	// ExchangeRoleInitiator indicates the node that sent the first message
	// in this exchange. The initiator allocates the Exchange ID and sets
	// the I flag in all messages it sends.
	ExchangeRoleInitiator

	// ExchangeRoleResponder indicates the node that received an unsolicited
	// message and is responding. The responder uses the Exchange ID from
	// the initiator and does NOT set the I flag.
	ExchangeRoleResponder
)

// String returns a human-readable name for the exchange role.
func (r ExchangeRole) String() string {
	switch r {
	case ExchangeRoleInitiator:
		return "Initiator"
	case ExchangeRoleResponder:
		return "Responder"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the role is a defined value.
func (r ExchangeRole) IsValid() bool {
	return r == ExchangeRoleInitiator || r == ExchangeRoleResponder
}

// Invert returns the opposite role.
// Used when creating a responder exchange from an incoming initiator message.
func (r ExchangeRole) Invert() ExchangeRole {
	switch r {
	case ExchangeRoleInitiator:
		return ExchangeRoleResponder
	case ExchangeRoleResponder:
		return ExchangeRoleInitiator
	default:
		return ExchangeRoleUnknown
	}
}

// ExchangeState tracks the lifecycle of an exchange.
//
// See Spec Section 4.10.5.3 for closing behavior.
type ExchangeState int

const (
	// ExchangeStateUnknown indicates an uninitialized state.
	ExchangeStateUnknown ExchangeState = iota

	// ExchangeStateActive indicates normal operation.
	// Messages can be sent and received.
	ExchangeStateActive

	// ExchangeStateClosing indicates the exchange is shutting down.
	// Per Spec 4.10.5.3: flush pending ACKs, wait for retransmissions.
	// No new messages accepted, but retransmissions continue.
	ExchangeStateClosing

	// ExchangeStateClosed indicates the exchange is fully terminated.
	// All resources released, no further operations allowed.
	ExchangeStateClosed
)

// String returns a human-readable name for the exchange state.
func (s ExchangeState) String() string {
	switch s {
	case ExchangeStateActive:
		return "Active"
	case ExchangeStateClosing:
		return "Closing"
	case ExchangeStateClosed:
		return "Closed"
	default:
		return "Unknown"
	}
}

// IsValid returns true if the state is a defined value.
func (s ExchangeState) IsValid() bool {
	return s >= ExchangeStateActive && s <= ExchangeStateClosed
}

// CanSend returns true if new messages can be sent in this state.
func (s ExchangeState) CanSend() bool {
	return s == ExchangeStateActive
}

// CanReceive returns true if messages can be received in this state.
func (s ExchangeState) CanReceive() bool {
	return s == ExchangeStateActive || s == ExchangeStateClosing
}
