package exchange

import "errors"

// Errors returned by the exchange package.
var (
	// ErrExchangeClosed is returned when attempting operations on a closed exchange.
	ErrExchangeClosed = errors.New("exchange: exchange is closed")

	// ErrExchangeClosing is returned when attempting to send on a closing exchange.
	ErrExchangeClosing = errors.New("exchange: exchange is closing")

	// ErrNoHandler is returned when no protocol handler is registered for a message.
	ErrNoHandler = errors.New("exchange: no handler registered for protocol")

	// ErrExchangeExists is returned when trying to create a duplicate exchange.
	ErrExchangeExists = errors.New("exchange: exchange already exists")

	// ErrExchangeNotFound is returned when an exchange cannot be found.
	ErrExchangeNotFound = errors.New("exchange: exchange not found")

	// ErrSessionNotFound is returned when a session cannot be found for a message.
	ErrSessionNotFound = errors.New("exchange: session not found")

	// ErrInvalidRole is returned for invalid exchange role values.
	ErrInvalidRole = errors.New("exchange: invalid exchange role")

	// ErrPendingRetransmit is returned when trying to send while a retransmit is pending.
	// Per Spec 4.10: Exchange layer SHALL NOT accept a message from upper layer
	// when there is an outbound reliable message pending.
	ErrPendingRetransmit = errors.New("exchange: reliable message pending")

	// ErrMaxRetransmits is returned when max retransmissions exceeded without ACK.
	ErrMaxRetransmits = errors.New("exchange: max retransmissions exceeded")

	// ErrDuplicateMessage is returned for duplicate messages (already processed).
	ErrDuplicateMessage = errors.New("exchange: duplicate message")

	// ErrInvalidMessage is returned for malformed or invalid messages.
	ErrInvalidMessage = errors.New("exchange: invalid message")

	// ErrUnsolicitedNotInitiator is returned for unsolicited messages without I flag.
	ErrUnsolicitedNotInitiator = errors.New("exchange: unsolicited message must have I flag set")
)
