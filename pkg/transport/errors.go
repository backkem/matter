package transport

import "errors"

// Transport errors.
var (
	// ErrClosed is returned when an operation is attempted on a closed transport.
	ErrClosed = errors.New("transport: closed")

	// ErrInvalidAddress is returned when an invalid peer address is provided.
	ErrInvalidAddress = errors.New("transport: invalid address")

	// ErrNoHandler is returned when no message handler is configured.
	ErrNoHandler = errors.New("transport: no message handler configured")

	// ErrNotStarted is returned when an operation requires a started transport.
	ErrNotStarted = errors.New("transport: not started")

	// ErrAlreadyStarted is returned when Start is called on an already running transport.
	ErrAlreadyStarted = errors.New("transport: already started")

	// ErrConnectionNotFound is returned when no connection exists for a peer address.
	ErrConnectionNotFound = errors.New("transport: connection not found for peer")

	// ErrSendFailed is returned when sending a message fails.
	ErrSendFailed = errors.New("transport: send failed")

	// ErrMessageTooLarge is returned when a message exceeds the maximum size.
	ErrMessageTooLarge = errors.New("transport: message too large")
)
