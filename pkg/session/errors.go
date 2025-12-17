package session

import "errors"

// Session package errors.
var (
	// ErrInvalidSessionType is returned when the session type is not PASE or CASE.
	ErrInvalidSessionType = errors.New("session: invalid session type")

	// ErrInvalidRole is returned when the session role is not Initiator or Responder.
	ErrInvalidRole = errors.New("session: invalid session role")

	// ErrInvalidKey is returned when an encryption key has invalid length.
	ErrInvalidKey = errors.New("session: invalid key length")

	// ErrInvalidSessionID is returned when a session ID is invalid (0 for secure sessions).
	ErrInvalidSessionID = errors.New("session: invalid session ID")

	// ErrSessionNotFound is returned when a session lookup fails.
	ErrSessionNotFound = errors.New("session: session not found")

	// ErrSessionTableFull is returned when no more sessions can be allocated.
	ErrSessionTableFull = errors.New("session: session table full")

	// ErrSessionIDExhausted is returned when no more session IDs are available.
	ErrSessionIDExhausted = errors.New("session: session ID space exhausted")

	// ErrDuplicateSession is returned when adding a session with an existing ID.
	ErrDuplicateSession = errors.New("session: duplicate session ID")

	// ErrCounterExhausted is returned when the message counter has wrapped.
	// The session must be re-established when this occurs.
	ErrCounterExhausted = errors.New("session: message counter exhausted")

	// ErrReplayDetected is returned when an incoming message counter indicates replay.
	ErrReplayDetected = errors.New("session: replay detected")

	// ErrDecryptionFailed is returned when message decryption fails.
	ErrDecryptionFailed = errors.New("session: decryption failed")

	// ErrGroupPeerTableFull is returned when no more group peers can be tracked.
	ErrGroupPeerTableFull = errors.New("session: group peer table full")

	// ErrInvalidNodeID is returned when a node ID is invalid (0 for unsecured sessions).
	ErrInvalidNodeID = errors.New("session: invalid node ID")
)
