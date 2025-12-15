package im

import (
	"errors"

	"github.com/backkem/matter/pkg/im/message"
)

// IM engine errors.
var (
	// ErrClusterNotFound indicates the cluster doesn't exist on the endpoint.
	ErrClusterNotFound = errors.New("im: cluster not found")

	// ErrAttributeNotFound indicates the attribute doesn't exist on the cluster.
	ErrAttributeNotFound = errors.New("im: attribute not found")

	// ErrCommandNotFound indicates the command doesn't exist on the cluster.
	ErrCommandNotFound = errors.New("im: command not found")

	// ErrAccessDenied indicates ACL check failed.
	ErrAccessDenied = errors.New("im: access denied")

	// ErrUnsupportedWrite indicates the attribute doesn't support writes.
	ErrUnsupportedWrite = errors.New("im: unsupported write")

	// ErrUnsupportedRead indicates the attribute doesn't support reads.
	ErrUnsupportedRead = errors.New("im: unsupported read")

	// ErrConstraintError indicates a constraint violation (e.g., invalid value).
	ErrConstraintError = errors.New("im: constraint error")

	// ErrDataVersionMismatch indicates optimistic lock failure.
	ErrDataVersionMismatch = errors.New("im: data version mismatch")

	// ErrNeedsTimedInteraction indicates the operation requires a timed interaction.
	ErrNeedsTimedInteraction = errors.New("im: needs timed interaction")

	// ErrInvalidPath indicates the path is malformed or has wildcard when not allowed.
	ErrInvalidPath = errors.New("im: invalid path")

	// ErrBusy indicates the engine is busy and cannot process the request.
	ErrBusy = errors.New("im: busy")

	// ErrResourceExhausted indicates resource limits exceeded.
	ErrResourceExhausted = errors.New("im: resource exhausted")
)

// ErrorToStatus maps an error to an IM status code.
// This follows the Matter spec mapping of errors to status codes.
func ErrorToStatus(err error) message.Status {
	if err == nil {
		return message.StatusSuccess
	}

	switch {
	case errors.Is(err, ErrClusterNotFound):
		return message.StatusUnsupportedCluster
	case errors.Is(err, ErrAttributeNotFound):
		return message.StatusUnsupportedAttribute
	case errors.Is(err, ErrCommandNotFound):
		return message.StatusUnsupportedCommand
	case errors.Is(err, ErrAccessDenied):
		return message.StatusUnsupportedAccess
	case errors.Is(err, ErrUnsupportedWrite):
		return message.StatusUnsupportedWrite
	case errors.Is(err, ErrUnsupportedRead):
		return message.StatusUnsupportedRead
	case errors.Is(err, ErrConstraintError):
		return message.StatusConstraintError
	case errors.Is(err, ErrDataVersionMismatch):
		return message.StatusDataVersionMismatch
	case errors.Is(err, ErrNeedsTimedInteraction):
		return message.StatusNeedsTimedInteraction
	case errors.Is(err, ErrInvalidPath):
		return message.StatusInvalidAction
	case errors.Is(err, ErrBusy):
		return message.StatusBusy
	case errors.Is(err, ErrResourceExhausted):
		return message.StatusResourceExhausted
	default:
		return message.StatusFailure
	}
}

// StatusToError maps an IM status code to an error.
func StatusToError(status message.Status) error {
	switch status {
	case message.StatusSuccess:
		return nil
	case message.StatusUnsupportedCluster:
		return ErrClusterNotFound
	case message.StatusUnsupportedAttribute:
		return ErrAttributeNotFound
	case message.StatusUnsupportedCommand:
		return ErrCommandNotFound
	case message.StatusUnsupportedAccess:
		return ErrAccessDenied
	case message.StatusUnsupportedWrite:
		return ErrUnsupportedWrite
	case message.StatusUnsupportedRead:
		return ErrUnsupportedRead
	case message.StatusConstraintError:
		return ErrConstraintError
	case message.StatusDataVersionMismatch:
		return ErrDataVersionMismatch
	case message.StatusNeedsTimedInteraction:
		return ErrNeedsTimedInteraction
	case message.StatusInvalidAction:
		return ErrInvalidPath
	case message.StatusBusy:
		return ErrBusy
	case message.StatusResourceExhausted:
		return ErrResourceExhausted
	default:
		return errors.New("im: " + status.String())
	}
}
