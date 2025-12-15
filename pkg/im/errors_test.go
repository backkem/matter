package im

import (
	"errors"
	"testing"

	"github.com/backkem/matter/pkg/im/message"
)

func TestErrorToStatus(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		want   message.Status
	}{
		{"nil error", nil, message.StatusSuccess},
		{"cluster not found", ErrClusterNotFound, message.StatusUnsupportedCluster},
		{"attribute not found", ErrAttributeNotFound, message.StatusUnsupportedAttribute},
		{"command not found", ErrCommandNotFound, message.StatusUnsupportedCommand},
		{"access denied", ErrAccessDenied, message.StatusUnsupportedAccess},
		{"unsupported write", ErrUnsupportedWrite, message.StatusUnsupportedWrite},
		{"unsupported read", ErrUnsupportedRead, message.StatusUnsupportedRead},
		{"constraint error", ErrConstraintError, message.StatusConstraintError},
		{"data version mismatch", ErrDataVersionMismatch, message.StatusDataVersionMismatch},
		{"needs timed interaction", ErrNeedsTimedInteraction, message.StatusNeedsTimedInteraction},
		{"invalid path", ErrInvalidPath, message.StatusInvalidAction},
		{"busy", ErrBusy, message.StatusBusy},
		{"resource exhausted", ErrResourceExhausted, message.StatusResourceExhausted},
		{"unknown error", errors.New("something else"), message.StatusFailure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ErrorToStatus(tt.err)
			if got != tt.want {
				t.Errorf("ErrorToStatus(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestStatusToError(t *testing.T) {
	tests := []struct {
		name   string
		status message.Status
		want   error
	}{
		{"success", message.StatusSuccess, nil},
		{"unsupported cluster", message.StatusUnsupportedCluster, ErrClusterNotFound},
		{"unsupported attribute", message.StatusUnsupportedAttribute, ErrAttributeNotFound},
		{"unsupported command", message.StatusUnsupportedCommand, ErrCommandNotFound},
		{"unsupported access", message.StatusUnsupportedAccess, ErrAccessDenied},
		{"unsupported write", message.StatusUnsupportedWrite, ErrUnsupportedWrite},
		{"unsupported read", message.StatusUnsupportedRead, ErrUnsupportedRead},
		{"constraint error", message.StatusConstraintError, ErrConstraintError},
		{"data version mismatch", message.StatusDataVersionMismatch, ErrDataVersionMismatch},
		{"needs timed interaction", message.StatusNeedsTimedInteraction, ErrNeedsTimedInteraction},
		{"invalid action", message.StatusInvalidAction, ErrInvalidPath},
		{"busy", message.StatusBusy, ErrBusy},
		{"resource exhausted", message.StatusResourceExhausted, ErrResourceExhausted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StatusToError(tt.status)
			if !errors.Is(got, tt.want) {
				t.Errorf("StatusToError(%v) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestStatusToError_Unknown(t *testing.T) {
	// Unknown status codes should return a non-nil error with the status name
	got := StatusToError(message.StatusTimeout)
	if got == nil {
		t.Error("StatusToError(StatusTimeout) should return error, got nil")
	}
	if got.Error() != "im: Timeout" {
		t.Errorf("StatusToError(StatusTimeout) = %q, want %q", got.Error(), "im: Timeout")
	}
}

func TestErrorToStatus_WrappedError(t *testing.T) {
	// Test that wrapped errors are correctly identified
	wrapped := errors.Join(ErrClusterNotFound, errors.New("additional context"))
	got := ErrorToStatus(wrapped)
	if got != message.StatusUnsupportedCluster {
		t.Errorf("ErrorToStatus(wrapped ErrClusterNotFound) = %v, want %v", got, message.StatusUnsupportedCluster)
	}
}

func TestErrorToStatusToError_Roundtrip(t *testing.T) {
	// Test that converting error -> status -> error preserves the semantic
	errs := []error{
		ErrClusterNotFound,
		ErrAttributeNotFound,
		ErrCommandNotFound,
		ErrAccessDenied,
		ErrUnsupportedWrite,
		ErrUnsupportedRead,
		ErrConstraintError,
		ErrDataVersionMismatch,
		ErrNeedsTimedInteraction,
		ErrInvalidPath,
		ErrBusy,
		ErrResourceExhausted,
	}

	for _, original := range errs {
		status := ErrorToStatus(original)
		recovered := StatusToError(status)
		if !errors.Is(recovered, original) {
			t.Errorf("Roundtrip failed: %v -> %v -> %v", original, status, recovered)
		}
	}
}
