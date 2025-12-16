package clusters

import (
	"errors"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/im/message"
)

// Timed command errors.
var (
	// ErrTimedRequired is returned when a command requires timed invocation
	// but the request was not part of a timed interaction.
	ErrTimedRequired = errors.New("command requires timed invocation")
)

// RequireTimed checks if the invoke request is part of a timed interaction.
// Returns ErrTimedRequired if the command requires timed invocation but
// the request is not timed.
//
// Usage in command handlers:
//
//	func (c *MyCluster) InvokeCommand(ctx context.Context, req datamodel.InvokeRequest, r *tlv.Reader) ([]byte, error) {
//	    switch req.Path.Command {
//	    case CmdSensitiveOperation:
//	        if err := clusters.RequireTimed(req); err != nil {
//	            return nil, err
//	        }
//	        // ... process command ...
//	    }
//	}
func RequireTimed(req datamodel.InvokeRequest) error {
	if !req.IsTimed() {
		return ErrTimedRequired
	}
	return nil
}

// RequireTimedWrite checks if the write request is part of a timed interaction.
// Returns ErrTimedRequired if the attribute requires timed writes but
// the request is not timed.
func RequireTimedWrite(req datamodel.WriteAttributeRequest) error {
	if !req.IsTimed() {
		return ErrTimedRequired
	}
	return nil
}

// TimedStatus returns an IM status indicating the command needs timed interaction.
// Use this to build error responses when RequireTimed fails.
func TimedStatus() message.StatusIB {
	return message.StatusIB{
		Status: message.StatusNeedsTimedInteraction,
	}
}

// StatusSuccess returns a success status.
func StatusSuccess() message.StatusIB {
	return message.StatusIB{
		Status: message.StatusSuccess,
	}
}

// StatusFailure returns a generic failure status.
func StatusFailure() message.StatusIB {
	return message.StatusIB{
		Status: message.StatusFailure,
	}
}

// StatusUnsupportedCommand returns an unsupported command status.
func StatusUnsupportedCommand() message.StatusIB {
	return message.StatusIB{
		Status: message.StatusUnsupportedCommand,
	}
}

// StatusUnsupportedAttribute returns an unsupported attribute status.
func StatusUnsupportedAttribute() message.StatusIB {
	return message.StatusIB{
		Status: message.StatusUnsupportedAttribute,
	}
}

// StatusUnsupportedWrite returns an unsupported write status.
func StatusUnsupportedWrite() message.StatusIB {
	return message.StatusIB{
		Status: message.StatusUnsupportedWrite,
	}
}

// StatusConstraintError returns a constraint error status.
func StatusConstraintError() message.StatusIB {
	return message.StatusIB{
		Status: message.StatusConstraintError,
	}
}

// StatusInvalidAction returns an invalid action status.
func StatusInvalidAction() message.StatusIB {
	return message.StatusIB{
		Status: message.StatusInvalidAction,
	}
}

// StatusResourceExhausted returns a resource exhausted status.
func StatusResourceExhausted() message.StatusIB {
	return message.StatusIB{
		Status: message.StatusResourceExhausted,
	}
}

// StatusNotFound returns a not found status.
func StatusNotFound() message.StatusIB {
	return message.StatusIB{
		Status: message.StatusNotFound,
	}
}

// StatusBusy returns a busy status.
func StatusBusy() message.StatusIB {
	return message.StatusIB{
		Status: message.StatusBusy,
	}
}

// ClusterStatus returns a cluster-specific status with the given code.
// Use this for cluster-specific error codes defined in the cluster spec.
func ClusterStatus(code uint8) message.StatusIB {
	return message.StatusIB{
		Status:        message.StatusSuccess, // IM status is success
		ClusterStatus: &code,                 // Cluster-specific code indicates the actual result
	}
}
