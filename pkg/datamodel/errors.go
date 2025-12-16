package datamodel

import "errors"

// Errors returned by datamodel operations.
var (
	// ErrEndpointNotFound indicates the requested endpoint does not exist.
	ErrEndpointNotFound = errors.New("endpoint not found")

	// ErrEndpointExists indicates an endpoint with the same ID already exists.
	ErrEndpointExists = errors.New("endpoint already exists")

	// ErrClusterNotFound indicates the requested cluster does not exist.
	ErrClusterNotFound = errors.New("cluster not found")

	// ErrClusterExists indicates a cluster with the same ID already exists.
	ErrClusterExists = errors.New("cluster already exists")

	// ErrAttributeNotFound indicates the requested attribute does not exist.
	ErrAttributeNotFound = errors.New("attribute not found")

	// ErrAttributeNotReadable indicates the attribute does not support read access.
	ErrAttributeNotReadable = errors.New("attribute not readable")

	// ErrAttributeNotWritable indicates the attribute does not support write access.
	ErrAttributeNotWritable = errors.New("attribute not writable")

	// ErrCommandNotFound indicates the requested command does not exist.
	ErrCommandNotFound = errors.New("command not found")

	// ErrEventNotFound indicates the requested event does not exist.
	ErrEventNotFound = errors.New("event not found")

	// ErrUnsupportedAccess indicates the access type is not supported.
	ErrUnsupportedAccess = errors.New("unsupported access")

	// ErrAccessDenied indicates insufficient privileges for the operation.
	ErrAccessDenied = errors.New("access denied")

	// ErrInvalidDataVersion indicates a data version mismatch.
	ErrInvalidDataVersion = errors.New("data version mismatch")

	// ErrTimedRequired indicates a timed interaction is required.
	ErrTimedRequired = errors.New("timed interaction required")

	// ErrAtomicRequired indicates the attribute requires atomic write.
	ErrAtomicRequired = errors.New("atomic write required")

	// ErrInvalidInState indicates the operation is invalid in the current state.
	ErrInvalidInState = errors.New("invalid in current state")

	// ErrResourceExhausted indicates insufficient resources.
	ErrResourceExhausted = errors.New("resource exhausted")

	// ErrBusy indicates the resource is busy with another operation.
	ErrBusy = errors.New("resource busy")

	// ErrConstraintError indicates a constraint violation.
	ErrConstraintError = errors.New("constraint error")

	// ErrInvalidCommand indicates an invalid command.
	ErrInvalidCommand = errors.New("invalid command")

	// ErrNoFabricContext indicates a fabric context is required but not present.
	ErrNoFabricContext = errors.New("no fabric context")

	// ErrUnsupportedAttribute indicates the attribute is not supported by the cluster.
	ErrUnsupportedAttribute = errors.New("unsupported attribute")

	// ErrUnsupportedWrite indicates the attribute does not support writes.
	ErrUnsupportedWrite = errors.New("unsupported write")

	// ErrUnsupportedCommand indicates the command is not supported by the cluster.
	ErrUnsupportedCommand = errors.New("unsupported command")
)
