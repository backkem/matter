package discovery

import "errors"

// Package-level sentinel errors for discovery operations.
var (
	// ErrClosed is returned when an operation is attempted on a closed component.
	ErrClosed = errors.New("discovery: closed")

	// ErrAlreadyStarted is returned when starting an already-started service.
	ErrAlreadyStarted = errors.New("discovery: already started")

	// ErrNotStarted is returned when stopping a service that was not started.
	ErrNotStarted = errors.New("discovery: not started")

	// ErrInvalidServiceType is returned for invalid or unknown service types.
	ErrInvalidServiceType = errors.New("discovery: invalid service type")

	// ErrInvalidDiscriminator is returned when the discriminator is out of range.
	// Valid range: 0-4095 (12 bits).
	ErrInvalidDiscriminator = errors.New("discovery: invalid discriminator (must be 0-4095)")

	// ErrInvalidDeviceName is returned when the device name exceeds the maximum length.
	// Maximum length: 32 characters.
	ErrInvalidDeviceName = errors.New("discovery: invalid device name (max 32 characters)")

	// ErrInvalidHostName is returned when the host name is empty or invalid.
	ErrInvalidHostName = errors.New("discovery: invalid host name")

	// ErrInvalidPort is returned when the port number is out of range.
	ErrInvalidPort = errors.New("discovery: invalid port (must be 1-65535)")

	// ErrNoAddresses is returned when no IP addresses are provided for advertising.
	ErrNoAddresses = errors.New("discovery: no IP addresses provided")

	// ErrServiceNotFound is returned when a requested service is not found.
	ErrServiceNotFound = errors.New("discovery: service not found")

	// ErrTimeout is returned when an operation times out.
	ErrTimeout = errors.New("discovery: operation timed out")

	// ErrInvalidInstanceName is returned when the instance name format is invalid.
	ErrInvalidInstanceName = errors.New("discovery: invalid instance name format")

	// ErrInvalidTXTRecord is returned when a TXT record has invalid format.
	ErrInvalidTXTRecord = errors.New("discovery: invalid TXT record format")
)
