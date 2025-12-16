package matter

import "errors"

// Package-level errors.
var (
	// ErrNotInitialized is returned when an operation requires an initialized node.
	ErrNotInitialized = errors.New("matter: node not initialized")

	// ErrAlreadyStarted is returned when Start() is called on a running node.
	ErrAlreadyStarted = errors.New("matter: node already started")

	// ErrNotStarted is returned when an operation requires a running node.
	ErrNotStarted = errors.New("matter: node not started")

	// ErrAlreadyStopped is returned when Stop() is called on a stopped node.
	ErrAlreadyStopped = errors.New("matter: node already stopped")

	// ErrInvalidConfig is returned when NodeConfig validation fails.
	ErrInvalidConfig = errors.New("matter: invalid configuration")

	// ErrStorageRequired is returned when Storage is nil.
	ErrStorageRequired = errors.New("matter: storage is required")

	// ErrInvalidVendorID is returned when VendorID is invalid.
	ErrInvalidVendorID = errors.New("matter: invalid vendor ID")

	// ErrInvalidProductID is returned when ProductID is invalid.
	ErrInvalidProductID = errors.New("matter: invalid product ID")

	// ErrInvalidDiscriminator is returned when Discriminator is out of range (0-4095).
	ErrInvalidDiscriminator = errors.New("matter: discriminator must be 0-4095")

	// ErrInvalidPasscode is returned when Passcode is invalid.
	ErrInvalidPasscode = errors.New("matter: invalid passcode")

	// ErrEndpointExists is returned when adding an endpoint with a duplicate ID.
	ErrEndpointExists = errors.New("matter: endpoint already exists")

	// ErrEndpointNotFound is returned when an endpoint is not found.
	ErrEndpointNotFound = errors.New("matter: endpoint not found")

	// ErrRootEndpointReserved is returned when trying to add endpoint 0 manually.
	ErrRootEndpointReserved = errors.New("matter: endpoint 0 is reserved for root endpoint")

	// ErrCommissioningWindowOpen is returned when a commissioning window is already open.
	ErrCommissioningWindowOpen = errors.New("matter: commissioning window already open")

	// ErrCommissioningWindowClosed is returned when no commissioning window is open.
	ErrCommissioningWindowClosed = errors.New("matter: no commissioning window open")

	// ErrAlreadyCommissioned is returned when the node is already commissioned.
	ErrAlreadyCommissioned = errors.New("matter: node is already commissioned")

	// ErrNotCommissioned is returned when the node is not commissioned.
	ErrNotCommissioned = errors.New("matter: node is not commissioned")

	// ErrFabricNotFound is returned when a fabric is not found.
	ErrFabricNotFound = errors.New("matter: fabric not found")
)

// InvalidPasscodes lists passcodes that are not allowed per Matter spec.
// See Matter Specification Section 5.1.1.6.
var InvalidPasscodes = map[uint32]bool{
	0:        true,
	11111111: true,
	22222222: true,
	33333333: true,
	44444444: true,
	55555555: true,
	66666666: true,
	77777777: true,
	88888888: true,
	99999999: true,
	12345678: true,
	87654321: true,
}

// IsValidPasscode returns true if the passcode is valid per Matter spec.
func IsValidPasscode(passcode uint32) bool {
	if passcode < 1 || passcode > 99999998 {
		return false
	}
	return !InvalidPasscodes[passcode]
}
