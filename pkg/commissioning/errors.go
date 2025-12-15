package commissioning

import "errors"

// Commissioning errors
var (
	// ErrAlreadyCommissioning indicates a commissioning operation is already in progress.
	ErrAlreadyCommissioning = errors.New("commissioning: operation already in progress")

	// ErrNotCommissioning indicates no commissioning operation is in progress.
	ErrNotCommissioning = errors.New("commissioning: no operation in progress")

	// ErrDeviceNotFound indicates the device could not be discovered.
	ErrDeviceNotFound = errors.New("commissioning: device not found")

	// ErrPASEFailed indicates the PASE handshake failed.
	ErrPASEFailed = errors.New("commissioning: PASE handshake failed")

	// ErrCASEFailed indicates the CASE handshake failed.
	ErrCASEFailed = errors.New("commissioning: CASE handshake failed")

	// ErrAttestationFailed indicates device attestation verification failed.
	ErrAttestationFailed = errors.New("commissioning: device attestation failed")

	// ErrCSRFailed indicates the CSR request failed.
	ErrCSRFailed = errors.New("commissioning: CSR request failed")

	// ErrAddNOCFailed indicates adding the NOC failed.
	ErrAddNOCFailed = errors.New("commissioning: add NOC failed")

	// ErrNetworkConfigFailed indicates network configuration failed.
	ErrNetworkConfigFailed = errors.New("commissioning: network configuration failed")

	// ErrFailSafeExpired indicates the fail-safe timer expired during commissioning.
	ErrFailSafeExpired = errors.New("commissioning: fail-safe timer expired")

	// ErrFailSafeArm indicates the ArmFailSafe command failed.
	ErrFailSafeArm = errors.New("commissioning: failed to arm fail-safe")

	// ErrCommissioningCompleteFailed indicates the CommissioningComplete command failed.
	ErrCommissioningCompleteFailed = errors.New("commissioning: commissioning complete command failed")

	// ErrCommissioningTimeout indicates the overall commissioning timeout was exceeded.
	ErrCommissioningTimeout = errors.New("commissioning: operation timed out")

	// ErrCancelled indicates commissioning was cancelled by the user.
	ErrCancelled = errors.New("commissioning: operation cancelled")

	// ErrWindowClosed indicates the commissioning window has been closed.
	ErrWindowClosed = errors.New("commissioning: window closed")

	// ErrWindowAlreadyOpen indicates a commissioning window is already open.
	ErrWindowAlreadyOpen = errors.New("commissioning: window already open")

	// ErrInvalidPayload indicates the onboarding payload is invalid.
	ErrInvalidPayload = errors.New("commissioning: invalid onboarding payload")

	// ErrInvalidPasscode indicates the passcode is invalid.
	ErrInvalidPasscode = errors.New("commissioning: invalid passcode")

	// ErrInvalidDiscriminator indicates the discriminator is invalid.
	ErrInvalidDiscriminator = errors.New("commissioning: invalid discriminator")

	// ErrNilConfig indicates a required configuration is nil.
	ErrNilConfig = errors.New("commissioning: nil configuration")
)
