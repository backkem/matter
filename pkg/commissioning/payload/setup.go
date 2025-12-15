package payload

import (
	"crypto/rand"
	"errors"
)

// PBKDF2 parameter constraints (Section 5.1.5.2)
const (
	PBKDFMinIterations     = 1000
	PBKDFMaxIterations     = 100000
	PBKDFDefaultIterations = 1000
	PBKDFMinSaltLength     = 16
	PBKDFMaxSaltLength     = 32
)

// Setup errors
var (
	ErrInvalidIterations = errors.New("setup: invalid PBKDF iterations (must be 1000-100000)")
	ErrInvalidSalt       = errors.New("setup: invalid salt length (must be 16-32 bytes)")
)

// PBKDFParams contains the parameters needed for PBKDF2-based
// verifier generation during PASE commissioning.
type PBKDFParams struct {
	Iterations uint32
	Salt       []byte
}

// DefaultPBKDFParams returns default PBKDF parameters with a randomly
// generated salt. Use this when the QR code doesn't include custom parameters.
func DefaultPBKDFParams() (*PBKDFParams, error) {
	salt := make([]byte, PBKDFMinSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return &PBKDFParams{
		Iterations: PBKDFDefaultIterations,
		Salt:       salt,
	}, nil
}

// ExtractPBKDFParams extracts PBKDF parameters from a SetupPayload.
//
// If the payload contains optional TLV data with PBKDF parameters,
// those values are used. Otherwise, returns defaults with a random salt.
//
// Note: The salt is generated fresh since QR codes typically only contain
// the iteration count hint, not the actual salt.
func ExtractPBKDFParams(payload *SetupPayload) (*PBKDFParams, error) {
	params, err := DefaultPBKDFParams()
	if err != nil {
		return nil, err
	}

	if payload.OptionalData != nil {
		// Use custom iterations if provided
		if payload.OptionalData.HasPBKDFIterations {
			params.Iterations = payload.OptionalData.PBKDFIterations
		}

		// Use custom salt if provided
		if len(payload.OptionalData.BPKFSalt) > 0 {
			params.Salt = payload.OptionalData.BPKFSalt
		}
	}

	// Validate the parameters
	if err := ValidatePBKDFParams(params); err != nil {
		return nil, err
	}

	return params, nil
}

// ValidatePBKDFParams validates PBKDF2 parameters.
func ValidatePBKDFParams(params *PBKDFParams) error {
	if params.Iterations < PBKDFMinIterations || params.Iterations > PBKDFMaxIterations {
		return ErrInvalidIterations
	}
	if len(params.Salt) < PBKDFMinSaltLength || len(params.Salt) > PBKDFMaxSaltLength {
		return ErrInvalidSalt
	}
	return nil
}

// SetupInfo contains all information needed to initiate commissioning
// with a device, extracted from a setup payload.
type SetupInfo struct {
	// Passcode for PASE authentication (27-bit value)
	Passcode uint32

	// Discriminator for device discovery (12-bit or 4-bit)
	Discriminator Discriminator

	// PBKDFParams for verifier generation
	PBKDFParams *PBKDFParams

	// VendorID and ProductID (may be 0 if not in payload)
	VendorID  uint16
	ProductID uint16

	// CommissioningFlow indicates how the device enters pairing mode
	CommissioningFlow CommissioningFlow

	// DiscoveryCapabilities indicates how to find the device
	// Only valid if HasDiscoveryCapabilities is true
	DiscoveryCapabilities    DiscoveryCapabilities
	HasDiscoveryCapabilities bool

	// SerialNumber from optional TLV data (may be empty)
	SerialNumber string

	// CommissioningTimeout in seconds (0 means use default)
	CommissioningTimeout uint16
}

// ExtractSetupInfo extracts all commissioning information from a SetupPayload.
//
// This is a convenience function that combines payload fields with PBKDF
// parameter extraction for use in commissioning flows.
func ExtractSetupInfo(payload *SetupPayload) (*SetupInfo, error) {
	if payload == nil {
		return nil, errors.New("setup: nil payload")
	}

	// Extract and validate PBKDF params
	pbkdf, err := ExtractPBKDFParams(payload)
	if err != nil {
		return nil, err
	}

	info := &SetupInfo{
		Passcode:                 payload.Passcode,
		Discriminator:            payload.Discriminator,
		PBKDFParams:              pbkdf,
		VendorID:                 payload.VendorID,
		ProductID:                payload.ProductID,
		CommissioningFlow:        payload.CommissioningFlow,
		DiscoveryCapabilities:    payload.DiscoveryCapabilities,
		HasDiscoveryCapabilities: payload.HasDiscoveryCapabilities,
	}

	// Extract optional data
	if payload.OptionalData != nil {
		if payload.OptionalData.HasSerialNumber {
			info.SerialNumber = payload.OptionalData.SerialNumber
		}
		if payload.OptionalData.HasCommissioningTimeout {
			info.CommissioningTimeout = payload.OptionalData.CommissioningTimeout
		}
	}

	return info, nil
}
