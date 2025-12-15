package payload

import (
	"errors"
	"fmt"
)

// Discriminator bit lengths
const (
	DiscriminatorLongBits  = 12 // QR code discriminator
	DiscriminatorShortBits = 4  // Manual code discriminator (MSBs of long)
)

// Discriminator represents a Matter setup discriminator.
//
// QR codes contain a 12-bit discriminator. Manual pairing codes contain only
// the 4 most significant bits. This type handles both cases and provides
// methods for matching discriminators of different sizes.
type Discriminator struct {
	value   uint16
	isShort bool
}

// NewLongDiscriminator creates a 12-bit discriminator (from QR code).
// Panics if value exceeds 12 bits (0xFFF).
func NewLongDiscriminator(value uint16) Discriminator {
	if value > 0xFFF {
		panic(fmt.Sprintf("discriminator value %d exceeds 12 bits", value))
	}
	return Discriminator{value: value, isShort: false}
}

// NewShortDiscriminator creates a 4-bit discriminator (from manual code).
// Panics if value exceeds 4 bits (0xF).
func NewShortDiscriminator(value uint8) Discriminator {
	if value > 0xF {
		panic(fmt.Sprintf("discriminator value %d exceeds 4 bits", value))
	}
	return Discriminator{value: uint16(value), isShort: true}
}

// IsShort returns true if this is a 4-bit (manual code) discriminator.
func (d Discriminator) IsShort() bool {
	return d.isShort
}

// Long returns the 12-bit discriminator value.
// Panics if called on a short discriminator.
func (d Discriminator) Long() uint16 {
	if d.isShort {
		panic("cannot get long value from short discriminator")
	}
	return d.value
}

// Short returns the 4-bit discriminator value.
// For long discriminators, returns the 4 most significant bits.
func (d Discriminator) Short() uint8 {
	if d.isShort {
		return uint8(d.value)
	}
	// Long to short: take the 4 MSBs of the 12-bit value
	return uint8(d.value >> (DiscriminatorLongBits - DiscriminatorShortBits))
}

// Matches returns true if this discriminator matches a 12-bit discriminator.
// For short discriminators, matches if the 4 MSBs are equal.
func (d Discriminator) Matches(longValue uint16) bool {
	if d.isShort {
		// Compare 4 MSBs
		shortFromLong := uint8(longValue >> (DiscriminatorLongBits - DiscriminatorShortBits))
		return uint8(d.value) == shortFromLong
	}
	return d.value == longValue
}

// String returns a string representation of the discriminator.
func (d Discriminator) String() string {
	if d.isShort {
		return fmt.Sprintf("short:%d", d.value)
	}
	return fmt.Sprintf("long:%d", d.value)
}

// DiscoveryCapabilities represents the discovery methods supported by a device.
// This is an 8-bit bitmask encoded in QR codes.
type DiscoveryCapabilities uint8

const (
	DiscoveryCapabilitySoftAP    DiscoveryCapabilities = 1 << 0 // Bit 0: SoftAP (deprecated)
	DiscoveryCapabilityBLE       DiscoveryCapabilities = 1 << 1 // Bit 1: BLE
	DiscoveryCapabilityOnNetwork DiscoveryCapabilities = 1 << 2 // Bit 2: On IP network
	DiscoveryCapabilityWiFiPAF   DiscoveryCapabilities = 1 << 3 // Bit 3: Wi-Fi Public Action Frame
	DiscoveryCapabilityNFC       DiscoveryCapabilities = 1 << 4 // Bit 4: NFC
)

// Has returns true if the specified capability flag is set.
func (d DiscoveryCapabilities) Has(flag DiscoveryCapabilities) bool {
	return d&flag != 0
}

// String returns a human-readable representation of the capabilities.
func (d DiscoveryCapabilities) String() string {
	if d == 0 {
		return "none"
	}

	var caps []string
	if d.Has(DiscoveryCapabilitySoftAP) {
		caps = append(caps, "SoftAP")
	}
	if d.Has(DiscoveryCapabilityBLE) {
		caps = append(caps, "BLE")
	}
	if d.Has(DiscoveryCapabilityOnNetwork) {
		caps = append(caps, "OnNetwork")
	}
	if d.Has(DiscoveryCapabilityWiFiPAF) {
		caps = append(caps, "WiFiPAF")
	}
	if d.Has(DiscoveryCapabilityNFC) {
		caps = append(caps, "NFC")
	}

	result := ""
	for i, c := range caps {
		if i > 0 {
			result += "|"
		}
		result += c
	}
	return result
}

// CommissioningFlow represents the commissioning flow type.
type CommissioningFlow uint8

const (
	// CommissioningFlowStandard indicates the device automatically enters
	// pairing mode upon power-up.
	CommissioningFlowStandard CommissioningFlow = 0

	// CommissioningFlowUserIntent indicates the device requires user
	// interaction (e.g., button press) to enter pairing mode.
	CommissioningFlowUserIntent CommissioningFlow = 1

	// CommissioningFlowCustom indicates commissioning steps should be
	// retrieved from the Distributed Compliance Ledger or vendor docs.
	CommissioningFlowCustom CommissioningFlow = 2
)

// String returns a human-readable representation of the commissioning flow.
func (c CommissioningFlow) String() string {
	switch c {
	case CommissioningFlowStandard:
		return "Standard"
	case CommissioningFlowUserIntent:
		return "UserIntent"
	case CommissioningFlowCustom:
		return "Custom"
	default:
		return fmt.Sprintf("Unknown(%d)", c)
	}
}

// SetupPayload contains all data from a Matter onboarding payload.
// This can be parsed from a QR code or manual pairing code.
type SetupPayload struct {
	// Version is a 3-bit field. Currently must be 0.
	Version uint8

	// VendorID is the 16-bit vendor identifier.
	VendorID uint16

	// ProductID is the 16-bit product identifier.
	ProductID uint16

	// CommissioningFlow indicates how the device enters pairing mode.
	CommissioningFlow CommissioningFlow

	// DiscoveryCapabilities indicates supported discovery methods.
	// Only present in QR codes, not manual codes.
	DiscoveryCapabilities DiscoveryCapabilities

	// HasDiscoveryCapabilities indicates if DiscoveryCapabilities is valid.
	// QR codes always have this, manual codes do not.
	HasDiscoveryCapabilities bool

	// Discriminator for device discovery.
	// QR codes have 12-bit, manual codes have 4-bit.
	Discriminator Discriminator

	// Passcode is the 27-bit setup PIN code.
	Passcode uint32

	// OptionalData contains optional TLV data (from QR codes only).
	// nil if no optional data is present.
	OptionalData *OptionalData
}

// ValidationMode controls validation strictness.
type ValidationMode int

const (
	// ValidationModeProduce is strict validation for generating payloads.
	// Only values allowed by the current spec version are permitted.
	ValidationModeProduce ValidationMode = iota

	// ValidationModeConsume is lenient validation for parsing payloads.
	// Allows reserved/future flags for forward/backward compatibility.
	ValidationModeConsume
)

// Passcode constraints (Section 5.1.7)
const (
	PasscodeMin = 1
	PasscodeMax = 99999998
)

// Invalid passcodes that must not be used (Section 5.1.7.1)
var invalidPasscodes = map[uint32]bool{
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

// Validation errors
var (
	ErrInvalidVersion               = errors.New("payload: invalid version (must be 0)")
	ErrInvalidPasscode              = errors.New("payload: invalid passcode")
	ErrInvalidDiscriminator         = errors.New("payload: invalid discriminator")
	ErrInvalidCommissioningFlow     = errors.New("payload: invalid commissioning flow")
	ErrInvalidDiscoveryCapabilities = errors.New("payload: invalid discovery capabilities")
	ErrMissingDiscoveryCapabilities = errors.New("payload: QR code requires discovery capabilities")
	ErrShortDiscriminatorForQR      = errors.New("payload: QR code requires long discriminator")
)

// ValidatePasscode checks if a passcode is valid.
func ValidatePasscode(passcode uint32) error {
	if passcode < PasscodeMin || passcode > PasscodeMax {
		return ErrInvalidPasscode
	}
	if invalidPasscodes[passcode] {
		return ErrInvalidPasscode
	}
	return nil
}

// Validate checks if the payload is valid.
func (p *SetupPayload) Validate(mode ValidationMode) error {
	// Version must be 0 in current spec
	if p.Version != 0 {
		return ErrInvalidVersion
	}

	// Validate passcode
	if err := ValidatePasscode(p.Passcode); err != nil {
		return err
	}

	// Validate commissioning flow
	if mode == ValidationModeProduce && p.CommissioningFlow > CommissioningFlowCustom {
		return ErrInvalidCommissioningFlow
	}

	// Validate discovery capabilities (if present)
	if p.HasDiscoveryCapabilities && mode == ValidationModeProduce {
		// Check for unknown bits
		knownBits := DiscoveryCapabilitySoftAP | DiscoveryCapabilityBLE |
			DiscoveryCapabilityOnNetwork | DiscoveryCapabilityWiFiPAF | DiscoveryCapabilityNFC
		if p.DiscoveryCapabilities & ^knownBits != 0 {
			return ErrInvalidDiscoveryCapabilities
		}
	}

	return nil
}

// IsValidQRCodePayload checks if this payload can be encoded as a QR code.
func (p *SetupPayload) IsValidQRCodePayload(mode ValidationMode) bool {
	if err := p.Validate(mode); err != nil {
		return false
	}

	// QR codes require discovery capabilities
	if !p.HasDiscoveryCapabilities {
		return false
	}

	// QR codes require long discriminator
	if p.Discriminator.IsShort() {
		return false
	}

	return true
}

// IsValidManualCode checks if this payload can be encoded as a manual code.
func (p *SetupPayload) IsValidManualCode(mode ValidationMode) bool {
	if err := p.Validate(mode); err != nil {
		return false
	}
	return true
}

// SupportsOnNetworkDiscovery returns true if the device supports IP discovery.
func (p *SetupPayload) SupportsOnNetworkDiscovery() bool {
	return p.HasDiscoveryCapabilities && p.DiscoveryCapabilities.Has(DiscoveryCapabilityOnNetwork)
}

// SupportsBLE returns true if the device supports BLE discovery.
func (p *SetupPayload) SupportsBLE() bool {
	return p.HasDiscoveryCapabilities && p.DiscoveryCapabilities.Has(DiscoveryCapabilityBLE)
}
