package matter

import (
	"github.com/backkem/matter/pkg/commissioning/payload"
	"github.com/backkem/matter/pkg/fabric"
)

// OnboardingPayload returns the QR code payload for this device.
// The payload encodes the discriminator, passcode, and other setup information.
//
// Example output: "MT:Y.K90SO000000000000"
func (n *Node) OnboardingPayload() string {
	n.mu.RLock()
	defer n.mu.RUnlock()

	p := payload.SetupPayload{
		Version:                  0,
		VendorID:                 uint16(n.config.VendorID),
		ProductID:                n.config.ProductID,
		CommissioningFlow:        payload.CommissioningFlowStandard,
		DiscoveryCapabilities:    payload.DiscoveryCapabilityOnNetwork, // IP-only
		HasDiscoveryCapabilities: true,
		Discriminator:            payload.NewLongDiscriminator(n.config.Discriminator),
		Passcode:                 n.config.Passcode,
	}

	qr, err := payload.EncodeQRCode(&p)
	if err != nil {
		return ""
	}

	return qr
}

// ManualPairingCode returns the 11-digit or 21-digit manual pairing code.
// The format depends on whether custom commissioning flow is used.
//
// Example output: "34970112332"
func (n *Node) ManualPairingCode() string {
	n.mu.RLock()
	defer n.mu.RUnlock()

	p := payload.SetupPayload{
		Version:           0,
		VendorID:          uint16(n.config.VendorID),
		ProductID:         n.config.ProductID,
		CommissioningFlow: payload.CommissioningFlowStandard,
		Discriminator:     payload.NewLongDiscriminator(n.config.Discriminator),
		Passcode:          n.config.Passcode,
	}

	code, err := payload.EncodeManualCode(&p)
	if err != nil {
		return ""
	}

	return code
}

// SetupInfo contains all information needed for pairing.
type SetupInfo struct {
	// VendorID is the vendor identifier.
	VendorID fabric.VendorID

	// ProductID is the product identifier.
	ProductID uint16

	// Discriminator is the 12-bit discriminator for DNS-SD filtering.
	Discriminator uint16

	// Passcode is the setup passcode.
	Passcode uint32

	// QRCode is the full QR code payload string.
	QRCode string

	// ManualCode is the manual pairing code.
	ManualCode string

	// Port is the Matter port.
	Port int
}

// GetSetupInfo returns all pairing information for the device.
func (n *Node) GetSetupInfo() SetupInfo {
	return SetupInfo{
		VendorID:      n.config.VendorID,
		ProductID:     n.config.ProductID,
		Discriminator: n.config.Discriminator,
		Passcode:      n.config.Passcode,
		QRCode:        n.OnboardingPayload(),
		ManualCode:    n.ManualPairingCode(),
		Port:          n.config.Port,
	}
}
