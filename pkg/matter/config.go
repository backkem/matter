package matter

import (
	"time"

	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/session"
	"github.com/backkem/matter/pkg/transport"
)

// DefaultPort is the default Matter port.
const DefaultPort = 5540

// NodeConfig holds all configuration for a Matter Node.
type NodeConfig struct {
	// Identity - Required
	VendorID  fabric.VendorID // Vendor ID (assigned by CSA)
	ProductID uint16          // Product ID (vendor-assigned)

	// Device Information - Optional
	DeviceName       string // Human-readable name (max 32 chars)
	SerialNumber     string // Serial number
	HardwareVersion  uint16 // Hardware version
	SoftwareVersion  uint32 // Software version
	SoftwareVersionString string // Software version string (e.g., "1.0.0")

	// Network
	Port     int  // UDP/TCP port (default: 5540)
	IPv6Only bool // Disable IPv4 (default: false)

	// Commissioning
	Discriminator uint16 // 12-bit discriminator for pairing (0-4095)
	Passcode      uint32 // Setup passcode (1-99999998, excluding invalid codes)

	// Storage - Required
	Storage Storage // Persistence interface

	// MRP Parameters - Optional (uses defaults if zero)
	IdleRetransTimeout   time.Duration // MRP_RETRY_INTERVAL_IDLE (default: 500ms)
	ActiveRetransTimeout time.Duration // MRP_RETRY_INTERVAL_ACTIVE (default: 300ms)
	ActiveThreshold      time.Duration // MRP_ACTIVE_THRESHOLD (default: 4s)

	// Callbacks - Optional
	OnStateChanged        func(state NodeState)
	OnSessionEstablished  func(sessionID uint16, sessionType session.SessionType)
	OnSessionClosed       func(sessionID uint16)
	OnCommissioningStart  func()
	OnCommissioningComplete func(fabricIndex fabric.FabricIndex)

	// Advanced - Internal use / Testing
	TransportFactory transport.Factory // For virtual network testing
}

// Validate checks the configuration for errors.
func (c *NodeConfig) Validate() error {
	if c.Storage == nil {
		return ErrStorageRequired
	}

	if c.VendorID == 0 {
		return ErrInvalidVendorID
	}

	if c.ProductID == 0 {
		return ErrInvalidProductID
	}

	if c.Discriminator > 4095 {
		return ErrInvalidDiscriminator
	}

	if !IsValidPasscode(c.Passcode) {
		return ErrInvalidPasscode
	}

	return nil
}

// applyDefaults fills in default values for unset fields.
func (c *NodeConfig) applyDefaults() {
	if c.Port == 0 {
		c.Port = DefaultPort
	}

	if c.IdleRetransTimeout == 0 {
		c.IdleRetransTimeout = 500 * time.Millisecond
	}

	if c.ActiveRetransTimeout == 0 {
		c.ActiveRetransTimeout = 300 * time.Millisecond
	}

	if c.ActiveThreshold == 0 {
		c.ActiveThreshold = 4 * time.Second
	}

	// Truncate device name to 32 chars per spec
	if len(c.DeviceName) > 32 {
		c.DeviceName = c.DeviceName[:32]
	}
}

// SessionParams returns MRP session parameters from config.
func (c *NodeConfig) SessionParams() session.Params {
	return session.Params{
		IdleInterval:    c.IdleRetransTimeout,
		ActiveInterval:  c.ActiveRetransTimeout,
		ActiveThreshold: c.ActiveThreshold,
	}
}
