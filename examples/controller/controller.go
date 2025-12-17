// Package controller implements a Matter controller/commissioner.
//
// This package can be imported directly for testing or compiled
// as part of a binary (see cmd/matter-controller).
//
// Example usage:
//
//	ctrl, _ := controller.New(controller.DefaultOptions())
//	ctrl.Start(ctx)
package controller

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/backkem/matter/pkg/commissioning"
	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/matter"
	"github.com/backkem/matter/pkg/session"
	"github.com/backkem/matter/pkg/transport"
)

// Default configuration values.
const (
	DefaultPort          = 5541
	DefaultVendorID      = 0xFFF2 // Test vendor 2
	DefaultProductID     = 0x8002
	DefaultDiscriminator = 3841
	DefaultPasscode      = 20202022
	DefaultPASETimeout   = 30 * time.Second
)

// Errors
var (
	ErrNotStarted     = errors.New("controller: not started")
	ErrAlreadyStarted = errors.New("controller: already started")
)

// Options configures the controller.
type Options struct {
	VendorID      uint16
	ProductID     uint16
	DeviceName    string
	Discriminator uint16
	Passcode      uint32
	Port          int
	StoragePath   string

	// PASETimeout is the timeout for PASE establishment.
	PASETimeout time.Duration

	// TransportFactory allows injecting custom transport for testing.
	// If nil, standard UDP transport is used.
	TransportFactory transport.Factory

	// Callbacks
	OnSessionEstablished func(sessionID uint16, sessionType session.SessionType)
}

// DefaultOptions returns default controller options.
func DefaultOptions() Options {
	return Options{
		VendorID:      DefaultVendorID,
		ProductID:     DefaultProductID,
		DeviceName:    "Matter Controller",
		Discriminator: DefaultDiscriminator,
		Passcode:      DefaultPasscode,
		Port:          DefaultPort,
		PASETimeout:   DefaultPASETimeout,
	}
}

// Controller is a Matter controller that can commission and control devices.
type Controller struct {
	node    *matter.Node
	opts    Options
	started bool
	mu      sync.RWMutex
}

// New creates a new controller with the given options.
func New(opts Options) (*Controller, error) {
	// Apply defaults
	if opts.VendorID == 0 {
		opts.VendorID = DefaultVendorID
	}
	if opts.ProductID == 0 {
		opts.ProductID = DefaultProductID
	}
	if opts.DeviceName == "" {
		opts.DeviceName = "Matter Controller"
	}
	if opts.Discriminator == 0 {
		opts.Discriminator = DefaultDiscriminator
	}
	if opts.Passcode == 0 {
		opts.Passcode = DefaultPasscode
	}
	if opts.Port == 0 {
		opts.Port = DefaultPort
	}
	if opts.PASETimeout == 0 {
		opts.PASETimeout = DefaultPASETimeout
	}

	return &Controller{
		opts: opts,
	}, nil
}

// NewWithConfig creates a new controller with a custom Matter node config.
// This is useful for testing where you want full control over the node configuration.
func NewWithConfig(config matter.NodeConfig) (*Controller, error) {
	// Create the node
	node, err := matter.NewNode(config)
	if err != nil {
		return nil, err
	}

	return &Controller{
		node: node,
		opts: Options{
			PASETimeout: DefaultPASETimeout,
		},
	}, nil
}

// Start starts the controller.
func (c *Controller) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started {
		return ErrAlreadyStarted
	}

	// If no node yet, create one
	if c.node == nil {
		config := matter.NodeConfig{
			VendorID:         fabric.VendorID(c.opts.VendorID),
			ProductID:        c.opts.ProductID,
			DeviceName:       c.opts.DeviceName,
			Discriminator:    c.opts.Discriminator,
			Passcode:         c.opts.Passcode,
			Port:             c.opts.Port,
			Storage:          matter.NewMemoryStorage(),
			TransportFactory: c.opts.TransportFactory,
			OnSessionEstablished: func(sessionID uint16, sessionType session.SessionType) {
				if c.opts.OnSessionEstablished != nil {
					c.opts.OnSessionEstablished(sessionID, sessionType)
				}
			},
		}

		node, err := matter.NewNode(config)
		if err != nil {
			return err
		}
		c.node = node
	}

	// Start the node
	if err := c.node.Start(ctx); err != nil {
		return err
	}

	c.started = true
	return nil
}

// Stop stops the controller.
func (c *Controller) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.started {
		return nil
	}

	if c.node != nil {
		if err := c.node.Stop(); err != nil {
			return err
		}
	}

	c.started = false
	return nil
}

// Node returns the underlying Matter node.
func (c *Controller) Node() *matter.Node {
	return c.node
}

// IsStarted returns true if the controller is started.
func (c *Controller) IsStarted() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.started
}

// StartPASE begins a PASE handshake as initiator and returns the PBKDFParamRequest.
// Use this with manual message pumping for testing.
//
// Parameters:
//   - exchangeID: Exchange ID for this handshake
//   - passcode: Device passcode
//
// Returns the PBKDFParamRequest payload to send to the device.
func (c *Controller) StartPASE(exchangeID uint16, passcode uint32) ([]byte, error) {
	c.mu.RLock()
	if !c.started {
		c.mu.RUnlock()
		return nil, ErrNotStarted
	}
	c.mu.RUnlock()

	scMgr := c.node.SecureChannelManager()
	if scMgr == nil {
		return nil, errors.New("controller: secure channel manager not available")
	}

	return scMgr.StartPASE(exchangeID, passcode)
}

// SecureSessionCount returns the number of established secure sessions.
func (c *Controller) SecureSessionCount() int {
	if c.node == nil {
		return 0
	}
	sessMgr := c.node.SessionManager()
	if sessMgr == nil {
		return 0
	}
	return sessMgr.SecureSessionCount()
}

// CommissionDevice commissions a device using PASE.
// This uses the full Matter stack (transport, exchange, secure channel).
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - peerAddr: Device network address
//   - passcode: Device setup passcode
//
// Returns the established secure session on success.
func (c *Controller) CommissionDevice(
	ctx context.Context,
	peerAddr transport.PeerAddress,
	passcode uint32,
) (*session.SecureContext, error) {
	c.mu.RLock()
	if !c.started {
		c.mu.RUnlock()
		return nil, ErrNotStarted
	}
	c.mu.RUnlock()

	// Get managers from node
	exchMgr := c.node.ExchangeManager()
	scMgr := c.node.SecureChannelManager()
	sessMgr := c.node.SessionManager()

	if exchMgr == nil || scMgr == nil || sessMgr == nil {
		return nil, errors.New("controller: managers not available")
	}

	// Create PASE client
	paseClient := commissioning.NewPASEClient(commissioning.PASEClientConfig{
		ExchangeManager: exchMgr,
		SecureChannel:   scMgr,
		SessionManager:  sessMgr,
		Timeout:         c.opts.PASETimeout,
	})

	// Establish PASE session
	return paseClient.Establish(ctx, peerAddr, passcode)
}
