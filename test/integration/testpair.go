// Package integration provides test infrastructure for Matter E2E tests.
package integration

import (
	"context"
	"testing"
	"time"

	"github.com/backkem/matter/examples/controller"
	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/matter"
	"github.com/backkem/matter/pkg/session"
	"github.com/backkem/matter/pkg/transport"
	"github.com/pion/logging"
)

// TestDevice is the interface that device types must implement for testing.
// Device examples (light.Device, camera.Device, etc.) should implement this.
type TestDevice interface {
	// GetNode returns the underlying Matter node.
	GetNode() *matter.Node
}

// TestController is the interface that controller types must implement for testing.
// Controller examples should implement this interface.
type TestController interface {
	// Start starts the controller.
	Start(ctx context.Context) error

	// Stop stops the controller.
	Stop() error

	// CommissionDevice commissions a device using PASE.
	CommissionDevice(ctx context.Context, peerAddr transport.PeerAddress, passcode uint32) (*session.SecureContext, error)
}

// DeviceFactory creates a device from a Matter node config.
// Each device type (light, camera, etc.) provides its own factory.
type DeviceFactory[D TestDevice] func(config matter.NodeConfig) (D, error)

// ControllerFactory creates a controller from a Matter node config.
// The default controller and specialized controllers provide their own factories.
type ControllerFactory[C TestController] func(config matter.NodeConfig) (C, error)

// TestPair holds a commissioned device and controller pair for E2E testing.
// Generic over device type D and controller type C for type-safe access
// to device/controller-specific methods in tests.
//
// Example usage:
//
//	pair := NewTestPair(t, light.Factory)
//	defer pair.Close()
//	pair.Device.IsOn() // Type-safe access to light-specific methods
type TestPair[D TestDevice, C TestController] struct {
	// Device is the device under test.
	Device D

	// Controller is the Matter controller.
	Controller C

	// DeviceAddr is the device's transport address.
	DeviceAddr transport.PeerAddress

	// Session is the established secure session between controller and device.
	Session *session.SecureContext

	// Passcode used for commissioning.
	Passcode uint32

	// internal
	t             *testing.T
	ctx           context.Context
	cancel        context.CancelFunc
	loggerFactory logging.LoggerFactory
}

// TestPairConfig configures the test pair creation.
type TestPairConfig struct {
	// DeviceConfig overrides for the device node.
	// If nil, defaults are used.
	DeviceVendorID      uint16
	DeviceProductID     uint16
	DeviceName          string
	DeviceDiscriminator uint16
	DevicePasscode      uint32
	DevicePort          int

	// ControllerConfig overrides for the controller node.
	ControllerVendorID      uint16
	ControllerProductID     uint16
	ControllerName          string
	ControllerDiscriminator uint16
	ControllerPort          int

	// CommissioningTimeout is the timeout for the PASE handshake.
	// Defaults to 30 seconds.
	CommissioningTimeout time.Duration

	// LoggerFactory for logging. If nil, uses DefaultLoggerFactory.
	LoggerFactory logging.LoggerFactory
}

// DefaultTestPairConfig returns default configuration for test pairs.
func DefaultTestPairConfig() TestPairConfig {
	return TestPairConfig{
		DeviceVendorID:          0xFFF1,
		DeviceProductID:         0x8001,
		DeviceName:              "Test Device",
		DeviceDiscriminator:     3840,
		DevicePasscode:          20202021,
		DevicePort:              5540,
		ControllerVendorID:      0xFFF2,
		ControllerProductID:     0x8002,
		ControllerName:          "Test Controller",
		ControllerDiscriminator: 3841,
		ControllerPort:          5541,
		CommissioningTimeout:    30 * time.Second,
	}
}

// NewTestPair creates a device+controller pair with an established PASE session.
// This is the simple constructor that uses the standard controller.Controller.
//
// Use this for most tests that don't need a specialized controller.
//
// Example:
//
//	pair := NewTestPair(t, light.Factory)
//	defer pair.Close()
//
//	// Send command through controller
//	result, err := pair.Controller.SendCommand(...)
//
//	// Check device state
//	if !pair.Device.IsOn() { t.Error("expected light on") }
func NewTestPair[D TestDevice](
	t *testing.T,
	deviceFactory DeviceFactory[D],
) *TestPair[D, *controller.Controller] {
	return NewTestPairWithConfig(t, deviceFactory, DefaultTestPairConfig())
}

// NewTestPairWithConfig creates a test pair with custom configuration.
// Uses the standard controller.Controller.
func NewTestPairWithConfig[D TestDevice](
	t *testing.T,
	deviceFactory DeviceFactory[D],
	config TestPairConfig,
) *TestPair[D, *controller.Controller] {
	return NewTestPairWithController(t, deviceFactory, DefaultControllerFactory, config)
}

// NewTestPairWithController creates a test pair with a custom controller type.
// This is the advanced constructor for tests that need specialized controllers
// (e.g., camera controller with WebRTC support).
//
// Example:
//
//	pair := NewTestPairWithController(t, camera.Factory, camera.ControllerFactory, config)
//	defer pair.Close()
//
//	// Use camera-specific controller methods
//	stream, err := pair.Controller.StartStream(...)
func NewTestPairWithController[D TestDevice, C TestController](
	t *testing.T,
	deviceFactory DeviceFactory[D],
	controllerFactory ControllerFactory[C],
	config TestPairConfig,
) *TestPair[D, C] {
	t.Helper()

	// Apply defaults
	if config.CommissioningTimeout == 0 {
		config.CommissioningTimeout = 30 * time.Second
	}
	if config.DevicePasscode == 0 {
		config.DevicePasscode = 20202021
	}

	// Create logger factory
	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}

	// Create paired transport factories connected via pipe
	deviceTransport, controllerTransport := transport.NewPipeFactoryPair()

	// Build device config
	deviceConfig := matter.NodeConfig{
		VendorID:         fabric.VendorID(config.DeviceVendorID),
		ProductID:        config.DeviceProductID,
		DeviceName:       config.DeviceName,
		Discriminator:    config.DeviceDiscriminator,
		Passcode:         config.DevicePasscode,
		Port:             config.DevicePort,
		Storage:          matter.NewMemoryStorage(),
		TransportFactory: deviceTransport,
		LoggerFactory:    loggerFactory,
	}

	// Create device using factory
	device, err := deviceFactory(deviceConfig)
	if err != nil {
		t.Fatalf("Failed to create device: %v", err)
	}

	// Build controller config
	controllerConfig := matter.NodeConfig{
		VendorID:         fabric.VendorID(config.ControllerVendorID),
		ProductID:        config.ControllerProductID,
		DeviceName:       config.ControllerName,
		Discriminator:    config.ControllerDiscriminator,
		Passcode:         20202022, // Controller's own passcode (not used for commissioning)
		Port:             config.ControllerPort,
		Storage:          matter.NewMemoryStorage(),
		TransportFactory: controllerTransport,
		LoggerFactory:    loggerFactory,
	}

	// Create controller using factory
	ctrl, err := controllerFactory(controllerConfig)
	if err != nil {
		t.Fatalf("Failed to create controller: %v", err)
	}

	// Create context with timeout for commissioning
	ctx, cancel := context.WithTimeout(context.Background(), config.CommissioningTimeout)

	// Start device node
	deviceNode := device.GetNode()
	if err := deviceNode.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Failed to start device: %v", err)
	}

	// Start controller
	if err := ctrl.Start(ctx); err != nil {
		deviceNode.Stop()
		cancel()
		t.Fatalf("Failed to start controller: %v", err)
	}

	// Get device address
	deviceAddr := transport.NewUDPPeerAddress(deviceTransport.LocalAddr())

	// Commission device via PASE
	sess, err := ctrl.CommissionDevice(ctx, deviceAddr, config.DevicePasscode)
	if err != nil {
		ctrl.Stop()
		deviceNode.Stop()
		cancel()
		t.Fatalf("CommissionDevice failed: %v", err)
	}

	return &TestPair[D, C]{
		Device:        device,
		Controller:    ctrl,
		DeviceAddr:    deviceAddr,
		Session:       sess,
		Passcode:      config.DevicePasscode,
		t:             t,
		ctx:           ctx,
		cancel:        cancel,
		loggerFactory: loggerFactory,
	}
}

// Close cleans up resources used by the pair.
// Should be called with defer after creating the pair.
func (p *TestPair[D, C]) Close() {
	// Stop controller (use any() for generic nil check)
	var zeroC C
	if any(p.Controller) != any(zeroC) {
		p.Controller.Stop()
	}

	// Get device node and stop it
	var zeroD D
	if any(p.Device) != any(zeroD) {
		if node := p.Device.GetNode(); node != nil {
			node.Stop()
		}
	}

	if p.cancel != nil {
		p.cancel()
	}
}

// Context returns a context for operations on this pair.
// Uses a reasonable timeout for E2E operations.
func (p *TestPair[D, C]) Context() context.Context {
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	return ctx
}

// ContextWithTimeout returns a context with custom timeout.
func (p *TestPair[D, C]) ContextWithTimeout(timeout time.Duration) context.Context {
	ctx, _ := context.WithTimeout(context.Background(), timeout)
	return ctx
}

// LoggerFactory returns the logger factory used by this pair.
func (p *TestPair[D, C]) LoggerFactory() logging.LoggerFactory {
	return p.loggerFactory
}

// DefaultControllerFactory creates a standard controller.Controller.
func DefaultControllerFactory(config matter.NodeConfig) (*controller.Controller, error) {
	return controller.NewWithConfig(config)
}
