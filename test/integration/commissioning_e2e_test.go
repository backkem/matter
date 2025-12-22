// Package integration contains integration tests for Matter devices.
//
// This file (commissioning_e2e_test.go) contains end-to-end tests that verify
// PASE commissioning through the full Matter stack.
package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/backkem/matter/examples/controller"
	"github.com/backkem/matter/examples/light"
	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/matter"
	"github.com/backkem/matter/pkg/session"
	"github.com/backkem/matter/pkg/transport"
	"github.com/pion/logging"
)

// TestE2E_PASECommissioning tests PASE commissioning through the full Matter stack.
// This test uses the pkg/matter facade and Controller.CommissionDevice to exercise
// the complete transport → exchange → secure channel flow.
//
// Following the testing pattern from docs/pkgs/testing.md (Strategy B: White-Box).
func TestE2E_PASECommissioning(t *testing.T) {
	// Create paired transport factories connected via pipe
	deviceFactory, controllerFactory := transport.NewPipeFactoryPair()

	// Device passcode - must match between device config and controller's commissioning
	passcode := uint32(20202021)

	// Track session establishment
	var deviceSessionEstablished bool
	var controllerSessionEstablished bool
	var mu sync.Mutex

	// Create logger factory for debugging
	loggerFactory := logging.NewDefaultLoggerFactory()

	// Create device using the light example
	deviceConfig := matter.NodeConfig{
		VendorID:         fabric.VendorID(0xFFF1),
		ProductID:        0x8001,
		DeviceName:       "Test Light",
		Discriminator:    3840,
		Passcode:         passcode,
		Port:             5540,
		Storage:          matter.NewMemoryStorage(),
		TransportFactory: deviceFactory,
		LoggerFactory:    loggerFactory,
		OnSessionEstablished: func(sessionID uint16, sessionType session.SessionType) {
			if sessionType == session.SessionTypePASE {
				mu.Lock()
				deviceSessionEstablished = true
				mu.Unlock()
				t.Logf("Device: PASE session established, ID=%d", sessionID)
			}
		},
	}

	device, err := light.NewDeviceWithConfig(deviceConfig)
	if err != nil {
		t.Fatalf("Failed to create device: %v", err)
	}

	// Create controller using the controller example
	controllerConfig := matter.NodeConfig{
		VendorID:         fabric.VendorID(0xFFF2),
		ProductID:        0x8002,
		DeviceName:       "Test Controller",
		Discriminator:    3841,
		Passcode:         20202022, // Controller's own passcode (different from device)
		Port:             5541,
		Storage:          matter.NewMemoryStorage(),
		TransportFactory: controllerFactory,
		LoggerFactory:    loggerFactory,
		OnSessionEstablished: func(sessionID uint16, sessionType session.SessionType) {
			if sessionType == session.SessionTypePASE {
				mu.Lock()
				controllerSessionEstablished = true
				mu.Unlock()
				t.Logf("Controller: PASE session established, ID=%d", sessionID)
			}
		},
	}

	ctrl, err := controller.NewWithConfig(controllerConfig)
	if err != nil {
		t.Fatalf("Failed to create controller: %v", err)
	}

	// Start both nodes
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := device.Node.Start(ctx); err != nil {
		t.Fatalf("Failed to start device: %v", err)
	}
	defer device.Node.Stop()

	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Failed to start controller: %v", err)
	}
	defer ctrl.Stop()

	// Verify device has commissioning window open
	if !device.Node.IsCommissioningWindowOpen() {
		t.Fatal("Device commissioning window should be open")
	}

	// Get device address - auto-process is enabled by default, no manual pump needed!
	deviceAddr := transport.NewUDPPeerAddress(deviceFactory.LocalAddr())
	t.Logf("Device address: %v", deviceAddr)

	// Commission the device using the full stack
	// This exercises: transport → message layer → exchange → secure channel
	secureSession, err := ctrl.CommissionDevice(ctx, deviceAddr, passcode)
	if err != nil {
		t.Fatalf("CommissionDevice failed: %v", err)
	}

	if secureSession == nil {
		t.Fatal("CommissionDevice returned nil session")
	}

	t.Logf("PASE session established: localID=%d, peerID=%d",
		secureSession.LocalSessionID(), secureSession.PeerSessionID())

	// Verify both sides have sessions established
	mu.Lock()
	deviceEstablished := deviceSessionEstablished
	controllerEstablished := controllerSessionEstablished
	mu.Unlock()

	if !deviceEstablished {
		t.Error("Device session callback was not called")
	}
	if !controllerEstablished {
		t.Error("Controller session callback was not called")
	}

	// Verify session counts
	deviceSessions := device.Node.SessionManager().SecureSessionCount()
	controllerSessions := ctrl.SecureSessionCount()

	if deviceSessions != 1 {
		t.Errorf("Device should have 1 secure session, got %d", deviceSessions)
	}
	if controllerSessions != 1 {
		t.Errorf("Controller should have 1 secure session, got %d", controllerSessions)
	}

	t.Log("PASE commissioning through full stack completed successfully!")
}

// TestE2E_PipeFactoryPair verifies that PipeFactoryPair creates connected factories.
func TestE2E_PipeFactoryPair(t *testing.T) {
	deviceFactory, controllerFactory := transport.NewPipeFactoryPair()

	if deviceFactory == nil {
		t.Error("Device factory is nil")
	}
	if controllerFactory == nil {
		t.Error("Controller factory is nil")
	}
	if deviceFactory.Pipe() != controllerFactory.Pipe() {
		t.Error("Factories should share the same pipe")
	}

	// Verify addresses are different
	deviceAddr := deviceFactory.LocalAddr()
	controllerAddr := controllerFactory.LocalAddr()

	if deviceAddr.String() == controllerAddr.String() {
		t.Error("Addresses should be different")
	}

	t.Logf("Device addr: %s", deviceAddr)
	t.Logf("Controller addr: %s", controllerAddr)
}
