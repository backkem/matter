// Package integration contains integration tests for Matter devices.
//
// This file (light_e2e_test.go) contains end-to-end tests that verify
// controller ↔ device communication over a virtual pipe network.
//
// For commissioning tests, see commissioning_e2e_test.go.
// For single-device tests without network I/O, see light_basic_test.go.
// For interop tests with chip-tool, see light_interop_test.go (build tag: interop).
package integration

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/backkem/matter/examples/controller"
	"github.com/backkem/matter/examples/light"
	"github.com/backkem/matter/pkg/clusters/onoff"
	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/matter"
	"github.com/backkem/matter/pkg/tlv"
	"github.com/backkem/matter/pkg/transport"
)

// TestE2E_DeviceAndControllerStartup verifies that both device and controller
// can start with pipe transport.
func TestE2E_DeviceAndControllerStartup(t *testing.T) {
	// Create paired transport factories
	deviceFactory, controllerFactory := transport.NewPipeFactoryPair()

	// Create device
	deviceConfig := matter.NodeConfig{
		VendorID:         fabric.VendorID(0xFFF1),
		ProductID:        0x8001,
		DeviceName:       "Test Light",
		Discriminator:    3840,
		Passcode:         20202021,
		Port:             5540,
		Storage:          matter.NewMemoryStorage(),
		TransportFactory: deviceFactory,
	}

	device, err := light.NewDeviceWithConfig(deviceConfig)
	if err != nil {
		t.Fatalf("Failed to create device: %v", err)
	}

	// Create controller
	controllerConfig := matter.NodeConfig{
		VendorID:         fabric.VendorID(0xFFF2),
		ProductID:        0x8002,
		DeviceName:       "Test Controller",
		Discriminator:    3841,
		Passcode:         20202022,
		Port:             5541,
		Storage:          matter.NewMemoryStorage(),
		TransportFactory: controllerFactory,
	}

	ctrl, err := controller.NewWithConfig(controllerConfig)
	if err != nil {
		t.Fatalf("Failed to create controller: %v", err)
	}

	// Start both
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := device.Node.Start(ctx); err != nil {
		t.Fatalf("Failed to start device: %v", err)
	}
	defer device.Node.Stop()

	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Failed to start controller: %v", err)
	}
	defer ctrl.Stop()

	// Verify both are running
	if device.Node.State() != matter.NodeStateCommissioningOpen {
		t.Errorf("Device state = %s, want CommissioningOpen", device.Node.State())
	}

	if !ctrl.IsStarted() {
		t.Error("Controller should be started")
	}

	t.Log("Both device and controller started successfully")
}

// TestE2E_OnOffCommand verifies sending On/Off commands from controller to device.
// This test exercises the full Matter stack: transport → exchange → IM → cluster.
func TestE2E_OnOffCommand(t *testing.T) {
	// Create commissioned device+controller pair using generic test infrastructure
	pair := NewTestPair(t, light.Factory)
	defer pair.Close()

	ctx := pair.Context()

	// Verify light is initially off
	if pair.Device.IsOn() {
		t.Fatal("Light should be initially off")
	}

	// Send On command
	t.Log("Sending On command...")
	result, err := pair.Controller.SendCommand(
		ctx,
		pair.Session,
		pair.DeviceAddr,
		uint16(light.LightEndpointID),
		uint32(onoff.ClusterID),
		uint32(onoff.CmdOn),
		nil, // On command has no fields
	)
	if err != nil {
		t.Fatalf("SendCommand(On) failed: %v", err)
	}
	t.Logf("On command result: hasStatus=%v, status=%v", result.HasStatus, result.Status)

	// Verify light is now on
	if !pair.Device.IsOn() {
		t.Error("Light should be on after On command")
	}

	// Send Off command
	t.Log("Sending Off command...")
	result, err = pair.Controller.SendCommand(
		ctx,
		pair.Session,
		pair.DeviceAddr,
		uint16(light.LightEndpointID),
		uint32(onoff.ClusterID),
		uint32(onoff.CmdOff),
		nil,
	)
	if err != nil {
		t.Fatalf("SendCommand(Off) failed: %v", err)
	}
	t.Logf("Off command result: hasStatus=%v, status=%v", result.HasStatus, result.Status)

	// Verify light is now off
	if pair.Device.IsOn() {
		t.Error("Light should be off after Off command")
	}

	// Send Toggle command
	t.Log("Sending Toggle command...")
	result, err = pair.Controller.SendCommand(
		ctx,
		pair.Session,
		pair.DeviceAddr,
		uint16(light.LightEndpointID),
		uint32(onoff.ClusterID),
		uint32(onoff.CmdToggle),
		nil,
	)
	if err != nil {
		t.Fatalf("SendCommand(Toggle) failed: %v", err)
	}
	t.Logf("Toggle command result: hasStatus=%v, status=%v", result.HasStatus, result.Status)

	// Verify light is now on (toggled from off)
	if !pair.Device.IsOn() {
		t.Error("Light should be on after Toggle command")
	}

	t.Log("On/Off commands through full stack completed successfully!")
}

// TestE2E_ReadOnOffAttribute verifies reading the OnOff attribute from controller.
// This test exercises the full Matter stack for attribute reads.
func TestE2E_ReadOnOffAttribute(t *testing.T) {
	// Create commissioned device+controller pair using generic test infrastructure
	pair := NewTestPair(t, light.Factory)
	defer pair.Close()

	ctx := pair.Context()

	// Turn light on locally
	pair.Device.TurnOn()
	if !pair.Device.IsOn() {
		t.Fatal("Device.TurnOn() failed")
	}

	// Read OnOff attribute via controller
	t.Log("Reading OnOff attribute (expecting true)...")
	data, err := pair.Controller.ReadAttribute(
		ctx,
		pair.Session,
		pair.DeviceAddr,
		uint16(light.LightEndpointID),
		uint32(onoff.ClusterID),
		uint32(onoff.AttrOnOff),
	)
	if err != nil {
		t.Fatalf("ReadAttribute failed: %v", err)
	}

	// Decode TLV boolean
	onOffValue, err := decodeTLVBool(data)
	if err != nil {
		t.Fatalf("Failed to decode OnOff attribute: %v", err)
	}

	if !onOffValue {
		t.Error("OnOff attribute should be true when light is on")
	}
	t.Logf("Read OnOff = %v (expected true)", onOffValue)

	// Turn light off locally
	pair.Device.TurnOff()
	if pair.Device.IsOn() {
		t.Fatal("Device.TurnOff() failed")
	}

	// Read OnOff attribute again
	t.Log("Reading OnOff attribute (expecting false)...")
	data, err = pair.Controller.ReadAttribute(
		ctx,
		pair.Session,
		pair.DeviceAddr,
		uint16(light.LightEndpointID),
		uint32(onoff.ClusterID),
		uint32(onoff.AttrOnOff),
	)
	if err != nil {
		t.Fatalf("ReadAttribute failed: %v", err)
	}

	// Decode TLV boolean
	onOffValue, err = decodeTLVBool(data)
	if err != nil {
		t.Fatalf("Failed to decode OnOff attribute: %v", err)
	}

	if onOffValue {
		t.Error("OnOff attribute should be false when light is off")
	}
	t.Logf("Read OnOff = %v (expected false)", onOffValue)

	t.Log("OnOff attribute reads through full stack completed successfully!")
}

// decodeTLVBool decodes a TLV-encoded boolean value.
func decodeTLVBool(data []byte) (bool, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		return false, err
	}
	return r.Bool()
}
