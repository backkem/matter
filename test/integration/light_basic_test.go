// Package integration contains integration tests for Matter devices.
//
// This file (light_basic_test.go) contains single-device tests that verify
// device creation, local state, and cluster functionality without network I/O.
//
// For end-to-end tests with controller ↔ device communication, see light_e2e_test.go.
// For interop tests with chip-tool, see light_interop_test.go (build tag: interop).
package integration

import (
	"testing"

	"github.com/backkem/matter/examples/common"
	"github.com/backkem/matter/examples/light"
	"github.com/backkem/matter/pkg/clusters/onoff"
	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/matter"
)

// TestLight_NewDevice verifies that a light device can be created.
func TestLight_NewDevice(t *testing.T) {
	opts := common.DefaultOptions()
	opts.DeviceName = "Test Light"

	device, err := light.NewDevice(opts)
	if err != nil {
		t.Fatalf("NewDevice failed: %v", err)
	}

	if device.Node == nil {
		t.Fatal("Device node is nil")
	}

	if device.OnOffCluster == nil {
		t.Fatal("OnOff cluster is nil")
	}

	// Verify initial state is off
	if device.IsOn() {
		t.Error("Light should be off initially")
	}
}

// TestLight_LocalControl verifies direct control of the light state.
func TestLight_LocalControl(t *testing.T) {
	opts := common.DefaultOptions()
	device, err := light.NewDevice(opts)
	if err != nil {
		t.Fatalf("NewDevice failed: %v", err)
	}

	// Initial state should be off
	if device.IsOn() {
		t.Error("Light should be off initially")
	}

	// Turn on
	device.TurnOn()
	if !device.IsOn() {
		t.Error("Light should be on after TurnOn()")
	}

	// Turn off
	device.TurnOff()
	if device.IsOn() {
		t.Error("Light should be off after TurnOff()")
	}

	// Toggle
	device.Toggle()
	if !device.IsOn() {
		t.Error("Light should be on after Toggle()")
	}

	device.Toggle()
	if device.IsOn() {
		t.Error("Light should be off after second Toggle()")
	}
}

// TestLight_OnboardingPayload verifies QR code generation.
func TestLight_OnboardingPayload(t *testing.T) {
	opts := common.DefaultOptions()
	opts.Discriminator = 3840
	opts.Passcode = 20202021

	device, err := light.NewDevice(opts)
	if err != nil {
		t.Fatalf("NewDevice failed: %v", err)
	}

	payload := device.OnboardingPayload()
	if payload == "" {
		t.Error("OnboardingPayload returned empty string")
	}

	// QR code payload should start with "MT:"
	if len(payload) < 3 || payload[:3] != "MT:" {
		t.Errorf("Expected QR payload to start with 'MT:', got %q", payload)
	}

	t.Logf("QR Payload: %s", payload)
}

// TestLight_ManualPairingCode verifies manual code generation.
func TestLight_ManualPairingCode(t *testing.T) {
	opts := common.DefaultOptions()
	device, err := light.NewDevice(opts)
	if err != nil {
		t.Fatalf("NewDevice failed: %v", err)
	}

	code := device.ManualPairingCode()
	if code == "" {
		t.Error("ManualPairingCode returned empty string")
	}

	// Manual code should be 11 or 21 digits
	if len(code) != 11 && len(code) != 21 {
		t.Errorf("Expected manual code length 11 or 21, got %d", len(code))
	}

	t.Logf("Manual Code: %s", code)
}

// TestLight_EndpointStructure verifies the device's endpoint layout.
func TestLight_EndpointStructure(t *testing.T) {
	opts := common.DefaultOptions()
	device, err := light.NewDevice(opts)
	if err != nil {
		t.Fatalf("NewDevice failed: %v", err)
	}

	// Root endpoint (0) should exist and have required clusters
	rootEP := device.Node.GetEndpoint(matter.RootEndpointID)
	if rootEP == nil {
		t.Fatal("Root endpoint (0) not found")
	}

	// Light endpoint (1) should exist
	lightEP := device.Node.GetEndpoint(light.LightEndpointID)
	if lightEP == nil {
		t.Fatal("Light endpoint (1) not found")
	}

	// Verify device types on light endpoint
	deviceTypes := lightEP.DeviceTypes()
	found := false
	for _, dt := range deviceTypes {
		if dt.DeviceTypeID == datamodel.DeviceTypeID(light.OnOffLightDeviceType) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Light endpoint missing OnOffLight device type (0x%04X)", light.OnOffLightDeviceType)
	}
}

// TestLight_OnOffCluster verifies the On/Off cluster functionality.
func TestLight_OnOffCluster(t *testing.T) {
	opts := common.DefaultOptions()
	device, err := light.NewDevice(opts)
	if err != nil {
		t.Fatalf("NewDevice failed: %v", err)
	}

	cluster := device.OnOffCluster

	// Verify cluster ID
	if cluster.ID() != onoff.ClusterID {
		t.Errorf("Expected cluster ID 0x%04X, got 0x%04X", onoff.ClusterID, cluster.ID())
	}

	// Test attribute list includes OnOff attribute
	attrList := cluster.AttributeList()
	foundOnOff := false
	for _, attr := range attrList {
		if attr.ID == onoff.AttrOnOff {
			foundOnOff = true
			break
		}
	}
	if !foundOnOff {
		t.Error("OnOff attribute not found in attribute list")
	}

	// Test command list includes On, Off, Toggle
	cmdList := cluster.AcceptedCommandList()
	expectedCmds := map[uint32]bool{
		uint32(onoff.CmdOff):    false,
		uint32(onoff.CmdOn):     false,
		uint32(onoff.CmdToggle): false,
	}
	for _, cmd := range cmdList {
		if _, ok := expectedCmds[uint32(cmd.ID)]; ok {
			expectedCmds[uint32(cmd.ID)] = true
		}
	}
	for cmd, found := range expectedCmds {
		if !found {
			t.Errorf("Command 0x%02X not found in accepted command list", cmd)
		}
	}
}

// TestLight_MultipleDevices verifies multiple lights can coexist.
func TestLight_MultipleDevices(t *testing.T) {
	// Create two light devices on different ports
	opts1 := common.DefaultOptions()
	opts1.Port = 5540
	opts1.DeviceName = "Light 1"
	opts1.Discriminator = 1000

	opts2 := common.DefaultOptions()
	opts2.Port = 5541
	opts2.DeviceName = "Light 2"
	opts2.Discriminator = 1001

	device1, err := light.NewDevice(opts1)
	if err != nil {
		t.Fatalf("NewDevice(1) failed: %v", err)
	}

	device2, err := light.NewDevice(opts2)
	if err != nil {
		t.Fatalf("NewDevice(2) failed: %v", err)
	}

	// Control them independently
	device1.TurnOn()
	device2.TurnOff()

	if !device1.IsOn() {
		t.Error("Device 1 should be on")
	}
	if device2.IsOn() {
		t.Error("Device 2 should be off")
	}

	// Verify they have different payloads (different discriminators)
	payload1 := device1.OnboardingPayload()
	payload2 := device2.OnboardingPayload()
	if payload1 == payload2 {
		t.Error("Devices with different discriminators should have different payloads")
	}
}

// TestLight_CustomConfig verifies device creation with custom config.
func TestLight_CustomConfig(t *testing.T) {
	config := matter.NodeConfig{
		VendorID:      fabric.VendorID(0xFFF2),
		ProductID:     0x8002,
		DeviceName:    "Custom Light",
		Discriminator: 2000,
		Passcode:      34567890,
		Port:          5542,
		Storage:       matter.NewMemoryStorage(),
	}

	device, err := light.NewDeviceWithConfig(config)
	if err != nil {
		t.Fatalf("NewDeviceWithConfig failed: %v", err)
	}

	if device.Node == nil {
		t.Fatal("Device node is nil")
	}

	// Verify configuration was applied
	info := device.Node.GetSetupInfo()
	if info.VendorID != config.VendorID {
		t.Errorf("Expected VendorID 0x%04X, got 0x%04X", config.VendorID, info.VendorID)
	}
	if info.ProductID != config.ProductID {
		t.Errorf("Expected ProductID 0x%04X, got 0x%04X", config.ProductID, info.ProductID)
	}
	if info.Discriminator != config.Discriminator {
		t.Errorf("Expected Discriminator %d, got %d", config.Discriminator, info.Discriminator)
	}
}

// TestLight_StateCallback verifies the state change callback.
func TestLight_StateCallback(t *testing.T) {
	var callbackCalled bool
	var lastState bool

	opts := common.DefaultOptions()
	config := matter.NodeConfig{
		VendorID:      fabric.VendorID(opts.VendorID),
		ProductID:     opts.ProductID,
		DeviceName:    "Callback Test Light",
		Discriminator: opts.Discriminator,
		Passcode:      opts.Passcode,
		Port:          opts.Port,
		Storage:       matter.NewMemoryStorage(),
	}

	node, err := matter.NewNode(config)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}

	// Create the On/Off cluster with callback
	onOffCluster := onoff.New(onoff.Config{
		EndpointID:   light.LightEndpointID,
		FeatureMap:   0,
		InitialOnOff: false,
		OnStateChange: func(endpoint datamodel.EndpointID, newState bool) {
			callbackCalled = true
			lastState = newState
		},
	})

	// Create endpoint 1 for the light
	lightEP := matter.NewEndpoint(light.LightEndpointID).
		WithDeviceType(light.OnOffLightDeviceType, 1).
		AddCluster(onOffCluster)

	if err := node.AddEndpoint(lightEP); err != nil {
		t.Fatalf("AddEndpoint failed: %v", err)
	}

	// Turn on and verify callback
	callbackCalled = false
	onOffCluster.SetOnOff(true)
	if !callbackCalled {
		t.Error("State change callback not called on turn on")
	}
	if !lastState {
		t.Error("Callback received wrong state (expected true)")
	}

	// Turn off and verify callback
	callbackCalled = false
	onOffCluster.SetOnOff(false)
	if !callbackCalled {
		t.Error("State change callback not called on turn off")
	}
	if lastState {
		t.Error("Callback received wrong state (expected false)")
	}

	// Setting same state should not trigger callback
	callbackCalled = false
	onOffCluster.SetOnOff(false)
	if callbackCalled {
		t.Error("Callback should not be called when state doesn't change")
	}
}
