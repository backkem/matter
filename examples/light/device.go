// Package light implements a Matter On/Off Light device.
//
// This package can be imported directly for testing or compiled
// as part of a binary (see cmd/matter-light-device).
//
// Example usage:
//
//	opts := common.DefaultOptions()
//	opts.DeviceName = "My Light"
//	device, _ := light.NewDevice(opts)
//	device.Start(ctx)
package light

import (
	"log"

	"github.com/backkem/matter/examples/common"
	"github.com/backkem/matter/pkg/clusters/onoff"
	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/matter"
)

// DeviceType constants for On/Off Light.
const (
	// OnOffLightDeviceType is the device type for On/Off Light (0x0100).
	OnOffLightDeviceType uint32 = 0x0100

	// OnOffDeviceType is a base device type (0x0010).
	OnOffDeviceType uint32 = 0x0010

	// LightEndpointID is the endpoint ID for the light.
	LightEndpointID datamodel.EndpointID = 1
)

// Device represents an On/Off Light device.
type Device struct {
	// Node is the underlying Matter node.
	Node *matter.Node

	// OnOffCluster is the On/Off cluster instance.
	// Exposed for testing state inspection.
	OnOffCluster *onoff.Cluster
}

// NewDevice creates a new On/Off Light device with the given options.
//
// The device has:
//   - Root Endpoint (0): Automatically created with required clusters
//   - Light Endpoint (1): On/Off cluster for light control
func NewDevice(opts common.Options) (*Device, error) {
	// Apply light-specific defaults
	if opts.DeviceName == "" || opts.DeviceName == "Matter Device" {
		opts.DeviceName = "Matter Light"
	}

	// Create the base node
	node, err := common.CreateNode(opts)
	if err != nil {
		return nil, err
	}

	// Create the On/Off cluster
	onOffCluster := onoff.New(onoff.Config{
		EndpointID:   LightEndpointID,
		FeatureMap:   0, // Basic on/off, no lighting features
		InitialOnOff: false,
		OnStateChange: func(endpoint datamodel.EndpointID, newState bool) {
			state := "OFF"
			if newState {
				state = "ON"
			}
			log.Printf("Light is now %s", state)
		},
	})

	// Create endpoint 1 for the light
	lightEP := matter.NewEndpoint(LightEndpointID).
		WithDeviceType(OnOffLightDeviceType, 1). // On/Off Light
		AddCluster(onOffCluster)

	// Add the endpoint to the node
	if err := node.AddEndpoint(lightEP); err != nil {
		return nil, err
	}

	return &Device{
		Node:         node,
		OnOffCluster: onOffCluster,
	}, nil
}

// NewDeviceWithConfig creates a new On/Off Light device with a custom Matter config.
// This is useful for testing where you want full control over the node configuration.
func NewDeviceWithConfig(config matter.NodeConfig) (*Device, error) {
	// Create the base node
	node, err := matter.NewNode(config)
	if err != nil {
		return nil, err
	}

	// Create the On/Off cluster
	onOffCluster := onoff.New(onoff.Config{
		EndpointID:   LightEndpointID,
		FeatureMap:   0,
		InitialOnOff: false,
	})

	// Create endpoint 1 for the light
	lightEP := matter.NewEndpoint(LightEndpointID).
		WithDeviceType(OnOffLightDeviceType, 1).
		AddCluster(onOffCluster)

	// Add the endpoint to the node
	if err := node.AddEndpoint(lightEP); err != nil {
		return nil, err
	}

	return &Device{
		Node:         node,
		OnOffCluster: onOffCluster,
	}, nil
}

// IsOn returns the current on/off state of the light.
func (d *Device) IsOn() bool {
	return d.OnOffCluster.GetOnOff()
}

// TurnOn turns the light on.
func (d *Device) TurnOn() {
	d.OnOffCluster.SetOnOff(true)
}

// TurnOff turns the light off.
func (d *Device) TurnOff() {
	d.OnOffCluster.SetOnOff(false)
}

// Toggle toggles the light state.
func (d *Device) Toggle() {
	d.OnOffCluster.SetOnOff(!d.OnOffCluster.GetOnOff())
}

// OnboardingPayload returns the QR code payload for commissioning.
func (d *Device) OnboardingPayload() string {
	return d.Node.OnboardingPayload()
}

// ManualPairingCode returns the manual pairing code for commissioning.
func (d *Device) ManualPairingCode() string {
	return d.Node.ManualPairingCode()
}
