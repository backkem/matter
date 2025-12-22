// Package webrtctransportexample implements a Matter device with WebRTC Transport Provider cluster.
//
// This package provides a device for WebRTC signaling tests. The actual WebRTC
// PeerConnection is managed externally and injected via the delegate.
package webrtctransportexample

import (
	"context"
	"sync"

	"github.com/backkem/matter/examples/common"
	webrtctransport "github.com/backkem/matter/pkg/clusters/webrtc-transport"
	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/matter"
)

// DeviceType constants for WebRTC Provider.
const (
	// WebRTCProviderDeviceType is the device type (placeholder).
	WebRTCProviderDeviceType uint32 = 0x0F00

	// WebRTCEndpointID is the endpoint ID for the WebRTC cluster.
	WebRTCEndpointID datamodel.EndpointID = 1
)

// Device represents a WebRTC Transport Provider device.
type Device struct {
	// Node is the underlying Matter node.
	Node *matter.Node

	// Provider is the WebRTC Transport Provider cluster instance.
	Provider *webrtctransport.Provider

	// Delegate handles WebRTC signaling callbacks.
	Delegate *DeviceDelegate
}

// DeviceDelegate implements webrtctransport.ProviderDelegate for the device.
type DeviceDelegate struct {
	mu sync.Mutex

	// OfferHandler is called when a ProvideOffer command is received.
	// Set this to handle incoming offers and provide answers.
	OfferHandler func(ctx context.Context, req *webrtctransport.ProvideOfferRequest) (*webrtctransport.ProvideOfferResult, error)

	// AnswerHandler is called when a ProvideAnswer command is received.
	AnswerHandler func(ctx context.Context, sessionID uint16, sdp string) error

	// ICECandidatesHandler is called when ICE candidates are received.
	ICECandidatesHandler func(ctx context.Context, sessionID uint16, candidates []webrtctransport.ICECandidateStruct) error

	// SessionEndedHandler is called when a session ends.
	SessionEndedHandler func(ctx context.Context, sessionID uint16, reason webrtctransport.WebRTCEndReasonEnum) error
}

// OnSolicitOffer implements webrtctransport.ProviderDelegate.
func (d *DeviceDelegate) OnSolicitOffer(ctx context.Context, req *webrtctransport.SolicitOfferRequest) (bool, error) {
	// For simplicity, we don't support SolicitOffer flow in this example.
	return false, nil
}

// OnOfferReceived implements webrtctransport.ProviderDelegate.
func (d *DeviceDelegate) OnOfferReceived(ctx context.Context, req *webrtctransport.ProvideOfferRequest) (*webrtctransport.ProvideOfferResult, error) {
	d.mu.Lock()
	handler := d.OfferHandler
	d.mu.Unlock()

	if handler != nil {
		return handler(ctx, req)
	}
	return &webrtctransport.ProvideOfferResult{}, nil
}

// OnAnswerReceived implements webrtctransport.ProviderDelegate.
func (d *DeviceDelegate) OnAnswerReceived(ctx context.Context, sessionID uint16, sdp string) error {
	d.mu.Lock()
	handler := d.AnswerHandler
	d.mu.Unlock()

	if handler != nil {
		return handler(ctx, sessionID, sdp)
	}
	return nil
}

// OnICECandidates implements webrtctransport.ProviderDelegate.
func (d *DeviceDelegate) OnICECandidates(ctx context.Context, sessionID uint16, candidates []webrtctransport.ICECandidateStruct) error {
	d.mu.Lock()
	handler := d.ICECandidatesHandler
	d.mu.Unlock()

	if handler != nil {
		return handler(ctx, sessionID, candidates)
	}
	return nil
}

// OnSessionEnded implements webrtctransport.ProviderDelegate.
func (d *DeviceDelegate) OnSessionEnded(ctx context.Context, sessionID uint16, reason webrtctransport.WebRTCEndReasonEnum) error {
	d.mu.Lock()
	handler := d.SessionEndedHandler
	d.mu.Unlock()

	if handler != nil {
		return handler(ctx, sessionID, reason)
	}
	return nil
}

// NewDevice creates a new WebRTC Transport device with the given options.
func NewDevice(opts common.Options) (*Device, error) {
	if opts.DeviceName == "" || opts.DeviceName == "Matter Device" {
		opts.DeviceName = "WebRTC Device"
	}

	node, err := common.CreateNode(opts)
	if err != nil {
		return nil, err
	}

	return newDeviceWithNode(node)
}

// NewDeviceWithConfig creates a new WebRTC Transport device with a custom Matter config.
func NewDeviceWithConfig(config matter.NodeConfig) (*Device, error) {
	node, err := matter.NewNode(config)
	if err != nil {
		return nil, err
	}

	return newDeviceWithNode(node)
}

func newDeviceWithNode(node *matter.Node) (*Device, error) {
	// Create delegate
	delegate := &DeviceDelegate{}

	// Create Provider cluster
	provider := webrtctransport.NewProvider(webrtctransport.ProviderConfig{
		EndpointID: WebRTCEndpointID,
		Delegate:   delegate,
	})

	// Create endpoint with Provider cluster
	ep := matter.NewEndpoint(WebRTCEndpointID).
		WithDeviceType(WebRTCProviderDeviceType, 1).
		AddCluster(provider)

	if err := node.AddEndpoint(ep); err != nil {
		return nil, err
	}

	return &Device{
		Node:     node,
		Provider: provider,
		Delegate: delegate,
	}, nil
}

// GetNode returns the underlying Matter node.
// Implements the TestDevice interface for integration testing.
func (d *Device) GetNode() *matter.Node {
	return d.Node
}

// Factory creates a WebRTC device from a Matter node config.
// Use this with the test infrastructure.
func Factory(config matter.NodeConfig) (*Device, error) {
	return NewDeviceWithConfig(config)
}
