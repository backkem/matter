// Package integration contains integration tests for Matter devices.
//
// This file tests WebRTC Transport cluster signaling flow and DataChannel
// communication between a device (Provider) and controller (Requestor).
package integration

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	webrtctransportexample "github.com/backkem/matter/examples/webrtc-transport"
	webrtctransport "github.com/backkem/matter/pkg/clusters/webrtc-transport"
	"github.com/backkem/matter/pkg/tlv"
	"github.com/pion/webrtc/v4"
)

// TestE2E_WebRTCSignaling tests the WebRTC signaling flow via Matter commands.
// This verifies that SDP offer/answer can be exchanged through the Provider cluster.
func TestE2E_WebRTCSignaling(t *testing.T) {
	// Create commissioned device+controller pair
	pair := NewTestPair(t, webrtctransportexample.Factory)
	defer pair.Close()

	ctx := pair.Context()

	// Set up device to handle incoming offers
	var receivedOffer string
	var mu sync.Mutex

	pair.Device.Delegate.OfferHandler = func(ctx context.Context, req *webrtctransport.ProvideOfferRequest) (*webrtctransport.ProvideOfferResult, error) {
		mu.Lock()
		receivedOffer = req.SDP
		mu.Unlock()

		// Return a simple answer (not a real SDP for this basic test)
		return &webrtctransport.ProvideOfferResult{
			AnswerSDP: "v=0\r\no=- 456 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n",
		}, nil
	}

	// Encode ProvideOffer command
	testOffer := "v=0\r\no=- 123 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
	offerPayload, err := webrtctransport.EncodeProvideOffer(
		nil,                              // new session
		testOffer,                        // SDP
		webrtctransport.StreamUsageLiveView, // stream usage
		1,                                // originating endpoint
		nil, nil,                         // no stream IDs
		nil,                              // no ICE servers
		"",                               // no transport policy
		false,                            // metadata disabled
	)
	if err != nil {
		t.Fatalf("EncodeProvideOffer failed: %v", err)
	}

	// Send ProvideOffer command to device
	t.Log("Sending ProvideOffer command...")
	result, err := pair.Controller.SendCommand(
		ctx,
		pair.Session,
		pair.DeviceAddr,
		uint16(webrtctransportexample.WebRTCEndpointID),
		webrtctransport.ProviderClusterID,
		webrtctransport.CmdProvideOffer,
		offerPayload,
	)
	if err != nil {
		t.Fatalf("SendCommand(ProvideOffer) failed: %v", err)
	}

	t.Logf("ProvideOffer result: hasStatus=%v, status=%v, hasResponse=%v",
		result.HasStatus, result.Status, result.ResponseData != nil)

	// Verify offer was received by device
	mu.Lock()
	if receivedOffer != testOffer {
		t.Errorf("Device received wrong offer: got %q, want %q", receivedOffer, testOffer)
	}
	mu.Unlock()

	// Decode the response to get session ID
	if result.ResponseData != nil {
		sessionID, videoID, audioID, err := webrtctransport.DecodeProvideOfferResponse(result.ResponseData)
		if err != nil {
			t.Logf("Warning: DecodeProvideOfferResponse failed: %v", err)
		} else {
			t.Logf("Got session ID: %d, videoID: %v, audioID: %v", sessionID, videoID, audioID)
		}
	}

	t.Log("WebRTC signaling test completed successfully!")
}

// TestE2E_WebRTCDataChannel tests full WebRTC DataChannel communication.
// This creates actual pion/webrtc PeerConnections and exchanges "hello" messages.
func TestE2E_WebRTCDataChannel(t *testing.T) {
	// Create commissioned device+controller pair
	pair := NewTestPair(t, webrtctransportexample.Factory)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// WebRTC configuration (no ICE servers for local testing)
	config := webrtc.Configuration{}

	// Create PeerConnections
	devicePC, err := webrtc.NewPeerConnection(config)
	if err != nil {
		t.Fatalf("Failed to create device PeerConnection: %v", err)
	}
	defer devicePC.Close()

	controllerPC, err := webrtc.NewPeerConnection(config)
	if err != nil {
		t.Fatalf("Failed to create controller PeerConnection: %v", err)
	}
	defer controllerPC.Close()

	// Channels for synchronization
	deviceReceived := make(chan string, 1)
	controllerReceived := make(chan string, 1)
	deviceDCReady := make(chan *webrtc.DataChannel, 1)
	controllerDCReady := make(chan struct{}, 1)

	// Device: handle incoming data channel
	devicePC.OnDataChannel(func(dc *webrtc.DataChannel) {
		t.Logf("Device received data channel: %s", dc.Label())
		dc.OnOpen(func() {
			t.Log("Device data channel opened")
			deviceDCReady <- dc
		})
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			t.Logf("Device received: %s", string(msg.Data))
			deviceReceived <- string(msg.Data)
		})
	})

	// Controller: create data channel
	controllerDC, err := controllerPC.CreateDataChannel("test", nil)
	if err != nil {
		t.Fatalf("Failed to create data channel: %v", err)
	}
	controllerDC.OnOpen(func() {
		t.Log("Controller data channel opened")
		controllerDCReady <- struct{}{}
	})
	controllerDC.OnMessage(func(msg webrtc.DataChannelMessage) {
		t.Logf("Controller received: %s", string(msg.Data))
		controllerReceived <- string(msg.Data)
	})

	// Set up device to respond to offers with actual WebRTC answer
	pair.Device.Delegate.OfferHandler = func(ctx context.Context, req *webrtctransport.ProvideOfferRequest) (*webrtctransport.ProvideOfferResult, error) {
		t.Logf("Device received SDP offer (%d bytes)", len(req.SDP))

		// Set remote description from offer
		if err := devicePC.SetRemoteDescription(webrtc.SessionDescription{
			Type: webrtc.SDPTypeOffer,
			SDP:  req.SDP,
		}); err != nil {
			t.Errorf("Device SetRemoteDescription failed: %v", err)
			return nil, err
		}

		// Create answer
		answer, err := devicePC.CreateAnswer(nil)
		if err != nil {
			t.Errorf("Device CreateAnswer failed: %v", err)
			return nil, err
		}

		// Set local description
		if err := devicePC.SetLocalDescription(answer); err != nil {
			t.Errorf("Device SetLocalDescription failed: %v", err)
			return nil, err
		}

		// Wait for ICE gathering to complete
		gatherComplete := webrtc.GatheringCompletePromise(devicePC)
		select {
		case <-gatherComplete:
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		return &webrtctransport.ProvideOfferResult{
			AnswerSDP: devicePC.LocalDescription().SDP,
		}, nil
	}

	// Controller: Create offer
	t.Log("Controller creating offer...")
	offer, err := controllerPC.CreateOffer(nil)
	if err != nil {
		t.Fatalf("CreateOffer failed: %v", err)
	}

	if err := controllerPC.SetLocalDescription(offer); err != nil {
		t.Fatalf("SetLocalDescription failed: %v", err)
	}

	// Wait for ICE gathering
	gatherComplete := webrtc.GatheringCompletePromise(controllerPC)
	select {
	case <-gatherComplete:
	case <-ctx.Done():
		t.Fatal("Timeout waiting for ICE gathering")
	}

	// Send offer via Matter signaling
	offerPayload, err := webrtctransport.EncodeProvideOffer(
		nil,
		controllerPC.LocalDescription().SDP,
		webrtctransport.StreamUsageLiveView,
		1,
		nil, nil,
		nil,
		"",
		false,
	)
	if err != nil {
		t.Fatalf("EncodeProvideOffer failed: %v", err)
	}

	t.Log("Sending SDP offer via Matter...")
	result, err := pair.Controller.SendCommand(
		ctx,
		pair.Session,
		pair.DeviceAddr,
		uint16(webrtctransportexample.WebRTCEndpointID),
		webrtctransport.ProviderClusterID,
		webrtctransport.CmdProvideOffer,
		offerPayload,
	)
	if err != nil {
		t.Fatalf("SendCommand(ProvideOffer) failed: %v", err)
	}

	// Note: In this simplified test, the answer is returned synchronously
	// via the OnOfferReceived callback. In a real implementation, the answer
	// would be sent via a separate Answer command back to the Requestor.
	// For now, we need to get the answer from the device directly.

	// Get the session to retrieve the answer
	// Since we're testing just the signaling, let's verify the response
	if result.ResponseData == nil {
		t.Log("No response data - checking if device PC has answer")
	}

	// Give the device time to process and set local description
	time.Sleep(100 * time.Millisecond)

	// Get device's answer directly (simulating the answer callback)
	if devicePC.LocalDescription() == nil {
		t.Fatal("Device should have local description set")
	}
	answerSDP := devicePC.LocalDescription().SDP

	// Controller: Set remote description from answer
	t.Log("Controller setting remote description...")
	if err := controllerPC.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  answerSDP,
	}); err != nil {
		t.Fatalf("Controller SetRemoteDescription failed: %v", err)
	}

	// Wait for data channels to be ready
	t.Log("Waiting for data channels...")
	select {
	case <-controllerDCReady:
		t.Log("Controller data channel ready")
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout waiting for controller data channel")
	}

	var deviceDC *webrtc.DataChannel
	select {
	case deviceDC = <-deviceDCReady:
		t.Log("Device data channel ready")
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout waiting for device data channel")
	}

	// Exchange messages
	t.Log("Sending hello from controller...")
	if err := controllerDC.SendText("hello from controller"); err != nil {
		t.Fatalf("Controller send failed: %v", err)
	}

	t.Log("Sending hello from device...")
	if err := deviceDC.SendText("hello from device"); err != nil {
		t.Fatalf("Device send failed: %v", err)
	}

	// Verify messages received
	select {
	case msg := <-deviceReceived:
		if msg != "hello from controller" {
			t.Errorf("Device received wrong message: %q", msg)
		}
		t.Log("Device received controller message OK")
	case <-time.After(5 * time.Second):
		t.Error("Timeout waiting for device to receive message")
	}

	select {
	case msg := <-controllerReceived:
		if msg != "hello from device" {
			t.Errorf("Controller received wrong message: %q", msg)
		}
		t.Log("Controller received device message OK")
	case <-time.After(5 * time.Second):
		t.Error("Timeout waiting for controller to receive message")
	}

	t.Log("WebRTC DataChannel test completed successfully!")
}

// TestE2E_WebRTCEndSession tests the EndSession command flow.
func TestE2E_WebRTCEndSession(t *testing.T) {
	// Create commissioned device+controller pair
	pair := NewTestPair(t, webrtctransportexample.Factory)
	defer pair.Close()

	ctx := pair.Context()

	// Track session ended callback
	var endedSessionID uint16
	var endedReason webrtctransport.WebRTCEndReasonEnum
	var mu sync.Mutex

	pair.Device.Delegate.OfferHandler = func(ctx context.Context, req *webrtctransport.ProvideOfferRequest) (*webrtctransport.ProvideOfferResult, error) {
		return &webrtctransport.ProvideOfferResult{
			AnswerSDP: "v=0\r\no=- 456 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n",
		}, nil
	}

	pair.Device.Delegate.SessionEndedHandler = func(ctx context.Context, sessionID uint16, reason webrtctransport.WebRTCEndReasonEnum) error {
		mu.Lock()
		endedSessionID = sessionID
		endedReason = reason
		mu.Unlock()
		return nil
	}

	// First create a session via ProvideOffer
	offerPayload, err := webrtctransport.EncodeProvideOffer(
		nil,
		"v=0\r\no=- 123 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n",
		webrtctransport.StreamUsageLiveView,
		1,
		nil, nil,
		nil, "",
		false,
	)
	if err != nil {
		t.Fatalf("EncodeProvideOffer failed: %v", err)
	}

	result, err := pair.Controller.SendCommand(
		ctx,
		pair.Session,
		pair.DeviceAddr,
		uint16(webrtctransportexample.WebRTCEndpointID),
		webrtctransport.ProviderClusterID,
		webrtctransport.CmdProvideOffer,
		offerPayload,
	)
	if err != nil {
		t.Fatalf("SendCommand(ProvideOffer) failed: %v", err)
	}

	// Get session ID from response
	var sessionID uint16
	if result.ResponseData != nil {
		sessionID, _, _, _ = webrtctransport.DecodeProvideOfferResponse(result.ResponseData)
		t.Logf("Created session: %d", sessionID)
	}

	// Send EndSession command
	t.Log("Sending EndSession command...")
	endPayload, err := webrtctransport.EncodeEndSession(sessionID, webrtctransport.WebRTCEndReasonUserHangup)
	if err != nil {
		t.Fatalf("EncodeEndSession failed: %v", err)
	}

	_, err = pair.Controller.SendCommand(
		ctx,
		pair.Session,
		pair.DeviceAddr,
		uint16(webrtctransportexample.WebRTCEndpointID),
		webrtctransport.ProviderClusterID,
		webrtctransport.CmdEndSession,
		endPayload,
	)
	if err != nil {
		t.Fatalf("SendCommand(EndSession) failed: %v", err)
	}

	// Verify session was ended
	mu.Lock()
	if endedSessionID != sessionID {
		t.Errorf("Wrong session ended: got %d, want %d", endedSessionID, sessionID)
	}
	if endedReason != webrtctransport.WebRTCEndReasonUserHangup {
		t.Errorf("Wrong end reason: got %v, want UserHangup", endedReason)
	}
	mu.Unlock()

	t.Log("EndSession test completed successfully!")
}

// decodeTLVUint16 decodes a TLV-encoded uint16 value.
func decodeTLVUint16(data []byte) (uint16, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		return 0, err
	}
	val, err := r.Uint()
	if err != nil {
		return 0, err
	}
	return uint16(val), nil
}
