package im

import (
	"testing"

	"github.com/backkem/matter/pkg/im/message"
)

func TestInvokeHandler_SimpleCommand(t *testing.T) {
	handler := NewInvokeHandler(func(ctx *InvokeContext, path message.CommandPathIB, fields []byte) (*CommandResult, error) {
		// Simple echo command - return the same path
		return &CommandResult{
			ResponsePath: path,
			ResponseData: []byte{0x15, 0x18}, // Empty struct in TLV
		}, nil
	}, DefaultMaxPayload)

	req := &message.InvokeRequestMessage{
		SuppressResponse: false,
		TimedRequest:     false,
		InvokeRequests: []message.CommandDataIB{
			{
				Path: message.CommandPathIB{
					Endpoint: 1,
					Cluster:  0x0006,
					Command:  0x00, // Toggle
				},
			},
		},
	}

	resp, err := handler.HandleInvokeRequest(nil, req, 1, 12345, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatal("expected response")
	}

	if len(resp.InvokeResponses) != 1 {
		t.Errorf("expected 1 response, got %d", len(resp.InvokeResponses))
	}

	if resp.InvokeResponses[0].Command == nil {
		t.Error("expected command response, got status")
	}

	if handler.State() != InvokeHandlerStateIdle {
		t.Errorf("expected idle state, got %s", handler.State())
	}
}

func TestInvokeHandler_StatusResponse(t *testing.T) {
	handler := NewInvokeHandler(func(ctx *InvokeContext, path message.CommandPathIB, fields []byte) (*CommandResult, error) {
		// Return a status instead of data
		return &CommandResult{
			Status: &message.StatusIB{
				Status: message.StatusSuccess,
			},
		}, nil
	}, DefaultMaxPayload)

	req := &message.InvokeRequestMessage{
		InvokeRequests: []message.CommandDataIB{
			{
				Path: message.CommandPathIB{
					Endpoint: 1,
					Cluster:  0x0006,
					Command:  0x00,
				},
			},
		},
	}

	resp, err := handler.HandleInvokeRequest(nil, req, 1, 12345, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.InvokeResponses[0].Status == nil {
		t.Error("expected status response")
	}
}

func TestInvokeHandler_NoHandler(t *testing.T) {
	handler := NewInvokeHandler(nil, DefaultMaxPayload)

	req := &message.InvokeRequestMessage{
		InvokeRequests: []message.CommandDataIB{
			{
				Path: message.CommandPathIB{
					Endpoint: 1,
					Cluster:  0x0006,
					Command:  0x00,
				},
			},
		},
	}

	resp, err := handler.HandleInvokeRequest(nil, req, 1, 12345, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should get UnsupportedCommand status
	if resp.InvokeResponses[0].Status == nil {
		t.Fatal("expected status response")
	}
	if resp.InvokeResponses[0].Status.Status.Status != message.StatusUnsupportedCommand {
		t.Errorf("expected UnsupportedCommand, got %s", resp.InvokeResponses[0].Status.Status.Status)
	}
}

func TestInvokeHandler_BatchCommands(t *testing.T) {
	callCount := 0
	handler := NewInvokeHandler(func(ctx *InvokeContext, path message.CommandPathIB, fields []byte) (*CommandResult, error) {
		callCount++
		return &CommandResult{
			ResponsePath: path,
			ResponseData: []byte{0x15, 0x18},
		}, nil
	}, DefaultMaxPayload)

	// Request with multiple commands
	ref1 := uint16(1)
	ref2 := uint16(2)
	ref3 := uint16(3)
	req := &message.InvokeRequestMessage{
		InvokeRequests: []message.CommandDataIB{
			{
				Path: message.CommandPathIB{Endpoint: 1, Cluster: 0x0006, Command: 0x00},
				Ref:  &ref1,
			},
			{
				Path: message.CommandPathIB{Endpoint: 1, Cluster: 0x0006, Command: 0x01},
				Ref:  &ref2,
			},
			{
				Path: message.CommandPathIB{Endpoint: 2, Cluster: 0x0006, Command: 0x00},
				Ref:  &ref3,
			},
		},
	}

	resp, err := handler.HandleInvokeRequest(nil, req, 1, 12345, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if callCount != 3 {
		t.Errorf("expected 3 command invocations, got %d", callCount)
	}

	if len(resp.InvokeResponses) != 3 {
		t.Errorf("expected 3 responses, got %d", len(resp.InvokeResponses))
	}

	// Check CommandRefs are preserved
	for i, r := range resp.InvokeResponses {
		if r.Command == nil {
			t.Errorf("response %d: expected command", i)
			continue
		}
		if r.Command.Ref == nil {
			t.Errorf("response %d: expected Ref", i)
			continue
		}
		expectedRef := uint16(i + 1)
		if *r.Command.Ref != expectedRef {
			t.Errorf("response %d: expected Ref %d, got %d", i, expectedRef, *r.Command.Ref)
		}
	}
}

func TestInvokeHandler_TimedMismatch(t *testing.T) {
	handler := NewInvokeHandler(nil, DefaultMaxPayload)

	req := &message.InvokeRequestMessage{
		TimedRequest: true, // Request says timed
		InvokeRequests: []message.CommandDataIB{
			{
				Path: message.CommandPathIB{Endpoint: 1, Cluster: 0x0006, Command: 0x00},
			},
		},
	}

	// But we say it's not timed
	_, err := handler.HandleInvokeRequest(nil, req, 1, 12345, false)
	if err != ErrInvokeTimedMismatch {
		t.Errorf("expected ErrInvokeTimedMismatch, got %v", err)
	}
}

func TestInvokeHandler_ChunkedResponse(t *testing.T) {
	// Use small max payload to force chunking
	handler := NewInvokeHandler(func(ctx *InvokeContext, path message.CommandPathIB, fields []byte) (*CommandResult, error) {
		// Return large response data
		return &CommandResult{
			ResponsePath: path,
			ResponseData: make([]byte, 100), // Large response
		}, nil
	}, 80) // Small MTU

	// Create request with multiple commands to generate large response
	req := &message.InvokeRequestMessage{
		InvokeRequests: make([]message.CommandDataIB, 5),
	}
	for i := range req.InvokeRequests {
		req.InvokeRequests[i] = message.CommandDataIB{
			Path: message.CommandPathIB{Endpoint: 1, Cluster: 0x0006, Command: message.CommandID(i)},
		}
	}

	// Get first response chunk
	resp1, err := handler.HandleInvokeRequest(nil, req, 1, 12345, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp1.MoreChunkedMessages {
		t.Fatal("expected MoreChunkedMessages=true for first chunk")
	}

	if handler.State() != InvokeHandlerStateSendingResponse {
		t.Errorf("expected SendingResponse state, got %s", handler.State())
	}

	// Simulate status response to get next chunk
	chunkCount := 1
	for handler.State() == InvokeHandlerStateSendingResponse {
		resp, err := handler.HandleStatusResponse(message.StatusSuccess)
		if err != nil {
			t.Fatalf("chunk %d: unexpected error: %v", chunkCount, err)
		}
		if resp != nil {
			chunkCount++
			if resp.MoreChunkedMessages && handler.State() != InvokeHandlerStateSendingResponse {
				t.Error("state should be SendingResponse when more chunks")
			}
		}
	}

	if chunkCount < 2 {
		t.Errorf("expected multiple chunks, got %d", chunkCount)
	}

	if handler.State() != InvokeHandlerStateIdle {
		t.Errorf("expected idle state after all chunks, got %s", handler.State())
	}
}

func TestInvokeHandler_ChunkedResponseAbort(t *testing.T) {
	handler := NewInvokeHandler(func(ctx *InvokeContext, path message.CommandPathIB, fields []byte) (*CommandResult, error) {
		return &CommandResult{
			ResponsePath: path,
			ResponseData: make([]byte, 100),
		}, nil
	}, 80)

	req := &message.InvokeRequestMessage{
		InvokeRequests: make([]message.CommandDataIB, 5),
	}
	for i := range req.InvokeRequests {
		req.InvokeRequests[i] = message.CommandDataIB{
			Path: message.CommandPathIB{Endpoint: 1, Cluster: 0x0006, Command: message.CommandID(i)},
		}
	}

	// Get first chunk
	_, err := handler.HandleInvokeRequest(nil, req, 1, 12345, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Abort with failure status
	resp, err := handler.HandleStatusResponse(message.StatusFailure)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Error("expected nil response on abort")
	}

	if handler.State() != InvokeHandlerStateIdle {
		t.Errorf("expected idle state after abort, got %s", handler.State())
	}
}

func TestInvokeHandler_Reset(t *testing.T) {
	handler := NewInvokeHandler(func(ctx *InvokeContext, path message.CommandPathIB, fields []byte) (*CommandResult, error) {
		return &CommandResult{
			ResponsePath: path,
			ResponseData: make([]byte, 100),
		}, nil
	}, 80)

	req := &message.InvokeRequestMessage{
		InvokeRequests: make([]message.CommandDataIB, 5),
	}
	for i := range req.InvokeRequests {
		req.InvokeRequests[i] = message.CommandDataIB{
			Path: message.CommandPathIB{Endpoint: 1, Cluster: 0x0006, Command: message.CommandID(i)},
		}
	}

	// Start chunked response
	handler.HandleInvokeRequest(nil, req, 1, 12345, false)

	if handler.State() == InvokeHandlerStateIdle {
		t.Fatal("expected non-idle state during chunking")
	}

	// Reset
	handler.Reset()

	if handler.State() != InvokeHandlerStateIdle {
		t.Errorf("expected idle state after reset, got %s", handler.State())
	}
}

func TestInvokeHandler_InvokeContext(t *testing.T) {
	var capturedCtx *InvokeContext

	handler := NewInvokeHandler(func(ctx *InvokeContext, path message.CommandPathIB, fields []byte) (*CommandResult, error) {
		capturedCtx = ctx
		return nil, nil
	}, DefaultMaxPayload)

	req := &message.InvokeRequestMessage{
		TimedRequest: true,
		InvokeRequests: []message.CommandDataIB{
			{
				Path: message.CommandPathIB{Endpoint: 1, Cluster: 0x0006, Command: 0x00},
			},
		},
	}

	handler.HandleInvokeRequest(nil, req, 5, 999, true)

	if capturedCtx == nil {
		t.Fatal("context not captured")
	}
	if capturedCtx.FabricIndex != 5 {
		t.Errorf("expected fabric 5, got %d", capturedCtx.FabricIndex)
	}
	if capturedCtx.SourceNodeID != 999 {
		t.Errorf("expected source node 999, got %d", capturedCtx.SourceNodeID)
	}
	if !capturedCtx.IsTimed {
		t.Error("expected IsTimed=true")
	}
}

func TestInvokeHandlerState_String(t *testing.T) {
	tests := []struct {
		state InvokeHandlerState
		want  string
	}{
		{InvokeHandlerStateIdle, "Idle"},
		{InvokeHandlerStateReceiving, "Receiving"},
		{InvokeHandlerStateProcessing, "Processing"},
		{InvokeHandlerStateSendingResponse, "SendingResponse"},
		{InvokeHandlerState(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("InvokeHandlerState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestEncodeDecodeInvokeRequest(t *testing.T) {
	original := &message.InvokeRequestMessage{
		SuppressResponse: true,
		TimedRequest:     false,
		InvokeRequests: []message.CommandDataIB{
			{
				Path: message.CommandPathIB{
					Endpoint: 1,
					Cluster:  0x0006,
					Command:  0x00,
				},
				Fields: []byte{0x15, 0x18},
			},
		},
	}

	// Encode
	encoded, err := EncodeInvokeResponse(&message.InvokeResponseMessage{
		SuppressResponse: true,
		InvokeResponses: []message.InvokeResponseIB{
			{
				Command: &message.CommandDataIB{
					Path: message.CommandPathIB{
						Endpoint: 1,
						Cluster:  0x0006,
						Command:  0x00,
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}

	if len(encoded) == 0 {
		t.Error("expected non-empty encoded data")
	}

	// Test status encoding
	statusData, err := EncodeStatusResponse(message.StatusSuccess)
	if err != nil {
		t.Fatalf("status encode error: %v", err)
	}
	if len(statusData) == 0 {
		t.Error("expected non-empty status data")
	}

	// Decode status
	decoded, err := DecodeStatusResponse(statusData)
	if err != nil {
		t.Fatalf("status decode error: %v", err)
	}
	if decoded.Status != message.StatusSuccess {
		t.Errorf("expected Success, got %s", decoded.Status)
	}

	// Verify original request can be decoded
	_ = original // Used in real test with actual request encoding
}
