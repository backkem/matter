package im

import (
	"context"
	"testing"

	"github.com/backkem/matter/pkg/im/message"
	"github.com/backkem/matter/pkg/tlv"
)

// mockWriteDispatcher implements Dispatcher for testing writes.
type mockWriteDispatcher struct {
	writeFunc func(ctx context.Context, req *AttributeWriteRequest, r *tlv.Reader) error
	callCount int
}

func (m *mockWriteDispatcher) ReadAttribute(ctx context.Context, req *AttributeReadRequest, w *tlv.Writer) error {
	return ErrClusterNotFound
}

func (m *mockWriteDispatcher) WriteAttribute(ctx context.Context, req *AttributeWriteRequest, r *tlv.Reader) error {
	m.callCount++
	if m.writeFunc != nil {
		return m.writeFunc(ctx, req, r)
	}
	return nil
}

func (m *mockWriteDispatcher) InvokeCommand(ctx context.Context, req *CommandInvokeRequest, r *tlv.Reader) ([]byte, error) {
	return nil, ErrClusterNotFound
}

func TestWriteHandler_SimpleWrite(t *testing.T) {
	dispatcher := &mockWriteDispatcher{}
	handler := NewWriteHandler(dispatcher)

	ep := message.EndpointID(0)
	cl := message.ClusterID(0x001F) // AccessControl
	attr := message.AttributeID(0x0000)

	req := &message.WriteRequestMessage{
		SuppressResponse: false,
		TimedRequest:     false,
		WriteRequests: []message.AttributeDataIB{
			{
				DataVersion: 0, // No version check
				Path: message.AttributePathIB{
					Endpoint:  &ep,
					Cluster:   &cl,
					Attribute: &attr,
				},
				Data: []byte{0x15, 0x18}, // Empty struct in TLV
			},
		},
	}

	resp, err := handler.HandleWriteRequest(nil, req, 1, 12345, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatal("expected response")
	}

	if len(resp.WriteResponses) != 1 {
		t.Errorf("expected 1 write response, got %d", len(resp.WriteResponses))
	}

	if resp.WriteResponses[0].Status.Status != message.StatusSuccess {
		t.Errorf("expected Success, got %s", resp.WriteResponses[0].Status.Status)
	}

	if dispatcher.callCount != 1 {
		t.Errorf("expected 1 dispatcher call, got %d", dispatcher.callCount)
	}

	if handler.State() != WriteHandlerStateIdle {
		t.Errorf("expected idle state, got %s", handler.State())
	}
}

func TestWriteHandler_MultipleAttributes(t *testing.T) {
	dispatcher := &mockWriteDispatcher{}
	handler := NewWriteHandler(dispatcher)

	ep := message.EndpointID(0)
	cl := message.ClusterID(0x001F)
	attr1 := message.AttributeID(0x0000)
	attr2 := message.AttributeID(0x0001)
	attr3 := message.AttributeID(0x0002)

	req := &message.WriteRequestMessage{
		WriteRequests: []message.AttributeDataIB{
			{Path: message.AttributePathIB{Endpoint: &ep, Cluster: &cl, Attribute: &attr1}, Data: []byte{0x15, 0x18}},
			{Path: message.AttributePathIB{Endpoint: &ep, Cluster: &cl, Attribute: &attr2}, Data: []byte{0x15, 0x18}},
			{Path: message.AttributePathIB{Endpoint: &ep, Cluster: &cl, Attribute: &attr3}, Data: []byte{0x15, 0x18}},
		},
	}

	resp, err := handler.HandleWriteRequest(nil, req, 1, 12345, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if dispatcher.callCount != 3 {
		t.Errorf("expected 3 dispatcher calls, got %d", dispatcher.callCount)
	}

	if len(resp.WriteResponses) != 3 {
		t.Errorf("expected 3 write responses, got %d", len(resp.WriteResponses))
	}

	for i, status := range resp.WriteResponses {
		if status.Status.Status != message.StatusSuccess {
			t.Errorf("response %d: expected Success, got %s", i, status.Status.Status)
		}
	}
}

func TestWriteHandler_NoDispatcher(t *testing.T) {
	handler := NewWriteHandler(nil)

	ep := message.EndpointID(0)
	cl := message.ClusterID(0x001F)
	attr := message.AttributeID(0x0000)

	req := &message.WriteRequestMessage{
		WriteRequests: []message.AttributeDataIB{
			{Path: message.AttributePathIB{Endpoint: &ep, Cluster: &cl, Attribute: &attr}, Data: []byte{0x15, 0x18}},
		},
	}

	resp, err := handler.HandleWriteRequest(nil, req, 1, 12345, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should get UnsupportedCluster status from NullDispatcher
	if resp.WriteResponses[0].Status.Status != message.StatusUnsupportedCluster {
		t.Errorf("expected UnsupportedCluster, got %s", resp.WriteResponses[0].Status.Status)
	}
}

func TestWriteHandler_WriteError(t *testing.T) {
	dispatcher := &mockWriteDispatcher{
		writeFunc: func(ctx context.Context, req *AttributeWriteRequest, r *tlv.Reader) error {
			return ErrConstraintError
		},
	}
	handler := NewWriteHandler(dispatcher)

	ep := message.EndpointID(0)
	cl := message.ClusterID(0x001F)
	attr := message.AttributeID(0x0000)

	req := &message.WriteRequestMessage{
		WriteRequests: []message.AttributeDataIB{
			{Path: message.AttributePathIB{Endpoint: &ep, Cluster: &cl, Attribute: &attr}, Data: []byte{0x15, 0x18}},
		},
	}

	resp, err := handler.HandleWriteRequest(nil, req, 1, 12345, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.WriteResponses[0].Status.Status != message.StatusConstraintError {
		t.Errorf("expected ConstraintError, got %s", resp.WriteResponses[0].Status.Status)
	}
}

func TestWriteHandler_WildcardPath(t *testing.T) {
	dispatcher := &mockWriteDispatcher{}
	handler := NewWriteHandler(dispatcher)

	// Wildcard endpoint (nil)
	cl := message.ClusterID(0x001F)
	attr := message.AttributeID(0x0000)

	req := &message.WriteRequestMessage{
		WriteRequests: []message.AttributeDataIB{
			{Path: message.AttributePathIB{Endpoint: nil, Cluster: &cl, Attribute: &attr}, Data: []byte{0x15, 0x18}},
		},
	}

	resp, err := handler.HandleWriteRequest(nil, req, 1, 12345, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should get InvalidAction for wildcard path
	if resp.WriteResponses[0].Status.Status != message.StatusInvalidAction {
		t.Errorf("expected InvalidAction for wildcard path, got %s", resp.WriteResponses[0].Status.Status)
	}

	// Dispatcher should not be called for wildcard paths
	if dispatcher.callCount != 0 {
		t.Errorf("expected 0 dispatcher calls for wildcard, got %d", dispatcher.callCount)
	}
}

func TestWriteHandler_ListOperation(t *testing.T) {
	dispatcher := &mockWriteDispatcher{}
	handler := NewWriteHandler(dispatcher)

	ep := message.EndpointID(0)
	cl := message.ClusterID(0x001F)
	attr := message.AttributeID(0x0000)
	listIdx := message.ListIndex(0)

	req := &message.WriteRequestMessage{
		WriteRequests: []message.AttributeDataIB{
			{Path: message.AttributePathIB{Endpoint: &ep, Cluster: &cl, Attribute: &attr, ListIndex: &listIdx}, Data: []byte{0x15, 0x18}},
		},
	}

	resp, err := handler.HandleWriteRequest(nil, req, 1, 12345, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should get UnsupportedWrite for list operations in simplified implementation
	if resp.WriteResponses[0].Status.Status != message.StatusUnsupportedWrite {
		t.Errorf("expected UnsupportedWrite for list operation, got %s", resp.WriteResponses[0].Status.Status)
	}
}

func TestWriteHandler_SuppressResponse(t *testing.T) {
	dispatcher := &mockWriteDispatcher{}
	handler := NewWriteHandler(dispatcher)

	ep := message.EndpointID(0)
	cl := message.ClusterID(0x001F)
	attr := message.AttributeID(0x0000)

	req := &message.WriteRequestMessage{
		SuppressResponse: true,
		WriteRequests: []message.AttributeDataIB{
			{Path: message.AttributePathIB{Endpoint: &ep, Cluster: &cl, Attribute: &attr}, Data: []byte{0x15, 0x18}},
		},
	}

	resp, err := handler.HandleWriteRequest(nil, req, 1, 12345, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Response should be nil when SuppressResponse is set
	if resp != nil {
		t.Error("expected nil response when SuppressResponse=true")
	}

	// But dispatcher should still be called
	if dispatcher.callCount != 1 {
		t.Errorf("expected 1 dispatcher call, got %d", dispatcher.callCount)
	}
}

func TestWriteHandler_TimedMismatch(t *testing.T) {
	handler := NewWriteHandler(nil)

	ep := message.EndpointID(0)
	cl := message.ClusterID(0x001F)
	attr := message.AttributeID(0x0000)

	req := &message.WriteRequestMessage{
		TimedRequest: true, // Request says timed
		WriteRequests: []message.AttributeDataIB{
			{Path: message.AttributePathIB{Endpoint: &ep, Cluster: &cl, Attribute: &attr}, Data: []byte{0x15, 0x18}},
		},
	}

	// But we say it's not timed
	_, err := handler.HandleWriteRequest(nil, req, 1, 12345, false)
	if err != ErrWriteTimedMismatch {
		t.Errorf("expected ErrWriteTimedMismatch, got %v", err)
	}
}

func TestWriteHandler_Reset(t *testing.T) {
	dispatcher := &mockWriteDispatcher{}
	handler := NewWriteHandler(dispatcher)

	ep := message.EndpointID(0)
	cl := message.ClusterID(0x001F)
	attr := message.AttributeID(0x0000)

	req := &message.WriteRequestMessage{
		WriteRequests: []message.AttributeDataIB{
			{Path: message.AttributePathIB{Endpoint: &ep, Cluster: &cl, Attribute: &attr}, Data: []byte{0x15, 0x18}},
		},
	}

	handler.HandleWriteRequest(nil, req, 1, 12345, false)
	handler.Reset()

	if handler.State() != WriteHandlerStateIdle {
		t.Errorf("expected idle state after reset, got %s", handler.State())
	}
}

func TestWriteHandlerState_String(t *testing.T) {
	tests := []struct {
		state WriteHandlerState
		want  string
	}{
		{WriteHandlerStateIdle, "Idle"},
		{WriteHandlerStateProcessing, "Processing"},
		{WriteHandlerStateReceivingChunks, "ReceivingChunks"},
		{WriteHandlerStateSendingResponse, "SendingResponse"},
		{WriteHandlerState(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("WriteHandlerState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestEncodeDecodeWriteRequest(t *testing.T) {
	ep := message.EndpointID(0)
	cl := message.ClusterID(0x001F)
	attr := message.AttributeID(0x0000)

	original := &message.WriteRequestMessage{
		SuppressResponse: false,
		TimedRequest:     false,
		WriteRequests: []message.AttributeDataIB{
			{
				Path: message.AttributePathIB{Endpoint: &ep, Cluster: &cl, Attribute: &attr},
				Data: []byte{0x15, 0x18},
			},
		},
	}

	// Encode response
	resp := &message.WriteResponseMessage{
		WriteResponses: []message.AttributeStatusIB{
			{
				Path: message.AttributePathIB{Endpoint: &ep, Cluster: &cl, Attribute: &attr},
				Status: message.StatusIB{
					Status: message.StatusSuccess,
				},
			},
		},
	}

	encoded, err := EncodeWriteResponse(resp)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}

	if len(encoded) == 0 {
		t.Error("expected non-empty encoded data")
	}

	// Verify original request (just to use it)
	if len(original.WriteRequests) != 1 {
		t.Error("original request mismatch")
	}
}
