package im

import (
	"bytes"
	"context"
	"testing"

	imsg "github.com/backkem/matter/pkg/im/message"
	"github.com/backkem/matter/pkg/message"
	"github.com/backkem/matter/pkg/tlv"
)

// testDispatcher implements Dispatcher for engine testing.
type testDispatcher struct {
	readFunc   func(ctx context.Context, req *AttributeReadRequest, w *tlv.Writer) error
	writeFunc  func(ctx context.Context, req *AttributeWriteRequest, r *tlv.Reader) error
	invokeFunc func(ctx context.Context, req *CommandInvokeRequest, r *tlv.Reader) ([]byte, error)
}

func (d *testDispatcher) ReadAttribute(ctx context.Context, req *AttributeReadRequest, w *tlv.Writer) error {
	if d.readFunc != nil {
		return d.readFunc(ctx, req, w)
	}
	return ErrClusterNotFound
}

func (d *testDispatcher) WriteAttribute(ctx context.Context, req *AttributeWriteRequest, r *tlv.Reader) error {
	if d.writeFunc != nil {
		return d.writeFunc(ctx, req, r)
	}
	return ErrClusterNotFound
}

func (d *testDispatcher) InvokeCommand(ctx context.Context, req *CommandInvokeRequest, r *tlv.Reader) ([]byte, error) {
	if d.invokeFunc != nil {
		return d.invokeFunc(ctx, req, r)
	}
	return nil, ErrClusterNotFound
}

func TestEngine_New(t *testing.T) {
	engine := NewEngine(EngineConfig{})

	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if engine.maxPayload != DefaultMaxPayload {
		t.Errorf("maxPayload = %d, want %d", engine.maxPayload, DefaultMaxPayload)
	}
}

func TestEngine_NewWithConfig(t *testing.T) {
	dispatcher := &testDispatcher{}

	engine := NewEngine(EngineConfig{
		Dispatcher: dispatcher,
		MaxPayload: 2000,
	})

	if engine.maxPayload != 2000 {
		t.Errorf("maxPayload = %d, want 2000", engine.maxPayload)
	}
}

func TestEngine_GetProtocolID(t *testing.T) {
	engine := NewEngine(EngineConfig{})

	if got := engine.GetProtocolID(); got != ProtocolID {
		t.Errorf("GetProtocolID() = %v, want %v", got, ProtocolID)
	}
}

func TestEngine_OnMessage_InvalidOpcode(t *testing.T) {
	engine := NewEngine(EngineConfig{})

	header := &message.ProtocolHeader{
		ProtocolOpcode: 0xFF, // Invalid opcode
	}

	resp, err := engine.OnMessage(nil, header, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should return StatusResponse with InvalidAction
	statusMsg, err := DecodeStatusResponse(resp)
	if err != nil {
		t.Fatalf("failed to decode status response: %v", err)
	}
	if statusMsg.Status != imsg.StatusInvalidAction {
		t.Errorf("Status = %v, want InvalidAction", statusMsg.Status)
	}
}

func TestEngine_OnMessage_SubscribeRequest_Unsupported(t *testing.T) {
	engine := NewEngine(EngineConfig{})

	header := &message.ProtocolHeader{
		ProtocolOpcode: uint8(imsg.OpcodeSubscribeRequest),
	}

	resp, err := engine.OnMessage(nil, header, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	statusMsg, err := DecodeStatusResponse(resp)
	if err != nil {
		t.Fatalf("failed to decode status response: %v", err)
	}
	if statusMsg.Status != imsg.StatusUnsupportedAccess {
		t.Errorf("Status = %v, want UnsupportedAccess", statusMsg.Status)
	}
}

func TestEngine_OnMessage_TimedRequest_Unsupported(t *testing.T) {
	engine := NewEngine(EngineConfig{})

	header := &message.ProtocolHeader{
		ProtocolOpcode: uint8(imsg.OpcodeTimedRequest),
	}

	resp, err := engine.OnMessage(nil, header, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	statusMsg, err := DecodeStatusResponse(resp)
	if err != nil {
		t.Fatalf("failed to decode status response: %v", err)
	}
	if statusMsg.Status != imsg.StatusUnsupportedAccess {
		t.Errorf("Status = %v, want UnsupportedAccess", statusMsg.Status)
	}
}

func TestEngine_OnMessage_ReadRequest(t *testing.T) {
	dispatcher := &testDispatcher{
		readFunc: func(ctx context.Context, req *AttributeReadRequest, w *tlv.Writer) error {
			// Write a simple boolean value
			return w.PutBool(tlv.Anonymous(), true)
		},
	}

	engine := NewEngine(EngineConfig{Dispatcher: dispatcher})

	// Build a ReadRequest
	ep := imsg.EndpointID(0)
	cl := imsg.ClusterID(0x001D)
	attr := imsg.AttributeID(0x0000)

	req := &imsg.ReadRequestMessage{
		AttributeRequests: []imsg.AttributePathIB{
			{
				Endpoint:  &ep,
				Cluster:   &cl,
				Attribute: &attr,
			},
		},
		FabricFiltered: false,
	}

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := req.Encode(w); err != nil {
		t.Fatalf("failed to encode request: %v", err)
	}

	header := &message.ProtocolHeader{
		ProtocolOpcode: uint8(imsg.OpcodeReadRequest),
	}

	resp, err := engine.OnMessage(nil, header, buf.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp) == 0 {
		t.Error("expected non-empty response")
	}

	// Verify it's a ReportData message
	r := tlv.NewReader(bytes.NewReader(resp))
	var report imsg.ReportDataMessage
	if err := report.Decode(r); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
}

func TestEngine_OnMessage_ReadRequest_Invalid(t *testing.T) {
	engine := NewEngine(EngineConfig{})

	header := &message.ProtocolHeader{
		ProtocolOpcode: uint8(imsg.OpcodeReadRequest),
	}

	// Invalid TLV data
	resp, err := engine.OnMessage(nil, header, []byte{0xFF, 0xFF})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	statusMsg, err := DecodeStatusResponse(resp)
	if err != nil {
		t.Fatalf("failed to decode status response: %v", err)
	}
	if statusMsg.Status != imsg.StatusInvalidAction {
		t.Errorf("Status = %v, want InvalidAction", statusMsg.Status)
	}
}

func TestEngine_OnMessage_WriteRequest(t *testing.T) {
	writeCalled := false
	dispatcher := &testDispatcher{
		writeFunc: func(ctx context.Context, req *AttributeWriteRequest, r *tlv.Reader) error {
			writeCalled = true
			return nil
		},
	}

	engine := NewEngine(EngineConfig{Dispatcher: dispatcher})

	// Build a WriteRequest
	ep := imsg.EndpointID(0)
	cl := imsg.ClusterID(0x001F)
	attr := imsg.AttributeID(0x0000)

	req := &imsg.WriteRequestMessage{
		WriteRequests: []imsg.AttributeDataIB{
			{
				Path: imsg.AttributePathIB{
					Endpoint:  &ep,
					Cluster:   &cl,
					Attribute: &attr,
				},
				Data: []byte{0x15, 0x18}, // Empty struct
			},
		},
	}

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := req.Encode(w); err != nil {
		t.Fatalf("failed to encode request: %v", err)
	}

	header := &message.ProtocolHeader{
		ProtocolOpcode: uint8(imsg.OpcodeWriteRequest),
	}

	resp, err := engine.OnMessage(nil, header, buf.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !writeCalled {
		t.Error("expected write handler to be called")
	}

	// Verify it's a WriteResponse message
	r := tlv.NewReader(bytes.NewReader(resp))
	var writeResp imsg.WriteResponseMessage
	if err := writeResp.Decode(r); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(writeResp.WriteResponses) != 1 {
		t.Errorf("expected 1 write response, got %d", len(writeResp.WriteResponses))
	}
}

func TestEngine_OnMessage_WriteRequest_SuppressResponse(t *testing.T) {
	dispatcher := &testDispatcher{
		writeFunc: func(ctx context.Context, req *AttributeWriteRequest, r *tlv.Reader) error {
			return nil
		},
	}

	engine := NewEngine(EngineConfig{Dispatcher: dispatcher})

	// Build a WriteRequest with SuppressResponse
	ep := imsg.EndpointID(0)
	cl := imsg.ClusterID(0x001F)
	attr := imsg.AttributeID(0x0000)

	req := &imsg.WriteRequestMessage{
		SuppressResponse: true,
		WriteRequests: []imsg.AttributeDataIB{
			{
				Path: imsg.AttributePathIB{
					Endpoint:  &ep,
					Cluster:   &cl,
					Attribute: &attr,
				},
				Data: []byte{0x15, 0x18},
			},
		},
	}

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := req.Encode(w); err != nil {
		t.Fatalf("failed to encode request: %v", err)
	}

	header := &message.ProtocolHeader{
		ProtocolOpcode: uint8(imsg.OpcodeWriteRequest),
	}

	resp, err := engine.OnMessage(nil, header, buf.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Response should be nil when SuppressResponse is true
	if resp != nil {
		t.Errorf("expected nil response, got %d bytes", len(resp))
	}
}

func TestEngine_OnMessage_InvokeRequest(t *testing.T) {
	invokeCalled := false
	dispatcher := &testDispatcher{
		invokeFunc: func(ctx context.Context, req *CommandInvokeRequest, r *tlv.Reader) ([]byte, error) {
			invokeCalled = true
			return nil, nil // No response data
		},
	}

	engine := NewEngine(EngineConfig{Dispatcher: dispatcher})

	// Build an InvokeRequest
	req := &imsg.InvokeRequestMessage{
		InvokeRequests: []imsg.CommandDataIB{
			{
				Path: imsg.CommandPathIB{
					Endpoint: 1,
					Cluster:  0x0006, // OnOff
					Command:  2,      // Toggle
				},
			},
		},
	}

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := req.Encode(w); err != nil {
		t.Fatalf("failed to encode request: %v", err)
	}

	header := &message.ProtocolHeader{
		ProtocolOpcode: uint8(imsg.OpcodeInvokeRequest),
	}

	resp, err := engine.OnMessage(nil, header, buf.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !invokeCalled {
		t.Error("expected invoke handler to be called")
	}

	// Verify it's an InvokeResponse message
	r := tlv.NewReader(bytes.NewReader(resp))
	var invokeResp imsg.InvokeResponseMessage
	if err := invokeResp.Decode(r); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
}

func TestEngine_OnMessage_StatusResponse_NoActiveHandler(t *testing.T) {
	engine := NewEngine(EngineConfig{})

	// Encode a status response
	statusReq := &imsg.StatusResponseMessage{
		Status: imsg.StatusSuccess,
	}

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := statusReq.Encode(w); err != nil {
		t.Fatalf("failed to encode status: %v", err)
	}

	header := &message.ProtocolHeader{
		ProtocolOpcode: uint8(imsg.OpcodeStatusResponse),
	}

	resp, err := engine.OnMessage(nil, header, buf.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No active handler, so no response
	if resp != nil {
		t.Errorf("expected nil response, got %d bytes", len(resp))
	}
}

func TestEngine_OnClose(t *testing.T) {
	engine := NewEngine(EngineConfig{})

	// Should not panic
	engine.OnClose(nil)

	// Verify handlers are reset
	if engine.readHandler.State() != ReadHandlerStateIdle {
		t.Errorf("readHandler state = %v, want Idle", engine.readHandler.State())
	}
	if engine.writeHandler.State() != WriteHandlerStateIdle {
		t.Errorf("writeHandler state = %v, want Idle", engine.writeHandler.State())
	}
	if engine.invokeHandler.State() != InvokeHandlerStateIdle {
		t.Errorf("invokeHandler state = %v, want Idle", engine.invokeHandler.State())
	}
}

func TestProtocolID_Value(t *testing.T) {
	// Spec: Section 10.2.1 - IM Protocol ID is 0x0001
	if ProtocolID != 0x0001 {
		t.Errorf("ProtocolID = %v, want 0x0001", ProtocolID)
	}
}

func TestEngine_DispatcherErrorMapping(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus imsg.Status
	}{
		{"cluster not found", ErrClusterNotFound, imsg.StatusUnsupportedCluster},
		{"access denied", ErrAccessDenied, imsg.StatusUnsupportedAccess},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dispatcher := &testDispatcher{
				invokeFunc: func(ctx context.Context, req *CommandInvokeRequest, r *tlv.Reader) ([]byte, error) {
					return nil, tt.err
				},
			}

			engine := NewEngine(EngineConfig{Dispatcher: dispatcher})

			req := &imsg.InvokeRequestMessage{
				InvokeRequests: []imsg.CommandDataIB{
					{
						Path: imsg.CommandPathIB{
							Endpoint: 1,
							Cluster:  0x0006,
							Command:  0,
						},
					},
				},
			}

			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)
			if err := req.Encode(w); err != nil {
				t.Fatalf("failed to encode request: %v", err)
			}

			header := &message.ProtocolHeader{
				ProtocolOpcode: uint8(imsg.OpcodeInvokeRequest),
			}

			resp, err := engine.OnMessage(nil, header, buf.Bytes())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Parse the InvokeResponse to verify status
			r := tlv.NewReader(bytes.NewReader(resp))
			var invokeResp imsg.InvokeResponseMessage
			if err := invokeResp.Decode(r); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if len(invokeResp.InvokeResponses) != 1 {
				t.Fatalf("expected 1 response, got %d", len(invokeResp.InvokeResponses))
			}

			if invokeResp.InvokeResponses[0].Status == nil {
				t.Fatal("expected status response")
			}

			if invokeResp.InvokeResponses[0].Status.Status.Status != tt.wantStatus {
				t.Errorf("status = %v, want %v", invokeResp.InvokeResponses[0].Status.Status.Status, tt.wantStatus)
			}
		})
	}
}
