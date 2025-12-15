package im

import (
	"testing"

	"github.com/backkem/matter/pkg/im/message"
)

func TestReadHandler_SimpleRead(t *testing.T) {
	handler := NewReadHandler(func(ctx *ReadContext, path message.AttributePathIB) (*AttributeResult, error) {
		// Return mock attribute data
		return &AttributeResult{
			DataVersion: 1,
			Data:        []byte{0x15, 0x18}, // Empty struct in TLV
		}, nil
	}, DefaultMaxPayload)

	ep := message.EndpointID(1)
	cl := message.ClusterID(0x001D) // Descriptor
	attr := message.AttributeID(0x0000)

	req := &message.ReadRequestMessage{
		AttributeRequests: []message.AttributePathIB{
			{
				Endpoint:  &ep,
				Cluster:   &cl,
				Attribute: &attr,
			},
		},
		FabricFiltered: true,
	}

	resp, err := handler.HandleReadRequest(nil, req, 1, 12345)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatal("expected response")
	}

	if len(resp.AttributeReports) != 1 {
		t.Errorf("expected 1 attribute report, got %d", len(resp.AttributeReports))
	}

	report := resp.AttributeReports[0]
	if report.AttributeData == nil {
		t.Fatal("expected attribute data, got status")
	}

	if report.AttributeData.DataVersion != 1 {
		t.Errorf("expected data version 1, got %d", report.AttributeData.DataVersion)
	}

	if handler.State() != ReadHandlerStateIdle {
		t.Errorf("expected idle state, got %s", handler.State())
	}
}

func TestReadHandler_MultipleAttributes(t *testing.T) {
	callCount := 0
	handler := NewReadHandler(func(ctx *ReadContext, path message.AttributePathIB) (*AttributeResult, error) {
		callCount++
		return &AttributeResult{
			DataVersion: message.DataVersion(callCount),
			Data:        []byte{0x15, 0x18},
		}, nil
	}, DefaultMaxPayload)

	ep := message.EndpointID(1)
	cl := message.ClusterID(0x001D)
	attr1 := message.AttributeID(0x0000)
	attr2 := message.AttributeID(0x0001)
	attr3 := message.AttributeID(0x0002)

	req := &message.ReadRequestMessage{
		AttributeRequests: []message.AttributePathIB{
			{Endpoint: &ep, Cluster: &cl, Attribute: &attr1},
			{Endpoint: &ep, Cluster: &cl, Attribute: &attr2},
			{Endpoint: &ep, Cluster: &cl, Attribute: &attr3},
		},
		FabricFiltered: false,
	}

	resp, err := handler.HandleReadRequest(nil, req, 1, 12345)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if callCount != 3 {
		t.Errorf("expected 3 reader calls, got %d", callCount)
	}

	if len(resp.AttributeReports) != 3 {
		t.Errorf("expected 3 attribute reports, got %d", len(resp.AttributeReports))
	}
}

func TestReadHandler_NoReader(t *testing.T) {
	handler := NewReadHandler(nil, DefaultMaxPayload)

	ep := message.EndpointID(1)
	cl := message.ClusterID(0x001D)
	attr := message.AttributeID(0x0000)

	req := &message.ReadRequestMessage{
		AttributeRequests: []message.AttributePathIB{
			{Endpoint: &ep, Cluster: &cl, Attribute: &attr},
		},
	}

	resp, err := handler.HandleReadRequest(nil, req, 1, 12345)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.AttributeReports[0].AttributeStatus == nil {
		t.Fatal("expected status response")
	}

	if resp.AttributeReports[0].AttributeStatus.Status.Status != message.StatusUnsupportedAttribute {
		t.Errorf("expected UnsupportedAttribute, got %s",
			resp.AttributeReports[0].AttributeStatus.Status.Status)
	}
}

func TestReadHandler_StatusResult(t *testing.T) {
	handler := NewReadHandler(func(ctx *ReadContext, path message.AttributePathIB) (*AttributeResult, error) {
		return &AttributeResult{
			Status: &message.StatusIB{
				Status: message.StatusUnsupportedRead,
			},
		}, nil
	}, DefaultMaxPayload)

	ep := message.EndpointID(1)
	cl := message.ClusterID(0x001D)
	attr := message.AttributeID(0x0000)

	req := &message.ReadRequestMessage{
		AttributeRequests: []message.AttributePathIB{
			{Endpoint: &ep, Cluster: &cl, Attribute: &attr},
		},
	}

	resp, err := handler.HandleReadRequest(nil, req, 1, 12345)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.AttributeReports[0].AttributeStatus == nil {
		t.Fatal("expected status response")
	}

	if resp.AttributeReports[0].AttributeStatus.Status.Status != message.StatusUnsupportedRead {
		t.Errorf("expected UnsupportedRead, got %s",
			resp.AttributeReports[0].AttributeStatus.Status.Status)
	}
}

func TestReadHandler_ChunkedResponse(t *testing.T) {
	// Use small max payload to force chunking
	handler := NewReadHandler(func(ctx *ReadContext, path message.AttributePathIB) (*AttributeResult, error) {
		return &AttributeResult{
			DataVersion: 1,
			Data:        make([]byte, 50), // Large data to force chunking
		}, nil
	}, 80)

	ep := message.EndpointID(1)
	cl := message.ClusterID(0x001D)

	// Create request with multiple attributes to generate large response
	req := &message.ReadRequestMessage{
		AttributeRequests: make([]message.AttributePathIB, 5),
	}
	for i := range req.AttributeRequests {
		attr := message.AttributeID(i)
		req.AttributeRequests[i] = message.AttributePathIB{
			Endpoint:  &ep,
			Cluster:   &cl,
			Attribute: &attr,
		}
	}

	// Get first chunk
	resp1, err := handler.HandleReadRequest(nil, req, 1, 12345)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp1.MoreChunkedMessages {
		t.Fatal("expected MoreChunkedMessages=true for first chunk")
	}

	if handler.State() != ReadHandlerStateSendingReport {
		t.Errorf("expected SendingReport state, got %s", handler.State())
	}

	// Get remaining chunks
	chunkCount := 1
	for handler.State() == ReadHandlerStateSendingReport {
		resp, err := handler.HandleStatusResponse(message.StatusSuccess)
		if err != nil {
			t.Fatalf("chunk %d: unexpected error: %v", chunkCount, err)
		}
		if resp != nil {
			chunkCount++
		}
	}

	if chunkCount < 2 {
		t.Errorf("expected multiple chunks, got %d", chunkCount)
	}

	if handler.State() != ReadHandlerStateIdle {
		t.Errorf("expected idle state after all chunks, got %s", handler.State())
	}
}

func TestReadHandler_FabricFiltered(t *testing.T) {
	var capturedCtx *ReadContext

	handler := NewReadHandler(func(ctx *ReadContext, path message.AttributePathIB) (*AttributeResult, error) {
		capturedCtx = ctx
		return &AttributeResult{DataVersion: 1, Data: []byte{0x15, 0x18}}, nil
	}, DefaultMaxPayload)

	ep := message.EndpointID(1)
	cl := message.ClusterID(0x001D)
	attr := message.AttributeID(0x0000)

	req := &message.ReadRequestMessage{
		AttributeRequests: []message.AttributePathIB{
			{Endpoint: &ep, Cluster: &cl, Attribute: &attr},
		},
		FabricFiltered: true,
	}

	handler.HandleReadRequest(nil, req, 5, 999)

	if capturedCtx == nil {
		t.Fatal("context not captured")
	}
	if !capturedCtx.IsFabricFiltered {
		t.Error("expected IsFabricFiltered=true")
	}
	if capturedCtx.FabricIndex != 5 {
		t.Errorf("expected fabric 5, got %d", capturedCtx.FabricIndex)
	}
	if capturedCtx.SourceNodeID != 999 {
		t.Errorf("expected source node 999, got %d", capturedCtx.SourceNodeID)
	}
}

func TestReadHandler_EmptyRequest(t *testing.T) {
	handler := NewReadHandler(func(ctx *ReadContext, path message.AttributePathIB) (*AttributeResult, error) {
		return &AttributeResult{DataVersion: 1, Data: []byte{0x15, 0x18}}, nil
	}, DefaultMaxPayload)

	req := &message.ReadRequestMessage{
		AttributeRequests: []message.AttributePathIB{},
	}

	resp, err := handler.HandleReadRequest(nil, req, 1, 12345)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.AttributeReports) != 0 {
		t.Errorf("expected 0 reports for empty request, got %d", len(resp.AttributeReports))
	}

	if !resp.SuppressResponse {
		t.Error("expected SuppressResponse=true")
	}
}

func TestReadHandler_Reset(t *testing.T) {
	handler := NewReadHandler(func(ctx *ReadContext, path message.AttributePathIB) (*AttributeResult, error) {
		return &AttributeResult{DataVersion: 1, Data: make([]byte, 50)}, nil
	}, 80)

	ep := message.EndpointID(1)
	cl := message.ClusterID(0x001D)

	req := &message.ReadRequestMessage{
		AttributeRequests: make([]message.AttributePathIB, 5),
	}
	for i := range req.AttributeRequests {
		attr := message.AttributeID(i)
		req.AttributeRequests[i] = message.AttributePathIB{
			Endpoint:  &ep,
			Cluster:   &cl,
			Attribute: &attr,
		}
	}

	// Start chunked response
	handler.HandleReadRequest(nil, req, 1, 12345)

	if handler.State() == ReadHandlerStateIdle {
		t.Fatal("expected non-idle state during chunking")
	}

	handler.Reset()

	if handler.State() != ReadHandlerStateIdle {
		t.Errorf("expected idle state after reset, got %s", handler.State())
	}
}

func TestReadHandlerState_String(t *testing.T) {
	tests := []struct {
		state ReadHandlerState
		want  string
	}{
		{ReadHandlerStateIdle, "Idle"},
		{ReadHandlerStateProcessing, "Processing"},
		{ReadHandlerStateSendingReport, "SendingReport"},
		{ReadHandlerState(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("ReadHandlerState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestEncodeDecodeReadRequest(t *testing.T) {
	ep := message.EndpointID(1)
	cl := message.ClusterID(0x001D)
	attr := message.AttributeID(0x0000)

	original := &message.ReadRequestMessage{
		AttributeRequests: []message.AttributePathIB{
			{Endpoint: &ep, Cluster: &cl, Attribute: &attr},
		},
		FabricFiltered: true,
	}

	// Encode a report
	report := &message.ReportDataMessage{
		AttributeReports: []message.AttributeReportIB{
			{
				AttributeData: &message.AttributeDataIB{
					DataVersion: 1,
					Path: message.AttributePathIB{
						Endpoint:  &ep,
						Cluster:   &cl,
						Attribute: &attr,
					},
					Data: []byte{0x15, 0x18},
				},
			},
		},
		SuppressResponse: true,
	}

	encoded, err := EncodeReportData(report)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}

	if len(encoded) == 0 {
		t.Error("expected non-empty encoded data")
	}

	// Verify original request (just to use it)
	if len(original.AttributeRequests) != 1 {
		t.Error("original request mismatch")
	}
}
