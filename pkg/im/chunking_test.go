package im

import (
	"testing"

	"github.com/backkem/matter/pkg/im/message"
)

func TestAssembler_WriteRequest_SingleChunk(t *testing.T) {
	a := NewAssembler()

	msg := &message.WriteRequestMessage{
		SuppressResponse:    true,
		TimedRequest:        false,
		WriteRequests:       makeWriteRequests(3),
		MoreChunkedMessages: false,
	}

	result, complete, err := a.AddWriteRequest(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !complete {
		t.Fatal("expected complete")
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if len(result.WriteRequests) != 3 {
		t.Errorf("expected 3 write requests, got %d", len(result.WriteRequests))
	}
	if result.SuppressResponse != true {
		t.Error("expected SuppressResponse=true")
	}
}

func TestAssembler_WriteRequest_MultipleChunks(t *testing.T) {
	a := NewAssembler()

	// First chunk
	msg1 := &message.WriteRequestMessage{
		SuppressResponse:    true,
		TimedRequest:        true,
		WriteRequests:       makeWriteRequests(2),
		MoreChunkedMessages: true,
	}

	result, complete, err := a.AddWriteRequest(msg1)
	if err != nil {
		t.Fatalf("chunk 1: unexpected error: %v", err)
	}
	if complete {
		t.Fatal("chunk 1: should not be complete")
	}
	if result != nil {
		t.Fatal("chunk 1: should not have result")
	}
	if !a.IsAssembling() {
		t.Fatal("should be assembling")
	}

	// Second chunk
	msg2 := &message.WriteRequestMessage{
		SuppressResponse:    false, // Should be ignored
		TimedRequest:        false, // Should be ignored
		WriteRequests:       makeWriteRequests(3),
		MoreChunkedMessages: true,
	}

	result, complete, err = a.AddWriteRequest(msg2)
	if err != nil {
		t.Fatalf("chunk 2: unexpected error: %v", err)
	}
	if complete {
		t.Fatal("chunk 2: should not be complete")
	}

	// Third chunk (final)
	msg3 := &message.WriteRequestMessage{
		SuppressResponse:    false,
		TimedRequest:        false,
		WriteRequests:       makeWriteRequests(1),
		MoreChunkedMessages: false,
	}

	result, complete, err = a.AddWriteRequest(msg3)
	if err != nil {
		t.Fatalf("chunk 3: unexpected error: %v", err)
	}
	if !complete {
		t.Fatal("chunk 3: should be complete")
	}
	if result == nil {
		t.Fatal("chunk 3: expected result")
	}

	// Verify accumulated result
	if len(result.WriteRequests) != 6 { // 2 + 3 + 1
		t.Errorf("expected 6 write requests, got %d", len(result.WriteRequests))
	}
	if result.SuppressResponse != true {
		t.Error("should preserve SuppressResponse from first chunk")
	}
	if result.TimedRequest != true {
		t.Error("should preserve TimedRequest from first chunk")
	}
	if a.IsAssembling() {
		t.Error("should not be assembling after complete")
	}
}

func TestAssembler_ReportData_MultipleChunks(t *testing.T) {
	a := NewAssembler()

	subID := message.SubscriptionID(12345)

	// First chunk with attributes
	msg1 := &message.ReportDataMessage{
		SubscriptionID:      &subID,
		AttributeReports:    makeAttributeReports(2),
		EventReports:        nil,
		MoreChunkedMessages: true,
		SuppressResponse:    false,
	}

	result, complete, err := a.AddReportData(msg1)
	if err != nil {
		t.Fatalf("chunk 1: unexpected error: %v", err)
	}
	if complete || result != nil {
		t.Fatal("chunk 1: should not be complete")
	}

	// Second chunk with events
	msg2 := &message.ReportDataMessage{
		SubscriptionID:      nil, // Should be ignored
		AttributeReports:    makeAttributeReports(1),
		EventReports:        makeEventReports(2),
		MoreChunkedMessages: true,
		SuppressResponse:    true,
	}

	result, complete, err = a.AddReportData(msg2)
	if err != nil {
		t.Fatalf("chunk 2: unexpected error: %v", err)
	}
	if complete {
		t.Fatal("chunk 2: should not be complete")
	}

	// Final chunk
	msg3 := &message.ReportDataMessage{
		SubscriptionID:      nil,
		AttributeReports:    nil,
		EventReports:        makeEventReports(1),
		MoreChunkedMessages: false,
		SuppressResponse:    true,
	}

	result, complete, err = a.AddReportData(msg3)
	if err != nil {
		t.Fatalf("chunk 3: unexpected error: %v", err)
	}
	if !complete {
		t.Fatal("chunk 3: should be complete")
	}

	// Verify
	if result.SubscriptionID == nil || *result.SubscriptionID != subID {
		t.Error("should preserve SubscriptionID from first chunk")
	}
	if len(result.AttributeReports) != 3 { // 2 + 1 + 0
		t.Errorf("expected 3 attribute reports, got %d", len(result.AttributeReports))
	}
	if len(result.EventReports) != 3 { // 0 + 2 + 1
		t.Errorf("expected 3 event reports, got %d", len(result.EventReports))
	}
}

func TestAssembler_InvokeResponse_MultipleChunks(t *testing.T) {
	a := NewAssembler()

	// First chunk
	msg1 := &message.InvokeResponseMessage{
		SuppressResponse:    true,
		InvokeResponses:     makeInvokeResponses(2),
		MoreChunkedMessages: true,
	}

	result, complete, err := a.AddInvokeResponse(msg1)
	if err != nil {
		t.Fatalf("chunk 1: unexpected error: %v", err)
	}
	if complete || result != nil {
		t.Fatal("chunk 1: should not be complete")
	}

	// Final chunk
	msg2 := &message.InvokeResponseMessage{
		SuppressResponse:    false,
		InvokeResponses:     makeInvokeResponses(1),
		MoreChunkedMessages: false,
	}

	result, complete, err = a.AddInvokeResponse(msg2)
	if err != nil {
		t.Fatalf("chunk 2: unexpected error: %v", err)
	}
	if !complete {
		t.Fatal("chunk 2: should be complete")
	}

	if len(result.InvokeResponses) != 3 {
		t.Errorf("expected 3 invoke responses, got %d", len(result.InvokeResponses))
	}
	if result.SuppressResponse != true {
		t.Error("should preserve SuppressResponse from first chunk")
	}
}

func TestAssembler_TypeMismatch(t *testing.T) {
	a := NewAssembler()

	// Start with WriteRequest
	msg1 := &message.WriteRequestMessage{
		WriteRequests:       makeWriteRequests(1),
		MoreChunkedMessages: true,
	}
	_, _, err := a.AddWriteRequest(msg1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Try to add InvokeResponse - should error
	msg2 := &message.InvokeResponseMessage{
		InvokeResponses:     makeInvokeResponses(1),
		MoreChunkedMessages: false,
	}
	_, _, err = a.AddInvokeResponse(msg2)
	if err != ErrChunkingInProgress {
		t.Errorf("expected ErrChunkingInProgress, got %v", err)
	}
}

func TestAssembler_Reset(t *testing.T) {
	a := NewAssembler()

	// Start assembly
	msg := &message.WriteRequestMessage{
		WriteRequests:       makeWriteRequests(2),
		MoreChunkedMessages: true,
	}
	a.AddWriteRequest(msg)

	if !a.IsAssembling() {
		t.Fatal("should be assembling")
	}

	// Reset
	a.Reset()

	if a.IsAssembling() {
		t.Fatal("should not be assembling after reset")
	}
	if a.ChunkType() != ChunkTypeNone {
		t.Error("chunk type should be None after reset")
	}
}

func TestFragmenter_InvokeResponse_NoChunking(t *testing.T) {
	f := NewFragmenter(1000)

	msg := &message.InvokeResponseMessage{
		SuppressResponse: true,
		InvokeResponses:  makeInvokeResponses(2),
	}

	chunks, err := f.FragmentInvokeResponse(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chunks) != 1 {
		t.Errorf("expected 1 chunk, got %d", len(chunks))
	}
	if chunks[0].MoreChunkedMessages {
		t.Error("single chunk should have MoreChunkedMessages=false")
	}
}

func TestFragmenter_InvokeResponse_Chunking(t *testing.T) {
	// Use small max payload to force chunking
	f := NewFragmenter(50)

	// Create responses with enough data to require chunking
	responses := make([]message.InvokeResponseIB, 5)
	for i := range responses {
		responses[i] = message.InvokeResponseIB{
			Command: &message.CommandDataIB{
				Path: message.CommandPathIB{
					Endpoint: 1,
					Cluster:  0x0006,
					Command:  0x00,
				},
				Fields: make([]byte, 30), // Force chunking
			},
		}
	}

	msg := &message.InvokeResponseMessage{
		SuppressResponse: false,
		InvokeResponses:  responses,
	}

	chunks, err := f.FragmentInvokeResponse(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chunks) < 2 {
		t.Errorf("expected multiple chunks, got %d", len(chunks))
	}

	// All but last should have MoreChunkedMessages=true
	for i, chunk := range chunks {
		if i < len(chunks)-1 {
			if !chunk.MoreChunkedMessages {
				t.Errorf("chunk %d: expected MoreChunkedMessages=true", i)
			}
		} else {
			if chunk.MoreChunkedMessages {
				t.Error("last chunk should have MoreChunkedMessages=false")
			}
		}
	}

	// Verify all responses are present
	total := 0
	for _, chunk := range chunks {
		total += len(chunk.InvokeResponses)
	}
	if total != 5 {
		t.Errorf("expected 5 total responses, got %d", total)
	}
}

func TestFragmenter_WriteRequest_Chunking(t *testing.T) {
	f := NewFragmenter(100)

	// Create write requests with data
	requests := make([]message.AttributeDataIB, 4)
	for i := range requests {
		requests[i] = message.AttributeDataIB{
			DataVersion: message.DataVersion(i),
			Path: message.AttributePathIB{
				Endpoint:  endpointIDPtr(1),
				Cluster:   clusterIDPtr(0x0006),
				Attribute: attributeIDPtr(0x0000),
			},
			Data: make([]byte, 50),
		}
	}

	msg := &message.WriteRequestMessage{
		SuppressResponse: true,
		TimedRequest:     true,
		WriteRequests:    requests,
	}

	chunks, err := f.FragmentWriteRequest(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chunks) < 2 {
		t.Errorf("expected multiple chunks, got %d", len(chunks))
	}

	// All chunks should preserve header fields
	for i, chunk := range chunks {
		if chunk.SuppressResponse != true {
			t.Errorf("chunk %d: SuppressResponse not preserved", i)
		}
		if chunk.TimedRequest != true {
			t.Errorf("chunk %d: TimedRequest not preserved", i)
		}
	}
}

func TestFragmenter_ReportData_Chunking(t *testing.T) {
	f := NewFragmenter(100)

	subID := message.SubscriptionID(999)

	msg := &message.ReportDataMessage{
		SubscriptionID:   &subID,
		AttributeReports: makeAttributeReports(3),
		EventReports:     makeEventReports(2),
		SuppressResponse: true,
	}

	chunks, err := f.FragmentReportData(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All but last chunk should have SuppressResponse=false (need flow control)
	for i, chunk := range chunks {
		if i < len(chunks)-1 {
			if chunk.SuppressResponse {
				t.Errorf("chunk %d: intermediate chunk should have SuppressResponse=false", i)
			}
		}
	}

	// Last chunk should have original SuppressResponse
	if !chunks[len(chunks)-1].SuppressResponse {
		t.Error("last chunk should preserve original SuppressResponse")
	}
}

func TestFragmenter_RoundTrip(t *testing.T) {
	// Fragment then reassemble
	f := NewFragmenter(80)
	a := NewAssembler()

	original := &message.InvokeResponseMessage{
		SuppressResponse: true,
		InvokeResponses:  makeInvokeResponses(5),
	}

	// Fragment
	chunks, err := f.FragmentInvokeResponse(original)
	if err != nil {
		t.Fatalf("fragment error: %v", err)
	}

	// Reassemble
	var result *message.InvokeResponseMessage
	var complete bool
	for _, chunk := range chunks {
		result, complete, err = a.AddInvokeResponse(chunk)
		if err != nil {
			t.Fatalf("assemble error: %v", err)
		}
	}

	if !complete {
		t.Fatal("should be complete after all chunks")
	}
	if len(result.InvokeResponses) != 5 {
		t.Errorf("expected 5 responses, got %d", len(result.InvokeResponses))
	}
	if result.SuppressResponse != original.SuppressResponse {
		t.Error("SuppressResponse mismatch")
	}
}

func TestChunkType_String(t *testing.T) {
	tests := []struct {
		ct   ChunkType
		want string
	}{
		{ChunkTypeNone, "None"},
		{ChunkTypeWriteRequest, "WriteRequest"},
		{ChunkTypeReportData, "ReportData"},
		{ChunkTypeInvokeResponse, "InvokeResponse"},
		{ChunkType(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.ct.String(); got != tt.want {
			t.Errorf("ChunkType(%d).String() = %q, want %q", tt.ct, got, tt.want)
		}
	}
}

// Helper functions

func makeWriteRequests(n int) []message.AttributeDataIB {
	result := make([]message.AttributeDataIB, n)
	for i := range result {
		result[i] = message.AttributeDataIB{
			DataVersion: message.DataVersion(i),
			Path: message.AttributePathIB{
				Endpoint:  endpointIDPtr(1),
				Cluster:   clusterIDPtr(0x0006),
				Attribute: attributeIDPtr(uint32(i)),
			},
			Data: []byte{0x00},
		}
	}
	return result
}

func makeAttributeReports(n int) []message.AttributeReportIB {
	result := make([]message.AttributeReportIB, n)
	for i := range result {
		result[i] = message.AttributeReportIB{
			AttributeData: &message.AttributeDataIB{
				DataVersion: message.DataVersion(i),
				Path: message.AttributePathIB{
					Endpoint:  endpointIDPtr(1),
					Cluster:   clusterIDPtr(0x0006),
					Attribute: attributeIDPtr(uint32(i)),
				},
				Data: []byte{0x00},
			},
		}
	}
	return result
}

func makeEventReports(n int) []message.EventReportIB {
	result := make([]message.EventReportIB, n)
	for i := range result {
		result[i] = message.EventReportIB{
			EventData: &message.EventDataIB{
				Path: message.EventPathIB{
					Endpoint: endpointIDPtr(1),
					Cluster:  clusterIDPtr(0x0006),
					Event:    eventIDPtr(uint32(i)),
				},
				EventNumber: message.EventNumber(i),
				Priority:    message.EventPriorityInfo,
			},
		}
	}
	return result
}

func makeInvokeResponses(n int) []message.InvokeResponseIB {
	result := make([]message.InvokeResponseIB, n)
	for i := range result {
		result[i] = message.InvokeResponseIB{
			Command: &message.CommandDataIB{
				Path: message.CommandPathIB{
					Endpoint: 1,
					Cluster:  0x0006,
					Command:  message.CommandID(i),
				},
				Fields: []byte{0x00},
			},
		}
	}
	return result
}

func endpointIDPtr(v uint16) *message.EndpointID {
	id := message.EndpointID(v)
	return &id
}

func clusterIDPtr(v uint32) *message.ClusterID {
	id := message.ClusterID(v)
	return &id
}

func attributeIDPtr(v uint32) *message.AttributeID {
	id := message.AttributeID(v)
	return &id
}

func eventIDPtr(v uint32) *message.EventID {
	id := message.EventID(v)
	return &id
}

func dataVersionPtr(v uint32) *message.DataVersion {
	dv := message.DataVersion(v)
	return &dv
}
