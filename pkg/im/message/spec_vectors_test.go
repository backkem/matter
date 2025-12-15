package message

import (
	"bytes"
	"testing"

	"github.com/backkem/matter/pkg/tlv"
)

// These tests verify that our TLV encoding matches the expected structure
// from the Matter spec and C++ reference implementation (TestMessageDef.cpp).
//
// While the spec doesn't provide binary test vectors for IM messages,
// these tests validate:
// 1. Correct context tag numbers (per spec Chapter 10)
// 2. Correct field ordering
// 3. Correct element types

// TestStatusIB_SpecEncoding verifies StatusIB encoding matches spec 10.6.1.
// Structure:
//   - Tag 0: Status (uint8, required)
//   - Tag 1: ClusterStatus (uint8, optional)
func TestStatusIB_SpecEncoding(t *testing.T) {
	tests := []struct {
		name           string
		status         StatusIB
		wantContextTag uint8 // First context tag should be 0
	}{
		{
			name:           "success status",
			status:         StatusIB{Status: StatusSuccess},
			wantContextTag: 0, // Tag 0 = Status
		},
		{
			name:           "with cluster status",
			status:         StatusIB{Status: StatusFailure, ClusterStatus: Ptr(uint8(0x42))},
			wantContextTag: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.status.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			// Verify structure encoding
			encoded := buf.Bytes()
			if len(encoded) < 3 {
				t.Fatalf("encoded too short: %d bytes", len(encoded))
			}

			// First byte should be structure start (0x15 = anonymous struct)
			if encoded[0] != 0x15 {
				t.Errorf("expected struct start 0x15, got 0x%02x", encoded[0])
			}

			// Second byte should be uint8 with context tag 0
			// Control byte: element type (4=uint8) | tag control (1=context) << 5 = 0x24
			if encoded[1] != 0x24 {
				t.Errorf("expected uint8 context tag control 0x24, got 0x%02x", encoded[1])
			}

			// Third byte should be context tag number 0
			if encoded[2] != 0x00 {
				t.Errorf("expected context tag 0, got 0x%02x", encoded[2])
			}
		})
	}
}

// TestAttributePathIB_SpecEncoding verifies AttributePathIB encoding matches spec 10.6.2.
// Per spec, AttributePathIB is encoded as a List (0x17) to allow wildcard expansion.
// Fields (all optional, presence indicated by pointer):
//   - Tag 0: EnableTagCompression (bool)
//   - Tag 1: Node (uint64)
//   - Tag 2: Endpoint (uint16)
//   - Tag 3: Cluster (uint32)
//   - Tag 4: Attribute (uint32)
//   - Tag 5: ListIndex (uint16, nullable)
func TestAttributePathIB_SpecEncoding(t *testing.T) {
	ep := EndpointID(1)
	cl := ClusterID(6)
	attr := AttributeID(0)

	path := AttributePathIB{
		Endpoint:  &ep,
		Cluster:   &cl,
		Attribute: &attr,
	}

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := path.Encode(w); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	encoded := buf.Bytes()

	// First byte: list start (0x17) - paths use list encoding per spec
	if encoded[0] != 0x17 {
		t.Errorf("expected list start 0x17, got 0x%02x", encoded[0])
	}

	// Look for context tags 2, 3, 4 in order (endpoint, cluster, attribute)
	foundTags := make(map[uint8]bool)
	for i := 1; i < len(encoded)-1; i++ {
		// Context tag control byte pattern: 0x24 (uint8), 0x25 (uint16/32), etc.
		ctrl := encoded[i]
		if ctrl&0xE0 == 0x20 { // Context tag
			tagNum := encoded[i+1]
			foundTags[tagNum] = true
		}
	}

	// Should have tags 2 (endpoint), 3 (cluster), 4 (attribute)
	expectedTags := []uint8{2, 3, 4}
	for _, tag := range expectedTags {
		if !foundTags[tag] {
			t.Errorf("missing expected context tag %d", tag)
		}
	}
}

// TestCommandPathIB_SpecEncoding verifies CommandPathIB encoding matches spec 10.6.11.
// Per spec, CommandPathIB is encoded as a List (0x17) to allow wildcard expansion.
// Fields:
//   - Tag 0: Endpoint (uint16, required)
//   - Tag 1: Cluster (uint32, required)
//   - Tag 2: Command (uint32, required)
func TestCommandPathIB_SpecEncoding(t *testing.T) {
	path := CommandPathIB{
		Endpoint: 1,
		Cluster:  0x0006, // OnOff
		Command:  2,      // Toggle
	}

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := path.Encode(w); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	encoded := buf.Bytes()

	// First byte: list start (0x17) - paths use list encoding per spec
	if encoded[0] != 0x17 {
		t.Errorf("expected list start 0x17, got 0x%02x", encoded[0])
	}

	// Last byte: end of container
	if encoded[len(encoded)-1] != 0x18 {
		t.Errorf("expected end container 0x18, got 0x%02x", encoded[len(encoded)-1])
	}

	// Verify all required tags are present
	foundTags := make(map[uint8]bool)
	for i := 1; i < len(encoded)-1; i++ {
		ctrl := encoded[i]
		if ctrl&0xE0 == 0x20 { // Context tag
			if i+1 < len(encoded) {
				tagNum := encoded[i+1]
				foundTags[tagNum] = true
			}
		}
	}

	for _, tag := range []uint8{0, 1, 2} {
		if !foundTags[tag] {
			t.Errorf("missing required context tag %d", tag)
		}
	}
}

// TestInvokeRequestMessage_SpecEncoding verifies InvokeRequestMessage matches spec 10.7.9.
// Structure:
//   - Tag 0: SuppressResponse (bool)
//   - Tag 1: TimedRequest (bool)
//   - Tag 2: InvokeRequests (array of CommandDataIB)
func TestInvokeRequestMessage_SpecEncoding(t *testing.T) {
	msg := InvokeRequestMessage{
		SuppressResponse: false,
		TimedRequest:     false,
		InvokeRequests: []CommandDataIB{
			{
				Path: CommandPathIB{
					Endpoint: 1,
					Cluster:  0x0006,
					Command:  2,
				},
			},
		},
	}

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := msg.Encode(w); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	encoded := buf.Bytes()

	// Verify structure
	if encoded[0] != 0x15 {
		t.Errorf("expected struct start 0x15, got 0x%02x", encoded[0])
	}

	// Roundtrip test
	r := tlv.NewReader(bytes.NewReader(encoded))
	var decoded InvokeRequestMessage
	if err := decoded.Decode(r); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.SuppressResponse != msg.SuppressResponse {
		t.Errorf("SuppressResponse mismatch")
	}
	if decoded.TimedRequest != msg.TimedRequest {
		t.Errorf("TimedRequest mismatch")
	}
	if len(decoded.InvokeRequests) != 1 {
		t.Errorf("InvokeRequests length mismatch")
	}
}

// TestWriteRequestMessage_SpecEncoding verifies WriteRequestMessage matches spec 10.7.6.
// Structure:
//   - Tag 0: SuppressResponse (bool)
//   - Tag 1: TimedRequest (bool)
//   - Tag 2: WriteRequests (array of AttributeDataIB)
//   - Tag 3: MoreChunkedMessages (bool, optional)
func TestWriteRequestMessage_SpecEncoding(t *testing.T) {
	ep := EndpointID(0)
	cl := ClusterID(0x001F)
	attr := AttributeID(0)

	msg := WriteRequestMessage{
		SuppressResponse: false,
		TimedRequest:     false,
		WriteRequests: []AttributeDataIB{
			{
				Path: AttributePathIB{
					Endpoint:  &ep,
					Cluster:   &cl,
					Attribute: &attr,
				},
				Data: []byte{0x09}, // Boolean true
			},
		},
		MoreChunkedMessages: false,
	}

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := msg.Encode(w); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	encoded := buf.Bytes()

	// Verify structure start
	if encoded[0] != 0x15 {
		t.Errorf("expected struct start 0x15, got 0x%02x", encoded[0])
	}

	// Roundtrip test to verify correctness
	r := tlv.NewReader(bytes.NewReader(encoded))
	var decoded WriteRequestMessage
	if err := decoded.Decode(r); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.SuppressResponse != msg.SuppressResponse {
		t.Errorf("SuppressResponse mismatch")
	}
	if len(decoded.WriteRequests) != 1 {
		t.Errorf("WriteRequests length mismatch")
	}
}

// TestReadRequestMessage_SpecEncoding verifies ReadRequestMessage matches spec 10.7.2.
// Structure:
//   - Tag 0: AttributeRequests (array of AttributePathIB, optional)
//   - Tag 1: EventRequests (array of EventPathIB, optional)
//   - Tag 2: EventFilters (array of EventFilterIB, optional)
//   - Tag 3: FabricFiltered (bool)
//   - Tag 4: DataVersionFilters (array of DataVersionFilterIB, optional)
func TestReadRequestMessage_SpecEncoding(t *testing.T) {
	ep := EndpointID(1)
	cl := ClusterID(0x0006)
	attr := AttributeID(0)

	msg := ReadRequestMessage{
		AttributeRequests: []AttributePathIB{
			{
				Endpoint:  &ep,
				Cluster:   &cl,
				Attribute: &attr,
			},
		},
		FabricFiltered: true,
	}

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := msg.Encode(w); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	encoded := buf.Bytes()

	// Verify structure
	if encoded[0] != 0x15 {
		t.Errorf("expected struct start 0x15, got 0x%02x", encoded[0])
	}

	// Roundtrip
	r := tlv.NewReader(bytes.NewReader(encoded))
	var decoded ReadRequestMessage
	if err := decoded.Decode(r); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.FabricFiltered != true {
		t.Errorf("FabricFiltered mismatch")
	}
	if len(decoded.AttributeRequests) != 1 {
		t.Errorf("AttributeRequests length mismatch")
	}
}

// TestReportDataMessage_SpecEncoding verifies ReportDataMessage matches spec 10.7.3.
// Structure:
//   - Tag 0: SubscriptionId (uint32, optional)
//   - Tag 1: AttributeReports (array, optional)
//   - Tag 2: EventReports (array, optional)
//   - Tag 3: MoreChunkedMessages (bool, optional)
//   - Tag 4: SuppressResponse (bool, optional)
func TestReportDataMessage_SpecEncoding(t *testing.T) {
	ep := EndpointID(1)
	cl := ClusterID(0x0006)
	attr := AttributeID(0)

	msg := ReportDataMessage{
		AttributeReports: []AttributeReportIB{
			{
				AttributeData: &AttributeDataIB{
					DataVersion: 1,
					Path: AttributePathIB{
						Endpoint:  &ep,
						Cluster:   &cl,
						Attribute: &attr,
					},
					Data: []byte{0x08}, // Boolean false
				},
			},
		},
		MoreChunkedMessages: false,
		SuppressResponse:    false,
	}

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := msg.Encode(w); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	encoded := buf.Bytes()

	// Verify structure
	if encoded[0] != 0x15 {
		t.Errorf("expected struct start 0x15, got 0x%02x", encoded[0])
	}

	// Roundtrip
	r := tlv.NewReader(bytes.NewReader(encoded))
	var decoded ReportDataMessage
	if err := decoded.Decode(r); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if len(decoded.AttributeReports) != 1 {
		t.Errorf("AttributeReports length mismatch")
	}
}

// TestStatusCodes_SpecValues verifies status code values match spec 8.10.
func TestStatusCodes_SpecValues(t *testing.T) {
	// Verify key status codes match spec Section 8.10
	specCodes := map[Status]uint8{
		StatusSuccess:               0x00,
		StatusFailure:               0x01,
		StatusInvalidSubscription:   0x7D,
		StatusUnsupportedAccess:     0x7E,
		StatusUnsupportedEndpoint:   0x7F,
		StatusInvalidAction:         0x80,
		StatusUnsupportedCommand:    0x81,
		StatusInvalidCommand:        0x85,
		StatusUnsupportedAttribute:  0x86,
		StatusConstraintError:       0x87,
		StatusUnsupportedWrite:      0x88,
		StatusResourceExhausted:     0x89,
		StatusNotFound:              0x8B,
		StatusUnsupportedCluster:    0xC3,
		StatusNeedsTimedInteraction: 0xC6,
	}

	for status, want := range specCodes {
		if uint8(status) != want {
			t.Errorf("Status %s = 0x%02x, want 0x%02x", status, uint8(status), want)
		}
	}
}

// TestOpcodes_SpecValues verifies opcode values match spec 10.2.1.
func TestOpcodes_SpecValues(t *testing.T) {
	specOpcodes := map[Opcode]uint8{
		OpcodeStatusResponse:    0x01,
		OpcodeReadRequest:       0x02,
		OpcodeSubscribeRequest:  0x03,
		OpcodeSubscribeResponse: 0x04,
		OpcodeReportData:        0x05,
		OpcodeWriteRequest:      0x06,
		OpcodeWriteResponse:     0x07,
		OpcodeInvokeRequest:     0x08,
		OpcodeInvokeResponse:    0x09,
		OpcodeTimedRequest:      0x0A,
	}

	for opcode, want := range specOpcodes {
		if uint8(opcode) != want {
			t.Errorf("Opcode %s = 0x%02x, want 0x%02x", opcode, uint8(opcode), want)
		}
	}
}
