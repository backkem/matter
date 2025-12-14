package message

import (
	"bytes"
	"testing"
)

func TestMessageHeaderSize(t *testing.T) {
	tests := []struct {
		name     string
		header   MessageHeader
		wantSize int
	}{
		{
			name:     "Minimal header (no optional fields)",
			header:   MessageHeader{},
			wantSize: 8, // Flags(1) + SessionID(2) + SecFlags(1) + Counter(4)
		},
		{
			name: "With source node ID",
			header: MessageHeader{
				SourcePresent: true,
			},
			wantSize: 16, // 8 + 8 (NodeID)
		},
		{
			name: "With destination node ID",
			header: MessageHeader{
				DestinationType: DestinationNodeID,
			},
			wantSize: 16, // 8 + 8 (NodeID)
		},
		{
			name: "With destination group ID",
			header: MessageHeader{
				DestinationType: DestinationGroupID,
			},
			wantSize: 10, // 8 + 2 (GroupID)
		},
		{
			name: "Full header (source + dest node)",
			header: MessageHeader{
				SourcePresent:   true,
				DestinationType: DestinationNodeID,
			},
			wantSize: 24, // 8 + 8 + 8
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.header.Size()
			if got != tc.wantSize {
				t.Errorf("Size() = %d, want %d", got, tc.wantSize)
			}
		})
	}
}

func TestMessageHeaderEncodeDecodeRoundtrip(t *testing.T) {
	tests := []struct {
		name   string
		header MessageHeader
	}{
		{
			name: "Minimal unicast header",
			header: MessageHeader{
				SessionID:      0x1234,
				MessageCounter: 0x56789ABC,
				SessionType:    SessionTypeUnicast,
			},
		},
		{
			name: "Unicast with source",
			header: MessageHeader{
				SessionID:      0xFFFF,
				MessageCounter: 0x00000001,
				SessionType:    SessionTypeUnicast,
				SourcePresent:  true,
				SourceNodeID:   0x0102030405060708,
			},
		},
		{
			name: "Group session",
			header: MessageHeader{
				SessionID:          0x1000,
				MessageCounter:     0x12345678,
				SessionType:        SessionTypeGroup,
				SourcePresent:      true,
				SourceNodeID:       0xAAAABBBBCCCCDDDD,
				DestinationType:    DestinationGroupID,
				DestinationGroupID: 0x1234,
			},
		},
		{
			name: "With privacy and control flags",
			header: MessageHeader{
				SessionID:      0x0001,
				MessageCounter: 0xFFFFFFFF,
				SessionType:    SessionTypeUnicast,
				Privacy:        true,
				Control:        true,
			},
		},
		{
			name: "Unicast to specific node",
			header: MessageHeader{
				SessionID:         0x5678,
				MessageCounter:    0x00001000,
				SessionType:       SessionTypeUnicast,
				DestinationType:   DestinationNodeID,
				DestinationNodeID: 0x1122334455667788,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Encode
			encoded := tc.header.Encode()

			// Verify size
			if len(encoded) != tc.header.Size() {
				t.Errorf("Encode() length = %d, want %d", len(encoded), tc.header.Size())
			}

			// Decode
			var decoded MessageHeader
			n, err := decoded.Decode(encoded)
			if err != nil {
				t.Fatalf("Decode() error: %v", err)
			}

			if n != len(encoded) {
				t.Errorf("Decode() consumed %d bytes, want %d", n, len(encoded))
			}

			// Compare fields
			compareHeaders(t, &tc.header, &decoded)
		})
	}
}

func compareHeaders(t *testing.T, want, got *MessageHeader) {
	t.Helper()

	if got.SessionID != want.SessionID {
		t.Errorf("SessionID = %04x, want %04x", got.SessionID, want.SessionID)
	}
	if got.MessageCounter != want.MessageCounter {
		t.Errorf("MessageCounter = %08x, want %08x", got.MessageCounter, want.MessageCounter)
	}
	if got.SessionType != want.SessionType {
		t.Errorf("SessionType = %v, want %v", got.SessionType, want.SessionType)
	}
	if got.SourcePresent != want.SourcePresent {
		t.Errorf("SourcePresent = %v, want %v", got.SourcePresent, want.SourcePresent)
	}
	if got.SourcePresent && got.SourceNodeID != want.SourceNodeID {
		t.Errorf("SourceNodeID = %016x, want %016x", got.SourceNodeID, want.SourceNodeID)
	}
	if got.DestinationType != want.DestinationType {
		t.Errorf("DestinationType = %v, want %v", got.DestinationType, want.DestinationType)
	}
	if got.DestinationType == DestinationNodeID && got.DestinationNodeID != want.DestinationNodeID {
		t.Errorf("DestinationNodeID = %016x, want %016x", got.DestinationNodeID, want.DestinationNodeID)
	}
	if got.DestinationType == DestinationGroupID && got.DestinationGroupID != want.DestinationGroupID {
		t.Errorf("DestinationGroupID = %04x, want %04x", got.DestinationGroupID, want.DestinationGroupID)
	}
	if got.Privacy != want.Privacy {
		t.Errorf("Privacy = %v, want %v", got.Privacy, want.Privacy)
	}
	if got.Control != want.Control {
		t.Errorf("Control = %v, want %v", got.Control, want.Control)
	}
}

func TestMessageHeaderDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr error
	}{
		{
			name:    "Empty data",
			data:    []byte{},
			wantErr: ErrMessageTooShort,
		},
		{
			name:    "Too short for header",
			data:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: ErrMessageTooShort,
		},
		{
			name: "Invalid version",
			data: []byte{
				0x10,       // Version = 1 (invalid)
				0x00, 0x00, // Session ID
				0x00,                   // Security Flags
				0x00, 0x00, 0x00, 0x00, // Counter
			},
			wantErr: ErrInvalidVersion,
		},
		{
			name: "Reserved DSIZ value",
			data: []byte{
				0x03,       // DSIZ = 3 (reserved)
				0x00, 0x00, // Session ID
				0x00,                   // Security Flags
				0x00, 0x00, 0x00, 0x00, // Counter
			},
			wantErr: ErrInvalidDSIZ,
		},
		{
			name: "Reserved session type",
			data: []byte{
				0x00,       // Message Flags
				0x00, 0x00, // Session ID
				0x03,                   // Session Type = 3 (reserved)
				0x00, 0x00, 0x00, 0x00, // Counter
			},
			wantErr: ErrInvalidSessionType,
		},
		{
			name: "Too short for source node ID",
			data: []byte{
				0x04,       // S Flag set
				0x00, 0x00, // Session ID
				0x00,                   // Security Flags
				0x00, 0x00, 0x00, 0x00, // Counter
				// Missing 8-byte source node ID
			},
			wantErr: ErrMessageTooShort,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var h MessageHeader
			_, err := h.Decode(tc.data)
			if err != tc.wantErr {
				t.Errorf("Decode() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestMessageHeaderIsSecure(t *testing.T) {
	tests := []struct {
		name       string
		header     MessageHeader
		wantSecure bool
	}{
		{
			name: "Unsecured session (unicast, ID=0)",
			header: MessageHeader{
				SessionType: SessionTypeUnicast,
				SessionID:   0,
			},
			wantSecure: false,
		},
		{
			name: "Secure unicast session",
			header: MessageHeader{
				SessionType: SessionTypeUnicast,
				SessionID:   1,
			},
			wantSecure: true,
		},
		{
			name: "Group session (always secure)",
			header: MessageHeader{
				SessionType: SessionTypeGroup,
				SessionID:   0,
			},
			wantSecure: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.header.IsSecure()
			if got != tc.wantSecure {
				t.Errorf("IsSecure() = %v, want %v", got, tc.wantSecure)
			}
		})
	}
}

func TestMessageHeaderValidate(t *testing.T) {
	tests := []struct {
		name    string
		header  MessageHeader
		wantErr error
	}{
		{
			name: "Valid unicast header",
			header: MessageHeader{
				SessionType: SessionTypeUnicast,
				SessionID:   1,
			},
			wantErr: nil,
		},
		{
			name: "Valid group header",
			header: MessageHeader{
				SessionType:        SessionTypeGroup,
				SourcePresent:      true,
				SourceNodeID:       0x1234,
				DestinationType:    DestinationGroupID,
				DestinationGroupID: 0x5678,
			},
			wantErr: nil,
		},
		{
			name: "Group without source node ID",
			header: MessageHeader{
				SessionType:        SessionTypeGroup,
				SourcePresent:      false,
				DestinationType:    DestinationGroupID,
				DestinationGroupID: 0x5678,
			},
			wantErr: ErrMissingSourceNodeID,
		},
		{
			name: "Group without destination",
			header: MessageHeader{
				SessionType:     SessionTypeGroup,
				SourcePresent:   true,
				SourceNodeID:    0x1234,
				DestinationType: DestinationNone,
			},
			wantErr: ErrInvalidDSIZ,
		},
		{
			name: "Unicast with group destination",
			header: MessageHeader{
				SessionType:        SessionTypeUnicast,
				DestinationType:    DestinationGroupID,
				DestinationGroupID: 0x1234,
			},
			wantErr: ErrInvalidDSIZ,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.header.Validate()
			if err != tc.wantErr {
				t.Errorf("Validate() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestMessageHeaderWireFormat tests specific byte-level encoding.
func TestMessageHeaderWireFormat(t *testing.T) {
	tests := []struct {
		name      string
		header    MessageHeader
		wantBytes []byte
	}{
		{
			name: "Basic unsecured unicast",
			header: MessageHeader{
				SessionID:       0,
				SessionType:     SessionTypeUnicast,
				MessageCounter:  1,
				DestinationType: DestinationNone,
			},
			wantBytes: []byte{
				0x00,       // Message Flags: Version=0, S=0, DSIZ=0
				0x00, 0x00, // Session ID = 0 (LE)
				0x00,                   // Security Flags: P=0, C=0, MX=0, SessionType=0
				0x01, 0x00, 0x00, 0x00, // Counter = 1 (LE)
			},
		},
		{
			name: "Secure unicast with counter",
			header: MessageHeader{
				SessionID:       0x1234,
				SessionType:     SessionTypeUnicast,
				MessageCounter:  0xAABBCCDD,
				DestinationType: DestinationNone,
			},
			wantBytes: []byte{
				0x00,       // Message Flags
				0x34, 0x12, // Session ID = 0x1234 (LE)
				0x00,                   // Security Flags
				0xDD, 0xCC, 0xBB, 0xAA, // Counter (LE)
			},
		},
		{
			name: "Group session with source and dest",
			header: MessageHeader{
				SessionID:          0x0100,
				SessionType:        SessionTypeGroup,
				MessageCounter:     0x00000001,
				SourcePresent:      true,
				SourceNodeID:       0x0102030405060708,
				DestinationType:    DestinationGroupID,
				DestinationGroupID: 0xABCD,
			},
			wantBytes: []byte{
				0x06,       // Message Flags: DSIZ=2, S=1
				0x00, 0x01, // Session ID (LE)
				0x01,                   // Security Flags: SessionType=1 (group)
				0x01, 0x00, 0x00, 0x00, // Counter (LE)
				0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // Source Node ID (LE)
				0xCD, 0xAB, // Destination Group ID (LE)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.header.Encode()
			if !bytes.Equal(got, tc.wantBytes) {
				t.Errorf("Encode() = %x, want %x", got, tc.wantBytes)
			}
		})
	}
}
