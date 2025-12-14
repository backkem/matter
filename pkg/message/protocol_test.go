package message

import (
	"bytes"
	"testing"
)

func TestProtocolHeaderSize(t *testing.T) {
	tests := []struct {
		name     string
		header   ProtocolHeader
		wantSize int
	}{
		{
			name:     "Minimal header",
			header:   ProtocolHeader{},
			wantSize: 6, // ExchFlags(1) + Opcode(1) + ExchID(2) + ProtocolID(2)
		},
		{
			name: "With vendor ID",
			header: ProtocolHeader{
				VendorPresent: true,
			},
			wantSize: 8, // 6 + 2
		},
		{
			name: "With acknowledgement",
			header: ProtocolHeader{
				Acknowledgement: true,
			},
			wantSize: 10, // 6 + 4
		},
		{
			name: "With vendor ID and acknowledgement",
			header: ProtocolHeader{
				VendorPresent:   true,
				Acknowledgement: true,
			},
			wantSize: 12, // 6 + 2 + 4
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

func TestProtocolHeaderEncodeDecodeRoundtrip(t *testing.T) {
	tests := []struct {
		name   string
		header ProtocolHeader
	}{
		{
			name: "Minimal header",
			header: ProtocolHeader{
				ProtocolID:     ProtocolSecureChannel,
				ProtocolOpcode: 0x20,
				ExchangeID:     0x1234,
			},
		},
		{
			name: "Initiator with reliability",
			header: ProtocolHeader{
				ProtocolID:     ProtocolInteractionModel,
				ProtocolOpcode: 0x01,
				ExchangeID:     0xABCD,
				Initiator:      true,
				Reliability:    true,
			},
		},
		{
			name: "Responder with acknowledgement",
			header: ProtocolHeader{
				ProtocolID:          ProtocolSecureChannel,
				ProtocolOpcode:      0x40,
				ExchangeID:          0x5678,
				Acknowledgement:     true,
				AckedMessageCounter: 0x12345678,
			},
		},
		{
			name: "With custom vendor ID",
			header: ProtocolHeader{
				ProtocolID:       ProtocolForTesting,
				ProtocolOpcode:   0xFF,
				ExchangeID:       0x9999,
				VendorPresent:    true,
				ProtocolVendorID: 0xBEEF,
			},
		},
		{
			name: "All flags set",
			header: ProtocolHeader{
				ProtocolID:          ProtocolBDX,
				ProtocolOpcode:      0x10,
				ExchangeID:          0x0001,
				Initiator:           true,
				Acknowledgement:     true,
				Reliability:         true,
				VendorPresent:       true,
				ProtocolVendorID:    0x1234,
				AckedMessageCounter: 0xFFFFFFFF,
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
			var decoded ProtocolHeader
			n, err := decoded.Decode(encoded)
			if err != nil {
				t.Fatalf("Decode() error: %v", err)
			}

			if n != len(encoded) {
				t.Errorf("Decode() consumed %d bytes, want %d", n, len(encoded))
			}

			// Compare fields
			compareProtocolHeaders(t, &tc.header, &decoded)
		})
	}
}

func compareProtocolHeaders(t *testing.T, want, got *ProtocolHeader) {
	t.Helper()

	if got.ProtocolID != want.ProtocolID {
		t.Errorf("ProtocolID = %04x, want %04x", got.ProtocolID, want.ProtocolID)
	}
	if got.ProtocolOpcode != want.ProtocolOpcode {
		t.Errorf("ProtocolOpcode = %02x, want %02x", got.ProtocolOpcode, want.ProtocolOpcode)
	}
	if got.ExchangeID != want.ExchangeID {
		t.Errorf("ExchangeID = %04x, want %04x", got.ExchangeID, want.ExchangeID)
	}
	if got.Initiator != want.Initiator {
		t.Errorf("Initiator = %v, want %v", got.Initiator, want.Initiator)
	}
	if got.Acknowledgement != want.Acknowledgement {
		t.Errorf("Acknowledgement = %v, want %v", got.Acknowledgement, want.Acknowledgement)
	}
	if got.Reliability != want.Reliability {
		t.Errorf("Reliability = %v, want %v", got.Reliability, want.Reliability)
	}
	if got.VendorPresent != want.VendorPresent {
		t.Errorf("VendorPresent = %v, want %v", got.VendorPresent, want.VendorPresent)
	}
	if got.VendorPresent && got.ProtocolVendorID != want.ProtocolVendorID {
		t.Errorf("ProtocolVendorID = %04x, want %04x", got.ProtocolVendorID, want.ProtocolVendorID)
	}
	if got.Acknowledgement && got.AckedMessageCounter != want.AckedMessageCounter {
		t.Errorf("AckedMessageCounter = %08x, want %08x", got.AckedMessageCounter, want.AckedMessageCounter)
	}
}

func TestProtocolHeaderDecodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr error
	}{
		{
			name:    "Empty data",
			data:    []byte{},
			wantErr: ErrPayloadTooShort,
		},
		{
			name:    "Too short for minimal header",
			data:    []byte{0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: ErrPayloadTooShort,
		},
		{
			name: "Too short for vendor ID",
			data: []byte{
				0x10, // V flag set
				0x00, // Opcode
				0x00, 0x00, // Exchange ID
				0x00, 0x00, // Protocol ID (missing vendor)
			},
			wantErr: ErrPayloadTooShort,
		},
		{
			name: "Too short for acked counter",
			data: []byte{
				0x02, // A flag set
				0x00, // Opcode
				0x00, 0x00, // Exchange ID
				0x00, 0x00, // Protocol ID (missing acked counter)
			},
			wantErr: ErrPayloadTooShort,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var h ProtocolHeader
			_, err := h.Decode(tc.data)
			if err != tc.wantErr {
				t.Errorf("Decode() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestProtocolHeaderWireFormat(t *testing.T) {
	tests := []struct {
		name      string
		header    ProtocolHeader
		wantBytes []byte
	}{
		{
			name: "Secure Channel Status Report",
			header: ProtocolHeader{
				ProtocolID:     ProtocolSecureChannel,
				ProtocolOpcode: 0x40, // Status Report
				ExchangeID:     0x0001,
				Initiator:      false,
				Reliability:    true,
			},
			wantBytes: []byte{
				0x04,       // Exchange Flags: R=1
				0x40,       // Opcode
				0x01, 0x00, // Exchange ID (LE)
				0x00, 0x00, // Protocol ID = 0 (LE)
			},
		},
		{
			name: "IM Read Request initiator",
			header: ProtocolHeader{
				ProtocolID:     ProtocolInteractionModel,
				ProtocolOpcode: 0x02, // Read Request
				ExchangeID:     0x1234,
				Initiator:      true,
				Reliability:    true,
			},
			wantBytes: []byte{
				0x05,       // Exchange Flags: I=1, R=1
				0x02,       // Opcode
				0x34, 0x12, // Exchange ID (LE)
				0x01, 0x00, // Protocol ID = 1 (LE)
			},
		},
		{
			name: "Response with piggybacked ACK",
			header: ProtocolHeader{
				ProtocolID:          ProtocolInteractionModel,
				ProtocolOpcode:      0x05, // Report Data
				ExchangeID:          0x1234,
				Acknowledgement:     true,
				AckedMessageCounter: 0xAABBCCDD,
			},
			wantBytes: []byte{
				0x02,       // Exchange Flags: A=1
				0x05,       // Opcode
				0x34, 0x12, // Exchange ID (LE)
				0x01, 0x00, // Protocol ID (LE)
				0xDD, 0xCC, 0xBB, 0xAA, // Acked Counter (LE)
			},
		},
		{
			name: "With vendor ID",
			header: ProtocolHeader{
				ProtocolID:       ProtocolForTesting,
				ProtocolOpcode:   0x01,
				ExchangeID:       0x5678,
				VendorPresent:    true,
				ProtocolVendorID: 0x1234,
			},
			wantBytes: []byte{
				0x10,       // Exchange Flags: V=1
				0x01,       // Opcode
				0x78, 0x56, // Exchange ID (LE)
				0x34, 0x12, // Vendor ID (LE)
				0x04, 0x00, // Protocol ID (LE)
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

func TestProtocolHeaderHelpers(t *testing.T) {
	t.Run("IsSecureChannel", func(t *testing.T) {
		h := ProtocolHeader{ProtocolID: ProtocolSecureChannel}
		if !h.IsSecureChannel() {
			t.Error("IsSecureChannel() = false, want true")
		}

		h.ProtocolID = ProtocolInteractionModel
		if h.IsSecureChannel() {
			t.Error("IsSecureChannel() = true, want false")
		}
	})

	t.Run("IsInteractionModel", func(t *testing.T) {
		h := ProtocolHeader{ProtocolID: ProtocolInteractionModel}
		if !h.IsInteractionModel() {
			t.Error("IsInteractionModel() = false, want true")
		}

		h.ProtocolID = ProtocolSecureChannel
		if h.IsInteractionModel() {
			t.Error("IsInteractionModel() = true, want false")
		}
	})

	t.Run("NeedsAck", func(t *testing.T) {
		h := ProtocolHeader{Reliability: true}
		if !h.NeedsAck() {
			t.Error("NeedsAck() = false, want true")
		}

		h.Reliability = false
		if h.NeedsAck() {
			t.Error("NeedsAck() = true, want false")
		}
	})

	t.Run("IsAck", func(t *testing.T) {
		h := ProtocolHeader{Acknowledgement: true}
		if !h.IsAck() {
			t.Error("IsAck() = false, want true")
		}

		h.Acknowledgement = false
		if h.IsAck() {
			t.Error("IsAck() = true, want false")
		}
	})
}

func TestProtocolIDString(t *testing.T) {
	tests := []struct {
		id   ProtocolID
		want string
	}{
		{ProtocolSecureChannel, "SecureChannel"},
		{ProtocolInteractionModel, "InteractionModel"},
		{ProtocolBDX, "BDX"},
		{ProtocolUserDirectedCommissioning, "UDC"},
		{ProtocolForTesting, "Testing"},
		{0xFFFF, "Unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := tc.id.String()
			if got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}
