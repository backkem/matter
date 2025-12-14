package message

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestFrameUnsecuredRoundtrip(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
	}{
		{
			name: "Minimal unsecured frame",
			frame: Frame{
				Header: MessageHeader{
					SessionID:       0, // Unsecured
					SessionType:     SessionTypeUnicast,
					MessageCounter:  1,
					DestinationType: DestinationNone,
				},
				Protocol: ProtocolHeader{
					ProtocolID:     ProtocolSecureChannel,
					ProtocolOpcode: 0x20,
					ExchangeID:     1,
					Initiator:      true,
				},
				Payload: nil,
			},
		},
		{
			name: "With payload",
			frame: Frame{
				Header: MessageHeader{
					SessionID:      0,
					SessionType:    SessionTypeUnicast,
					MessageCounter: 100,
				},
				Protocol: ProtocolHeader{
					ProtocolID:     ProtocolSecureChannel,
					ProtocolOpcode: 0x21,
					ExchangeID:     2,
					Initiator:      true,
					Reliability:    true,
				},
				Payload: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			},
		},
		{
			name: "With acknowledgement",
			frame: Frame{
				Header: MessageHeader{
					SessionID:      0,
					SessionType:    SessionTypeUnicast,
					MessageCounter: 200,
				},
				Protocol: ProtocolHeader{
					ProtocolID:          ProtocolSecureChannel,
					ProtocolOpcode:      0x40,
					ExchangeID:          1,
					Acknowledgement:     true,
					AckedMessageCounter: 100,
				},
				Payload: []byte("test payload"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Encode
			encoded := tc.frame.EncodeUnsecured()

			// Decode
			decoded, err := DecodeUnsecured(encoded)
			if err != nil {
				t.Fatalf("DecodeUnsecured() error: %v", err)
			}

			// Compare
			compareHeaders(t, &tc.frame.Header, &decoded.Header)
			compareProtocolHeaders(t, &tc.frame.Protocol, &decoded.Protocol)

			if !bytes.Equal(decoded.Payload, tc.frame.Payload) {
				t.Errorf("Payload = %x, want %x", decoded.Payload, tc.frame.Payload)
			}
		})
	}
}

func TestRawFrameRoundtrip(t *testing.T) {
	// Test raw frame encoding/decoding (before/after encryption)
	tests := []struct {
		name string
		raw  RawFrame
	}{
		{
			name: "Secure unicast frame",
			raw: RawFrame{
				Header: MessageHeader{
					SessionID:       0x1234,
					SessionType:     SessionTypeUnicast,
					MessageCounter:  0x56789ABC,
					DestinationType: DestinationNone,
				},
				EncryptedPayload: []byte{0xAA, 0xBB, 0xCC, 0xDD},
				MIC:              make([]byte, MICSize),
			},
		},
		{
			name: "Group frame with source and dest",
			raw: RawFrame{
				Header: MessageHeader{
					SessionID:          0x1000,
					SessionType:        SessionTypeGroup,
					MessageCounter:     0x00001000,
					SourcePresent:      true,
					SourceNodeID:       0x0102030405060708,
					DestinationType:    DestinationGroupID,
					DestinationGroupID: 0xABCD,
				},
				EncryptedPayload: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
				MIC:              bytes.Repeat([]byte{0xFF}, MICSize),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Encode
			encoded := tc.raw.EncodeRaw()

			// Verify total size
			expectedSize := tc.raw.TotalSize()
			if len(encoded) != expectedSize {
				t.Errorf("EncodeRaw() length = %d, want %d", len(encoded), expectedSize)
			}

			// Decode
			decoded, err := DecodeRaw(encoded)
			if err != nil {
				t.Fatalf("DecodeRaw() error: %v", err)
			}

			// Compare
			compareHeaders(t, &tc.raw.Header, &decoded.Header)

			if !bytes.Equal(decoded.EncryptedPayload, tc.raw.EncryptedPayload) {
				t.Errorf("EncryptedPayload = %x, want %x", decoded.EncryptedPayload, tc.raw.EncryptedPayload)
			}

			if !bytes.Equal(decoded.MIC, tc.raw.MIC) {
				t.Errorf("MIC = %x, want %x", decoded.MIC, tc.raw.MIC)
			}
		})
	}
}

func TestStreamFraming(t *testing.T) {
	// Use net.Pipe for in-memory testing
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	writer := NewStreamWriter(clientConn)
	reader := NewStreamReader(serverConn)

	// Test frames
	frames := [][]byte{
		{0x01, 0x02, 0x03},
		{0x04, 0x05, 0x06, 0x07, 0x08},
		bytes.Repeat([]byte{0xFF}, 100),
	}

	// Write frames in goroutine
	go func() {
		for _, frame := range frames {
			if _, err := writer.Write(frame); err != nil {
				return
			}
		}
	}()

	// Read and verify frames
	for i, expected := range frames {
		got, err := reader.Read()
		if err != nil {
			t.Fatalf("Frame %d: Read() error: %v", i, err)
		}

		if !bytes.Equal(got, expected) {
			t.Errorf("Frame %d: got %x, want %x", i, got, expected)
		}
	}
}

func TestStreamWriterReadFrames(t *testing.T) {
	// Test WriteFrame and ReadFrame with actual RawFrame
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	writer := NewStreamWriter(clientConn)
	reader := NewStreamReader(serverConn)

	raw := &RawFrame{
		Header: MessageHeader{
			SessionID:       0x5678,
			SessionType:     SessionTypeUnicast,
			MessageCounter:  12345,
			DestinationType: DestinationNone,
		},
		EncryptedPayload: []byte("encrypted data here"),
		MIC:              bytes.Repeat([]byte{0xAB}, MICSize),
	}

	// Write in goroutine
	done := make(chan error, 1)
	go func() {
		done <- writer.WriteFrame(raw)
	}()

	// Read
	decoded, err := reader.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}

	// Wait for write to complete
	if err := <-done; err != nil {
		t.Fatalf("WriteFrame() error: %v", err)
	}

	// Compare
	compareHeaders(t, &raw.Header, &decoded.Header)

	if !bytes.Equal(decoded.EncryptedPayload, raw.EncryptedPayload) {
		t.Errorf("EncryptedPayload mismatch")
	}

	if !bytes.Equal(decoded.MIC, raw.MIC) {
		t.Errorf("MIC mismatch")
	}
}

func TestEncodeWithLengthPrefix(t *testing.T) {
	frame := []byte{0x01, 0x02, 0x03, 0x04}
	prefixed := EncodeWithLengthPrefix(frame)

	// Check length
	if len(prefixed) != TCPLengthPrefixSize+len(frame) {
		t.Errorf("Length = %d, want %d", len(prefixed), TCPLengthPrefixSize+len(frame))
	}

	// Check prefix value (little-endian)
	expectedPrefix := []byte{0x04, 0x00, 0x00, 0x00}
	if !bytes.Equal(prefixed[:TCPLengthPrefixSize], expectedPrefix) {
		t.Errorf("Prefix = %x, want %x", prefixed[:TCPLengthPrefixSize], expectedPrefix)
	}

	// Check frame data
	if !bytes.Equal(prefixed[TCPLengthPrefixSize:], frame) {
		t.Errorf("Frame data mismatch")
	}
}

func TestValidateSize(t *testing.T) {
	// Under limit
	err := ValidateSize(make([]byte, MaxUDPMessageSize))
	if err != nil {
		t.Errorf("ValidateSize(%d) error: %v", MaxUDPMessageSize, err)
	}

	// Over limit
	err = ValidateSize(make([]byte, MaxUDPMessageSize+1))
	if err != ErrMessageTooLong {
		t.Errorf("ValidateSize(%d) error = %v, want %v", MaxUDPMessageSize+1, err, ErrMessageTooLong)
	}
}

func TestDecodeRawErrors(t *testing.T) {
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
			name: "Secure but too short for MIC",
			data: func() []byte {
				// Create a secure header (SessionID != 0) with too little data
				return []byte{
					0x00,       // Message Flags
					0x01, 0x00, // Session ID = 1 (secure)
					0x00,                   // Security Flags
					0x00, 0x00, 0x00, 0x00, // Counter
					// No payload or MIC
				}
			}(),
			wantErr: ErrMessageTooShort,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeRaw(tc.data)
			if err != tc.wantErr {
				t.Errorf("DecodeRaw() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestStreamReaderErrors(t *testing.T) {
	t.Run("EOF on length read", func(t *testing.T) {
		r := NewStreamReader(bytes.NewReader(nil))
		_, err := r.Read()
		if err != io.EOF {
			t.Errorf("Read() error = %v, want %v", err, io.EOF)
		}
	})

	t.Run("Zero length prefix", func(t *testing.T) {
		data := []byte{0x00, 0x00, 0x00, 0x00} // Length = 0
		r := NewStreamReader(bytes.NewReader(data))
		_, err := r.Read()
		if err != ErrInvalidLengthPrefix {
			t.Errorf("Read() error = %v, want %v", err, ErrInvalidLengthPrefix)
		}
	})

	t.Run("Truncated frame data", func(t *testing.T) {
		data := []byte{0x10, 0x00, 0x00, 0x00, 0x01, 0x02} // Length = 16, but only 2 bytes
		r := NewStreamReader(bytes.NewReader(data))
		_, err := r.Read()
		if err != ErrStreamReadFailed {
			t.Errorf("Read() error = %v, want %v", err, ErrStreamReadFailed)
		}
	})
}
