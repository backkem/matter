package message

import (
	"bytes"
	"testing"
)

// Test encryption key (16 bytes)
var testKey = []byte{
	0x5e, 0xde, 0xd2, 0x44, 0xe5, 0x53, 0x2b, 0x3c,
	0xdc, 0x23, 0x40, 0x9d, 0xba, 0xd0, 0x52, 0xd2,
}

func TestCodecRoundtrip(t *testing.T) {
	codec, err := NewCodec(testKey, UnspecifiedNodeID)
	if err != nil {
		t.Fatalf("NewCodec() error: %v", err)
	}

	tests := []struct {
		name    string
		header  MessageHeader
		proto   ProtocolHeader
		payload []byte
		privacy bool
	}{
		{
			name: "Minimal secure message",
			header: MessageHeader{
				SessionID:       0x1234,
				SessionType:     SessionTypeUnicast,
				MessageCounter:  1,
				DestinationType: DestinationNone,
			},
			proto: ProtocolHeader{
				ProtocolID:     ProtocolSecureChannel,
				ProtocolOpcode: 0x40,
				ExchangeID:     1,
			},
			payload: nil,
			privacy: false,
		},
		{
			name: "With application payload",
			header: MessageHeader{
				SessionID:       0x5678,
				SessionType:     SessionTypeUnicast,
				MessageCounter:  100,
				DestinationType: DestinationNone,
			},
			proto: ProtocolHeader{
				ProtocolID:     ProtocolInteractionModel,
				ProtocolOpcode: 0x02,
				ExchangeID:     0xABCD,
				Initiator:      true,
				Reliability:    true,
			},
			payload: []byte("Hello, Matter!"),
			privacy: false,
		},
		{
			name: "With acknowledgement",
			header: MessageHeader{
				SessionID:       0x1000,
				SessionType:     SessionTypeUnicast,
				MessageCounter:  200,
				DestinationType: DestinationNone,
			},
			proto: ProtocolHeader{
				ProtocolID:          ProtocolSecureChannel,
				ProtocolOpcode:      0x40,
				ExchangeID:          1,
				Acknowledgement:     true,
				AckedMessageCounter: 199,
			},
			payload: []byte{0x01, 0x02, 0x03, 0x04},
			privacy: false,
		},
		{
			name: "With privacy",
			header: MessageHeader{
				SessionID:       0x2000,
				SessionType:     SessionTypeUnicast,
				MessageCounter:  300,
				DestinationType: DestinationNone,
			},
			proto: ProtocolHeader{
				ProtocolID:     ProtocolInteractionModel,
				ProtocolOpcode: 0x05,
				ExchangeID:     0x1111,
			},
			payload: []byte("Private message content"),
			privacy: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Make a copy of header (Encode modifies Privacy flag)
			header := tc.header

			// Encode
			encoded, err := codec.Encode(&header, &tc.proto, tc.payload, tc.privacy)
			if err != nil {
				t.Fatalf("Encode() error: %v", err)
			}

			// Verify privacy flag was set
			if tc.privacy && !header.Privacy {
				t.Error("Privacy flag should be set after encode")
			}

			// Decode
			decoded, err := codec.Decode(encoded, UnspecifiedNodeID)
			if err != nil {
				t.Fatalf("Decode() error: %v", err)
			}

			// Compare header fields (note: some may differ due to decoding)
			if decoded.Header.SessionID != tc.header.SessionID {
				t.Errorf("SessionID = %04x, want %04x", decoded.Header.SessionID, tc.header.SessionID)
			}
			if decoded.Header.MessageCounter != tc.header.MessageCounter {
				t.Errorf("MessageCounter = %08x, want %08x", decoded.Header.MessageCounter, tc.header.MessageCounter)
			}

			// Compare protocol header
			compareProtocolHeaders(t, &tc.proto, &decoded.Protocol)

			// Compare payload
			if !bytes.Equal(decoded.Payload, tc.payload) {
				t.Errorf("Payload = %x, want %x", decoded.Payload, tc.payload)
			}
		})
	}
}

func TestCodecWithSourceNodeID(t *testing.T) {
	sourceNodeID := uint64(0x0102030405060708)
	codec, err := NewCodec(testKey, sourceNodeID)
	if err != nil {
		t.Fatalf("NewCodec() error: %v", err)
	}

	header := MessageHeader{
		SessionID:       0x1234,
		SessionType:     SessionTypeUnicast,
		MessageCounter:  1,
		DestinationType: DestinationNone,
	}

	proto := ProtocolHeader{
		ProtocolID:     ProtocolSecureChannel,
		ProtocolOpcode: 0x40,
		ExchangeID:     1,
	}

	payload := []byte("test")

	// Encode
	encoded, err := codec.Encode(&header, &proto, payload, false)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// Decode with same source node ID
	decoded, err := codec.Decode(encoded, sourceNodeID)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	if !bytes.Equal(decoded.Payload, payload) {
		t.Errorf("Payload mismatch")
	}

	// Decode with wrong source node ID should fail
	_, err = codec.Decode(encoded, 0xDEADBEEF)
	if err != ErrDecryptionFailed {
		t.Errorf("Decode() with wrong node ID error = %v, want %v", err, ErrDecryptionFailed)
	}
}

func TestCodecPrivacyObfuscation(t *testing.T) {
	codec, err := NewCodec(testKey, UnspecifiedNodeID)
	if err != nil {
		t.Fatalf("NewCodec() error: %v", err)
	}

	header := MessageHeader{
		SessionID:       0xABCD,
		SessionType:     SessionTypeUnicast,
		MessageCounter:  0x12345678,
		DestinationType: DestinationNone,
	}

	proto := ProtocolHeader{
		ProtocolID:     ProtocolSecureChannel,
		ProtocolOpcode: 0x40,
		ExchangeID:     1,
	}

	// Encode without privacy
	encodedNoPrivacy, err := codec.Encode(&header, &proto, nil, false)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// Reset header for next encode
	header.Privacy = false

	// Encode with privacy
	encodedWithPrivacy, err := codec.Encode(&header, &proto, nil, true)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// The first 4 bytes (Flags + SessionID + SecFlags) should be different
	// because SecFlags includes the P flag
	// But the obfuscated portion (Counter) at offset 4 should be different

	// Verify the P flag is set in the privacy-encoded message
	secFlagsOffset := 3 // Flags(1) + SessionID(2)
	if encodedWithPrivacy[secFlagsOffset]&0x80 == 0 {
		t.Error("P flag should be set in privacy-encoded message")
	}

	if encodedNoPrivacy[secFlagsOffset]&0x80 != 0 {
		t.Error("P flag should not be set in non-privacy message")
	}

	// The counter portion should be different (obfuscated)
	counterOffset := 4 // After Flags + SessionID + SecFlags
	counterNoPrivacy := encodedNoPrivacy[counterOffset : counterOffset+4]
	counterWithPrivacy := encodedWithPrivacy[counterOffset : counterOffset+4]

	// Counter in non-privacy message should be plaintext
	expectedCounter := []byte{0x78, 0x56, 0x34, 0x12} // Little-endian
	if !bytes.Equal(counterNoPrivacy, expectedCounter) {
		t.Errorf("Non-privacy counter = %x, want %x", counterNoPrivacy, expectedCounter)
	}

	// Counter in privacy message should be obfuscated (different)
	if bytes.Equal(counterWithPrivacy, expectedCounter) {
		t.Error("Privacy counter should be obfuscated (different from plaintext)")
	}

	// Both should decode correctly
	decodedNoPrivacy, err := codec.Decode(encodedNoPrivacy, UnspecifiedNodeID)
	if err != nil {
		t.Fatalf("Decode(noPrivacy) error: %v", err)
	}

	decodedWithPrivacy, err := codec.Decode(encodedWithPrivacy, UnspecifiedNodeID)
	if err != nil {
		t.Fatalf("Decode(withPrivacy) error: %v", err)
	}

	// Both should have the same message counter after decoding
	if decodedNoPrivacy.Header.MessageCounter != 0x12345678 {
		t.Errorf("NoPrivacy MessageCounter = %08x, want %08x", decodedNoPrivacy.Header.MessageCounter, 0x12345678)
	}

	if decodedWithPrivacy.Header.MessageCounter != 0x12345678 {
		t.Errorf("WithPrivacy MessageCounter = %08x, want %08x", decodedWithPrivacy.Header.MessageCounter, 0x12345678)
	}
}

func TestCodecDecryptionFailure(t *testing.T) {
	codec, err := NewCodec(testKey, UnspecifiedNodeID)
	if err != nil {
		t.Fatalf("NewCodec() error: %v", err)
	}

	header := MessageHeader{
		SessionID:       0x1234,
		SessionType:     SessionTypeUnicast,
		MessageCounter:  1,
		DestinationType: DestinationNone,
	}

	proto := ProtocolHeader{
		ProtocolID:     ProtocolSecureChannel,
		ProtocolOpcode: 0x40,
		ExchangeID:     1,
	}

	// Encode
	encoded, err := codec.Encode(&header, &proto, []byte("test"), false)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// Tamper with the encrypted payload
	encoded[len(encoded)-MICSize-1] ^= 0xFF

	// Decode should fail
	_, err = codec.Decode(encoded, UnspecifiedNodeID)
	if err != ErrDecryptionFailed {
		t.Errorf("Decode() error = %v, want %v", err, ErrDecryptionFailed)
	}
}

func TestCodecInvalidKey(t *testing.T) {
	// Too short
	_, err := NewCodec(make([]byte, 15), UnspecifiedNodeID)
	if err != ErrInvalidKey {
		t.Errorf("NewCodec(15 bytes) error = %v, want %v", err, ErrInvalidKey)
	}

	// Too long
	_, err = NewCodec(make([]byte, 17), UnspecifiedNodeID)
	if err != ErrInvalidKey {
		t.Errorf("NewCodec(17 bytes) error = %v, want %v", err, ErrInvalidKey)
	}

	// Nil
	_, err = NewCodec(nil, UnspecifiedNodeID)
	if err != ErrInvalidKey {
		t.Errorf("NewCodec(nil) error = %v, want %v", err, ErrInvalidKey)
	}
}

func TestUnsecuredCodec(t *testing.T) {
	codec := NewUnsecuredCodec()

	header := MessageHeader{
		SessionID:       0, // Unsecured
		SessionType:     SessionTypeUnicast,
		MessageCounter:  1,
		DestinationType: DestinationNone,
	}

	proto := ProtocolHeader{
		ProtocolID:     ProtocolSecureChannel,
		ProtocolOpcode: 0x20, // PBKDF Param Request
		ExchangeID:     1,
		Initiator:      true,
	}

	payload := []byte("PBKDF params")

	// Encode
	encoded := codec.Encode(&header, &proto, payload)

	// Decode
	decoded, err := codec.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	// Compare
	if decoded.Header.SessionID != 0 {
		t.Errorf("SessionID = %04x, want 0", decoded.Header.SessionID)
	}

	compareProtocolHeaders(t, &proto, &decoded.Protocol)

	if !bytes.Equal(decoded.Payload, payload) {
		t.Errorf("Payload = %x, want %x", decoded.Payload, payload)
	}
}

func TestDecodeWithKey(t *testing.T) {
	codec, _ := NewCodec(testKey, UnspecifiedNodeID)

	header := MessageHeader{
		SessionID:       0x1234,
		SessionType:     SessionTypeUnicast,
		MessageCounter:  1,
		DestinationType: DestinationNone,
	}

	proto := ProtocolHeader{
		ProtocolID:     ProtocolSecureChannel,
		ProtocolOpcode: 0x40,
		ExchangeID:     1,
	}

	// Encode
	encoded, _ := codec.Encode(&header, &proto, []byte("test"), false)

	// Decode using convenience function
	decoded, err := DecodeWithKey(encoded, testKey, UnspecifiedNodeID)
	if err != nil {
		t.Fatalf("DecodeWithKey() error: %v", err)
	}

	if !bytes.Equal(decoded.Payload, []byte("test")) {
		t.Errorf("Payload mismatch")
	}
}

func TestCodecGroupMessage(t *testing.T) {
	sourceNodeID := uint64(0xABCDEF0123456789)
	codec, err := NewCodec(testKey, sourceNodeID)
	if err != nil {
		t.Fatalf("NewCodec() error: %v", err)
	}

	header := MessageHeader{
		SessionID:          0x1000,
		SessionType:        SessionTypeGroup,
		MessageCounter:     100,
		SourcePresent:      true,
		SourceNodeID:       sourceNodeID,
		DestinationType:    DestinationGroupID,
		DestinationGroupID: 0x1234,
	}

	proto := ProtocolHeader{
		ProtocolID:     ProtocolInteractionModel,
		ProtocolOpcode: 0x10,
		ExchangeID:     1,
		Initiator:      true,
	}

	payload := []byte("Group message payload")

	// Encode
	encoded, err := codec.Encode(&header, &proto, payload, false)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// Decode
	decoded, err := codec.Decode(encoded, sourceNodeID)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	// Verify
	if decoded.Header.SessionType != SessionTypeGroup {
		t.Errorf("SessionType = %v, want %v", decoded.Header.SessionType, SessionTypeGroup)
	}

	if decoded.Header.SourceNodeID != sourceNodeID {
		t.Errorf("SourceNodeID = %016x, want %016x", decoded.Header.SourceNodeID, sourceNodeID)
	}

	if decoded.Header.DestinationGroupID != 0x1234 {
		t.Errorf("DestinationGroupID = %04x, want %04x", decoded.Header.DestinationGroupID, 0x1234)
	}

	if !bytes.Equal(decoded.Payload, payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestCodecLargePayload(t *testing.T) {
	codec, err := NewCodec(testKey, UnspecifiedNodeID)
	if err != nil {
		t.Fatalf("NewCodec() error: %v", err)
	}

	header := MessageHeader{
		SessionID:       0x1234,
		SessionType:     SessionTypeUnicast,
		MessageCounter:  1,
		DestinationType: DestinationNone,
	}

	proto := ProtocolHeader{
		ProtocolID:     ProtocolInteractionModel,
		ProtocolOpcode: 0x05,
		ExchangeID:     1,
	}

	// Create a reasonably large payload
	payload := bytes.Repeat([]byte{0xAB}, 1000)

	// Encode
	encoded, err := codec.Encode(&header, &proto, payload, false)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// Decode
	decoded, err := codec.Decode(encoded, UnspecifiedNodeID)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	if !bytes.Equal(decoded.Payload, payload) {
		t.Errorf("Large payload roundtrip failed")
	}
}
