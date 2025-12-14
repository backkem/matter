package session

import (
	"bytes"
	"testing"

	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/message"
)

// Test vectors from C SDK TestSessionManagerDispatch.cpp theMessageTestVector.
// These are the PASE session encryption test vectors.

// PASE encryption test vector: "secure pase message (short payload)"
// From C SDK TestSessionManagerDispatch.cpp
var paseTestVector = struct {
	name string

	// Session parameters
	sessionID  uint16
	peerNodeID uint64

	// Keys
	encryptKey []byte

	// Message content
	payload        []byte // Application payload
	plainMessage   []byte // Full plaintext message (header + protocol + payload)
	encryptedFrame []byte // Full encrypted frame (header + encrypted protocol/payload + MIC)

	// Message header fields (from plaintext)
	messageCounter uint32
}{
	name: "secure pase message (short payload)",

	// Session ID = 0x0bb8 (3000), peerNodeID = 0 (unspecified for PASE)
	sessionID:  0x0bb8,
	peerNodeID: 0x0000000000000000,

	// The "test key" used by C SDK for PASE tests
	// Note: For PASE, I2R and R2I keys are the same in this test vector
	encryptKey: []byte{
		0x5e, 0xde, 0xd2, 0x44, 0xe5, 0x53, 0x2b, 0x3c,
		0xdc, 0x23, 0x40, 0x9d, 0xba, 0xd0, 0x52, 0xd2,
	},

	// Application payload
	payload: []byte{0x11, 0x22, 0x33, 0x44, 0x55},

	// Full plaintext: message header (8 bytes) + protocol header (6 bytes) + payload (5 bytes) = 19 bytes
	// Byte breakdown:
	//   [0]:     0x00 - Message flags (version=0, S=0, DSIZ=00)
	//   [1-2]:   0xb8 0x0b - Session ID 0x0bb8 (LE)
	//   [3]:     0x00 - Security flags (session type=unicast, no P/C/MX)
	//   [4-7]:   0x39 0x30 0x00 0x00 - Message counter 0x00003039 (LE) = 12345
	//   [8-13]:  Protocol header: 0x05 0x64 0xee 0x0e 0x20 0x7d
	//            - 0x05 = Exchange flags (I=1, A=0, R=1)
	//            - 0x64 = Protocol Opcode (100)
	//            - 0xee 0x0e = Exchange ID 0x0eee (LE)
	//            - 0x20 0x7d = Protocol ID 0x7d20 (LE) - but this seems wrong...
	//   [14-18]: Payload: 0x11 0x22 0x33 0x44 0x55
	plainMessage: []byte{
		0x00, 0xb8, 0x0b, 0x00, 0x39, 0x30, 0x00, 0x00, // Message header
		0x05, 0x64, 0xee, 0x0e, 0x20, 0x7d, // Protocol header
		0x11, 0x22, 0x33, 0x44, 0x55, // Payload
	},

	// Full encrypted frame: header (8 bytes) + encrypted (11 bytes) + MIC (16 bytes) = 35 bytes
	// The header stays the same, protocol header + payload are encrypted
	encryptedFrame: []byte{
		0x00, 0xb8, 0x0b, 0x00, 0x39, 0x30, 0x00, 0x00, // Message header (unencrypted)
		0x5a, 0x98, 0x9a, 0xe4, 0x2e, 0x8d, 0x0f, 0x7f, 0x88, 0x5d, 0xfb, // Encrypted protocol+payload
		0x2f, 0xaa, 0x89, 0x49, 0xcf, 0x73, 0x0a, 0x57, 0x28, 0xe0, 0x35, 0x46, 0x10, 0xa0, 0xc4, 0xa7, // MIC
	},

	// Message header fields
	messageCounter: 0x00003039, // 12345
}

// TestSecureContextDecryptSDKVector tests decryption using C SDK test vector.
func TestSecureContextDecryptSDKVector(t *testing.T) {
	tv := paseTestVector

	// Create a SecureContext as a PASE responder
	// The responder decrypts with I2R key (since initiator encrypted with I2R)
	ctx, err := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleResponder,
		LocalSessionID: tv.sessionID,
		PeerSessionID:  tv.sessionID, // Same for test
		I2RKey:         tv.encryptKey,
		R2IKey:         tv.encryptKey, // Same key for this test
		FabricIndex:    0,             // Unset for PASE
		PeerNodeID:     fabric.NodeID(tv.peerNodeID),
		LocalNodeID:    fabric.NodeID(0), // Unset for PASE
	})
	if err != nil {
		t.Fatalf("NewSecureContext() error = %v", err)
	}

	// Decrypt the SDK test vector
	frame, err := ctx.Decrypt(tv.encryptedFrame)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	// Verify the decrypted message header
	if frame.Header.SessionID != tv.sessionID {
		t.Errorf("SessionID = %d, want %d", frame.Header.SessionID, tv.sessionID)
	}
	if frame.Header.MessageCounter != tv.messageCounter {
		t.Errorf("MessageCounter = %d, want %d", frame.Header.MessageCounter, tv.messageCounter)
	}

	// Verify the payload
	if !bytes.Equal(frame.Payload, tv.payload) {
		t.Errorf("Payload mismatch:\n  got:  %x\n  want: %x", frame.Payload, tv.payload)
	}
}

// TestSecureContextEncryptSDKVector tests encryption matches C SDK test vector.
func TestSecureContextEncryptSDKVector(t *testing.T) {
	tv := paseTestVector

	// Create a SecureContext as a PASE initiator
	// The initiator encrypts with I2R key
	ctx, err := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: tv.sessionID,
		PeerSessionID:  tv.sessionID, // Same for test
		I2RKey:         tv.encryptKey,
		R2IKey:         tv.encryptKey, // Same key for this test
		FabricIndex:    0,             // Unset for PASE
		PeerNodeID:     fabric.NodeID(tv.peerNodeID),
		LocalNodeID:    fabric.NodeID(0), // Unset for PASE
	})
	if err != nil {
		t.Fatalf("NewSecureContext() error = %v", err)
	}

	// Override the counter to match the test vector
	// The test vector uses counter 0x00003039 (12345)
	ctx.mu.Lock()
	ctx.localCounter = message.NewSessionCounterWithValue(tv.messageCounter)
	ctx.mu.Unlock()

	// Build the protocol header from the plaintext bytes
	// Protocol header bytes 8-13: 0x05 0x64 0xee 0x0e 0x20 0x7d
	// Parse exchange flags (0x05): I=1, A=0, R=1
	protocolHeader := &message.ProtocolHeader{
		Initiator:      true,  // Bit 0 of 0x05
		Acknowledgement: false, // Bit 1 of 0x05
		Reliability:    true,  // Bit 2 of 0x05
		ProtocolOpcode: tv.plainMessage[9],                                                            // 0x64
		ExchangeID:     uint16(tv.plainMessage[10]) | uint16(tv.plainMessage[11])<<8,                  // 0x0eee
		ProtocolID:     message.ProtocolID(uint16(tv.plainMessage[12]) | uint16(tv.plainMessage[13])<<8), // 0x7d20
	}

	// Create message header (minimal for unicast PASE)
	msgHeader := &message.MessageHeader{
		SessionType: message.SessionTypeUnicast,
		// SessionID and MessageCounter will be set by Encrypt
	}

	// Encrypt
	encrypted, err := ctx.Encrypt(msgHeader, protocolHeader, tv.payload, false)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Compare the full encrypted frame
	if !bytes.Equal(encrypted, tv.encryptedFrame) {
		t.Errorf("Encrypted frame mismatch:\n  got:  %x\n  want: %x", encrypted, tv.encryptedFrame)
	}
}

// TestSecureContextRoundtripSDKVector tests encrypt then decrypt.
func TestSecureContextRoundtripSDKVector(t *testing.T) {
	tv := paseTestVector

	// Create initiator context
	initiator, err := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: 1000,
		PeerSessionID:  2000,
		I2RKey:         tv.encryptKey,
		R2IKey:         tv.encryptKey,
		FabricIndex:    0,
		PeerNodeID:     fabric.NodeID(0),
		LocalNodeID:    fabric.NodeID(0),
	})
	if err != nil {
		t.Fatalf("NewSecureContext(initiator) error = %v", err)
	}

	// Create responder context
	responder, err := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleResponder,
		LocalSessionID: 2000,
		PeerSessionID:  1000,
		I2RKey:         tv.encryptKey,
		R2IKey:         tv.encryptKey,
		FabricIndex:    0,
		PeerNodeID:     fabric.NodeID(0),
		LocalNodeID:    fabric.NodeID(0),
	})
	if err != nil {
		t.Fatalf("NewSecureContext(responder) error = %v", err)
	}

	// Build protocol header
	protocolHeader := &message.ProtocolHeader{
		Initiator:      true,
		Reliability:    true,
		ProtocolOpcode: 0x20,
		ExchangeID:     0x0001,
		ProtocolID:     message.ProtocolSecureChannel,
	}

	// Initiator encrypts (uses I2R key)
	msgHeader := &message.MessageHeader{
		SessionType: message.SessionTypeUnicast,
	}
	encrypted, err := initiator.Encrypt(msgHeader, protocolHeader, tv.payload, false)
	if err != nil {
		t.Fatalf("initiator.Encrypt() error = %v", err)
	}

	// Responder decrypts (uses I2R key to decrypt)
	frame, err := responder.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("responder.Decrypt() error = %v", err)
	}

	// Verify payload matches
	if !bytes.Equal(frame.Payload, tv.payload) {
		t.Errorf("Payload mismatch:\n  got:  %x\n  want: %x", frame.Payload, tv.payload)
	}

	// Now test the reverse direction: responder encrypts, initiator decrypts
	responderHeader := &message.MessageHeader{
		SessionType: message.SessionTypeUnicast,
	}
	responderProto := &message.ProtocolHeader{
		Acknowledgement: true, // Response flag
		ProtocolOpcode:  0x21,
		ExchangeID:      0x0001,
		ProtocolID:      message.ProtocolSecureChannel,
	}
	responsePayload := []byte{0xaa, 0xbb, 0xcc}

	encryptedResponse, err := responder.Encrypt(responderHeader, responderProto, responsePayload, false)
	if err != nil {
		t.Fatalf("responder.Encrypt() error = %v", err)
	}

	// Initiator decrypts (uses R2I key)
	responseFrame, err := initiator.Decrypt(encryptedResponse)
	if err != nil {
		t.Fatalf("initiator.Decrypt() error = %v", err)
	}

	if !bytes.Equal(responseFrame.Payload, responsePayload) {
		t.Errorf("Response payload mismatch:\n  got:  %x\n  want: %x", responseFrame.Payload, responsePayload)
	}
}

// TestSecureContextDecryptWrongMIC tests that wrong MIC is detected.
// From C SDK test vector "secure pase message (short payload / wrong MIC)"
func TestSecureContextDecryptWrongMIC(t *testing.T) {
	tv := paseTestVector

	// Create context
	ctx, err := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleResponder,
		LocalSessionID: tv.sessionID,
		PeerSessionID:  tv.sessionID,
		I2RKey:         tv.encryptKey,
		R2IKey:         tv.encryptKey,
		FabricIndex:    0,
		PeerNodeID:     fabric.NodeID(tv.peerNodeID),
		LocalNodeID:    fabric.NodeID(0),
	})
	if err != nil {
		t.Fatalf("NewSecureContext() error = %v", err)
	}

	// Corrupt the last byte of the encrypted frame (the MIC)
	wrongMIC := make([]byte, len(tv.encryptedFrame))
	copy(wrongMIC, tv.encryptedFrame)
	wrongMIC[len(wrongMIC)-1] ^= 0xFF // Flip all bits in last byte

	// Decrypt should fail
	_, err = ctx.Decrypt(wrongMIC)
	if err == nil {
		t.Error("Decrypt() should fail with wrong MIC")
	}
}

// TestSecureContextCASEWithNodeID tests CASE session encryption with actual NodeIDs.
func TestSecureContextCASEWithNodeID(t *testing.T) {
	// CASE sessions use actual operational node IDs in the nonce
	localNodeID := fabric.NodeID(0x0102030405060708)
	peerNodeID := fabric.NodeID(0x1112131415161718)

	i2rKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	r2iKey := []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}

	// Create initiator
	initiator, err := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypeCASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: 1000,
		PeerSessionID:  2000,
		I2RKey:         i2rKey,
		R2IKey:         r2iKey,
		FabricIndex:    1,
		PeerNodeID:     peerNodeID,
		LocalNodeID:    localNodeID,
	})
	if err != nil {
		t.Fatalf("NewSecureContext(initiator) error = %v", err)
	}

	// Create responder
	responder, err := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypeCASE,
		Role:           SessionRoleResponder,
		LocalSessionID: 2000,
		PeerSessionID:  1000,
		I2RKey:         i2rKey,
		R2IKey:         r2iKey,
		FabricIndex:    1,
		PeerNodeID:     localNodeID,
		LocalNodeID:    peerNodeID,
	})
	if err != nil {
		t.Fatalf("NewSecureContext(responder) error = %v", err)
	}

	// Test payload
	payload := []byte("Hello CASE Session!")

	// Initiator encrypts
	msgHeader := &message.MessageHeader{
		SessionType: message.SessionTypeUnicast,
	}
	protocolHeader := &message.ProtocolHeader{
		Initiator:      true,
		Reliability:    true,
		ProtocolOpcode: 0x01,
		ExchangeID:     0x1234,
		ProtocolID:     message.ProtocolInteractionModel,
	}

	encrypted, err := initiator.Encrypt(msgHeader, protocolHeader, payload, false)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Responder decrypts
	frame, err := responder.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !bytes.Equal(frame.Payload, payload) {
		t.Errorf("Payload mismatch:\n  got:  %x\n  want: %x", frame.Payload, payload)
	}
}
