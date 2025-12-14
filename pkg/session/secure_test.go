package session

import (
	"bytes"
	"testing"
	"time"

	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/message"
)

// Test keys (16 bytes each)
var (
	testI2RKey = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	testR2IKey = []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20}
)

func TestNewSecureContext_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  SecureContextConfig
		wantErr error
	}{
		{
			name: "valid PASE config",
			config: SecureContextConfig{
				SessionType:    SessionTypePASE,
				Role:           SessionRoleInitiator,
				LocalSessionID: 1,
				PeerSessionID:  2,
				I2RKey:         testI2RKey,
				R2IKey:         testR2IKey,
			},
			wantErr: nil,
		},
		{
			name: "valid CASE config",
			config: SecureContextConfig{
				SessionType:    SessionTypeCASE,
				Role:           SessionRoleResponder,
				LocalSessionID: 100,
				PeerSessionID:  200,
				I2RKey:         testI2RKey,
				R2IKey:         testR2IKey,
				FabricIndex:    1,
				PeerNodeID:     fabric.NodeID(0x1234),
				LocalNodeID:    fabric.NodeID(0x5678),
			},
			wantErr: nil,
		},
		{
			name: "invalid session type",
			config: SecureContextConfig{
				SessionType:    SessionTypeUnknown,
				Role:           SessionRoleInitiator,
				LocalSessionID: 1,
				PeerSessionID:  2,
				I2RKey:         testI2RKey,
				R2IKey:         testR2IKey,
			},
			wantErr: ErrInvalidSessionType,
		},
		{
			name: "invalid role",
			config: SecureContextConfig{
				SessionType:    SessionTypePASE,
				Role:           SessionRoleUnknown,
				LocalSessionID: 1,
				PeerSessionID:  2,
				I2RKey:         testI2RKey,
				R2IKey:         testR2IKey,
			},
			wantErr: ErrInvalidRole,
		},
		{
			name: "zero local session ID",
			config: SecureContextConfig{
				SessionType:    SessionTypePASE,
				Role:           SessionRoleInitiator,
				LocalSessionID: 0,
				PeerSessionID:  2,
				I2RKey:         testI2RKey,
				R2IKey:         testR2IKey,
			},
			wantErr: ErrInvalidSessionID,
		},
		{
			name: "invalid I2R key length",
			config: SecureContextConfig{
				SessionType:    SessionTypePASE,
				Role:           SessionRoleInitiator,
				LocalSessionID: 1,
				PeerSessionID:  2,
				I2RKey:         []byte{0x01, 0x02, 0x03}, // Too short
				R2IKey:         testR2IKey,
			},
			wantErr: ErrInvalidKey,
		},
		{
			name: "invalid R2I key length",
			config: SecureContextConfig{
				SessionType:    SessionTypePASE,
				Role:           SessionRoleInitiator,
				LocalSessionID: 1,
				PeerSessionID:  2,
				I2RKey:         testI2RKey,
				R2IKey:         []byte{0x01, 0x02, 0x03}, // Too short
			},
			wantErr: ErrInvalidKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSecureContext(tt.config)
			if err != tt.wantErr {
				t.Errorf("NewSecureContext() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSecureContext_Getters(t *testing.T) {
	ctx, err := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypeCASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: 123,
		PeerSessionID:  456,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
		FabricIndex:    5,
		PeerNodeID:     fabric.NodeID(0xABCD),
		LocalNodeID:    fabric.NodeID(0x1234),
		CaseAuthTags:   []uint32{1, 2, 3},
	})
	if err != nil {
		t.Fatalf("NewSecureContext() error = %v", err)
	}

	if ctx.LocalSessionID() != 123 {
		t.Errorf("LocalSessionID() = %d, want 123", ctx.LocalSessionID())
	}
	if ctx.PeerSessionID() != 456 {
		t.Errorf("PeerSessionID() = %d, want 456", ctx.PeerSessionID())
	}
	if ctx.SessionType() != SessionTypeCASE {
		t.Errorf("SessionType() = %v, want CASE", ctx.SessionType())
	}
	if ctx.Role() != SessionRoleInitiator {
		t.Errorf("Role() = %v, want Initiator", ctx.Role())
	}
	if ctx.FabricIndex() != 5 {
		t.Errorf("FabricIndex() = %d, want 5", ctx.FabricIndex())
	}
	if ctx.PeerNodeID() != fabric.NodeID(0xABCD) {
		t.Errorf("PeerNodeID() = %v, want 0xABCD", ctx.PeerNodeID())
	}
	if ctx.LocalNodeID() != fabric.NodeID(0x1234) {
		t.Errorf("LocalNodeID() = %v, want 0x1234", ctx.LocalNodeID())
	}

	cats := ctx.CaseAuthTags()
	if len(cats) != 3 || cats[0] != 1 || cats[1] != 2 || cats[2] != 3 {
		t.Errorf("CaseAuthTags() = %v, want [1, 2, 3]", cats)
	}
}

func TestSecureContext_FabricIndexUpdate(t *testing.T) {
	ctx, _ := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: 1,
		PeerSessionID:  2,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
		FabricIndex:    0, // PASE starts with no fabric
	})

	if ctx.FabricIndex() != 0 {
		t.Errorf("FabricIndex() = %d, want 0", ctx.FabricIndex())
	}

	// Simulate AddNOC completion
	ctx.SetFabricIndex(3)
	if ctx.FabricIndex() != 3 {
		t.Errorf("FabricIndex() after SetFabricIndex(3) = %d, want 3", ctx.FabricIndex())
	}
}

func TestSecureContext_ResumptionID(t *testing.T) {
	ctx, _ := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypeCASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: 1,
		PeerSessionID:  2,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
	})

	// Initially zero
	rid := ctx.ResumptionID()
	var zeroID [16]byte
	if rid != zeroID {
		t.Errorf("ResumptionID() initially = %x, want zeros", rid)
	}

	// Set and verify
	var testID [16]byte
	for i := range testID {
		testID[i] = byte(i)
	}
	ctx.SetResumptionID(testID)

	rid = ctx.ResumptionID()
	if rid != testID {
		t.Errorf("ResumptionID() = %x, want %x", rid, testID)
	}
}

func TestSecureContext_SharedSecret(t *testing.T) {
	// PASE session has no shared secret
	pase, _ := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: 1,
		PeerSessionID:  2,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
	})
	if pase.SharedSecret() != nil {
		t.Error("PASE SharedSecret() should be nil")
	}

	// CASE session with shared secret
	secret := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	caseCtx, _ := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypeCASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: 1,
		PeerSessionID:  2,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
		SharedSecret:   secret,
	})
	got := caseCtx.SharedSecret()
	if !bytes.Equal(got, secret) {
		t.Errorf("SharedSecret() = %x, want %x", got, secret)
	}

	// Verify it returns a copy (modifying returned value doesn't affect context)
	got[0] = 0xFF
	got2 := caseCtx.SharedSecret()
	if got2[0] == 0xFF {
		t.Error("SharedSecret() should return a copy")
	}
}

func TestSecureContext_IsPeerActive(t *testing.T) {
	ctx, _ := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: 1,
		PeerSessionID:  2,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
		Params: Params{
			ActiveThreshold: 100 * time.Millisecond,
		},
	})

	// Initially active (just created)
	if !ctx.IsPeerActive() {
		t.Error("IsPeerActive() should be true immediately after creation")
	}

	// Wait for threshold to expire
	time.Sleep(150 * time.Millisecond)

	if ctx.IsPeerActive() {
		t.Error("IsPeerActive() should be false after threshold expires")
	}

	// Mark activity
	ctx.MarkActivity(true)
	if !ctx.IsPeerActive() {
		t.Error("IsPeerActive() should be true after MarkActivity")
	}
}

func TestSecureContext_Timestamps(t *testing.T) {
	before := time.Now()
	ctx, _ := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: 1,
		PeerSessionID:  2,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
	})
	after := time.Now()

	st := ctx.SessionTimestamp()
	at := ctx.ActiveTimestamp()

	if st.Before(before) || st.After(after) {
		t.Errorf("SessionTimestamp() = %v, should be between %v and %v", st, before, after)
	}
	if at.Before(before) || at.After(after) {
		t.Errorf("ActiveTimestamp() = %v, should be between %v and %v", at, before, after)
	}
}

func TestSecureContext_NextCounter(t *testing.T) {
	ctx, _ := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: 1,
		PeerSessionID:  2,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
	})

	// Counters should increment
	c1, err := ctx.NextCounter()
	if err != nil {
		t.Fatalf("NextCounter() error = %v", err)
	}

	c2, err := ctx.NextCounter()
	if err != nil {
		t.Fatalf("NextCounter() error = %v", err)
	}

	if c2 != c1+1 {
		t.Errorf("NextCounter() = %d, want %d", c2, c1+1)
	}
}

func TestSecureContext_CheckCounter(t *testing.T) {
	ctx, _ := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: 1,
		PeerSessionID:  2,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
	})

	// First counter accepted
	if !ctx.CheckCounter(100) {
		t.Error("CheckCounter(100) should accept first counter")
	}

	// Duplicate rejected
	if ctx.CheckCounter(100) {
		t.Error("CheckCounter(100) should reject duplicate")
	}

	// Higher counter accepted
	if !ctx.CheckCounter(101) {
		t.Error("CheckCounter(101) should be accepted")
	}
}

func TestSecureContext_ZeroizeKeys(t *testing.T) {
	ctx, _ := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: 1,
		PeerSessionID:  2,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
		SharedSecret:   []byte{0xAA, 0xBB},
	})

	ctx.ZeroizeKeys()

	// Keys should be zeroed
	for _, b := range ctx.i2rKey {
		if b != 0 {
			t.Error("i2rKey should be zeroed")
			break
		}
	}
	for _, b := range ctx.r2iKey {
		if b != 0 {
			t.Error("r2iKey should be zeroed")
			break
		}
	}
	for _, b := range ctx.sharedSecret {
		if b != 0 {
			t.Error("sharedSecret should be zeroed")
			break
		}
	}

	// Codecs should be nil
	if ctx.encryptCodec != nil {
		t.Error("encryptCodec should be nil after ZeroizeKeys")
	}
	if ctx.decryptCodec != nil {
		t.Error("decryptCodec should be nil after ZeroizeKeys")
	}
}

func TestSecureContext_EncryptDecrypt_Roundtrip(t *testing.T) {
	// Create initiator and responder contexts with the same keys
	initiator, _ := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: 1,
		PeerSessionID:  2,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
	})

	responder, _ := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleResponder,
		LocalSessionID: 2,
		PeerSessionID:  1,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
	})

	// Test message
	payload := []byte("Hello, Matter!")
	header := &message.MessageHeader{
		SessionType: message.SessionTypeUnicast,
	}
	protocol := &message.ProtocolHeader{
		ProtocolID:     message.ProtocolSecureChannel,
		ProtocolOpcode: 0x20,
		ExchangeID:     100,
	}

	// Initiator encrypts with I2R key
	encrypted, err := initiator.Encrypt(header, protocol, payload, false)
	if err != nil {
		t.Fatalf("Initiator.Encrypt() error = %v", err)
	}

	// Responder decrypts with I2R key
	frame, err := responder.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Responder.Decrypt() error = %v", err)
	}

	if !bytes.Equal(frame.Payload, payload) {
		t.Errorf("Decrypted payload = %q, want %q", frame.Payload, payload)
	}
	if frame.Protocol.ProtocolOpcode != 0x20 {
		t.Errorf("Decrypted opcode = %d, want 0x20", frame.Protocol.ProtocolOpcode)
	}
	if frame.Protocol.ExchangeID != 100 {
		t.Errorf("Decrypted exchangeID = %d, want 100", frame.Protocol.ExchangeID)
	}
}

func TestSecureContext_EncryptDecrypt_ReverseDirection(t *testing.T) {
	// Create initiator and responder contexts
	initiator, _ := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: 1,
		PeerSessionID:  2,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
	})

	responder, _ := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleResponder,
		LocalSessionID: 2,
		PeerSessionID:  1,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
	})

	// Test message from responder to initiator
	payload := []byte("Response from responder")
	header := &message.MessageHeader{
		SessionType: message.SessionTypeUnicast,
	}
	protocol := &message.ProtocolHeader{
		ProtocolID:     message.ProtocolSecureChannel,
		ProtocolOpcode: 0x30,
		ExchangeID:     200,
	}

	// Responder encrypts with R2I key
	encrypted, err := responder.Encrypt(header, protocol, payload, false)
	if err != nil {
		t.Fatalf("Responder.Encrypt() error = %v", err)
	}

	// Initiator decrypts with R2I key
	frame, err := initiator.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Initiator.Decrypt() error = %v", err)
	}

	if !bytes.Equal(frame.Payload, payload) {
		t.Errorf("Decrypted payload = %q, want %q", frame.Payload, payload)
	}
}

func TestSecureContext_Encrypt_SetsHeaderFields(t *testing.T) {
	ctx, _ := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: 100,
		PeerSessionID:  200,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
	})

	header := &message.MessageHeader{}
	protocol := &message.ProtocolHeader{}

	_, err := ctx.Encrypt(header, protocol, []byte("test"), false)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Header should have peer session ID and counter
	if header.SessionID != 200 {
		t.Errorf("header.SessionID = %d, want 200", header.SessionID)
	}
	if header.MessageCounter == 0 {
		t.Error("header.MessageCounter should be non-zero")
	}
}
