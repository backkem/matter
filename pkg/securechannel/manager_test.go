package securechannel

import (
	"testing"

	"github.com/backkem/matter/pkg/securechannel/pase"
	"github.com/backkem/matter/pkg/session"
)

func TestMessagePermitted(t *testing.T) {
	tests := []struct {
		opcode   Opcode
		expected bool
	}{
		// PASE opcodes - permitted
		{OpcodePBKDFParamRequest, true},
		{OpcodePBKDFParamResponse, true},
		{OpcodePASEPake1, true},
		{OpcodePASEPake2, true},
		{OpcodePASEPake3, true},
		// CASE opcodes - permitted
		{OpcodeCASESigma1, true},
		{OpcodeCASESigma2, true},
		{OpcodeCASESigma3, true},
		{OpcodeCASESigma2Resume, true},
		// Other permitted
		{OpcodeStandaloneAck, true},
		{OpcodeStatusReport, true},
		// Not permitted during session establishment
		{OpcodeMsgCounterSyncReq, false},
		{OpcodeMsgCounterSyncResp, false},
		{OpcodeICDCheckIn, false},
		{Opcode(0xFF), false},
	}

	for _, tc := range tests {
		t.Run(tc.opcode.String(), func(t *testing.T) {
			if got := MessagePermitted(tc.opcode); got != tc.expected {
				t.Errorf("MessagePermitted(%s) = %v, want %v", tc.opcode, got, tc.expected)
			}
		})
	}
}

func TestIsPASEOpcode(t *testing.T) {
	tests := []struct {
		opcode   Opcode
		expected bool
	}{
		{OpcodePBKDFParamRequest, true},
		{OpcodePBKDFParamResponse, true},
		{OpcodePASEPake1, true},
		{OpcodePASEPake2, true},
		{OpcodePASEPake3, true},
		{OpcodeCASESigma1, false},
		{OpcodeStatusReport, false},
	}

	for _, tc := range tests {
		t.Run(tc.opcode.String(), func(t *testing.T) {
			if got := IsPASEOpcode(tc.opcode); got != tc.expected {
				t.Errorf("IsPASEOpcode(%s) = %v, want %v", tc.opcode, got, tc.expected)
			}
		})
	}
}

func TestIsCASEOpcode(t *testing.T) {
	tests := []struct {
		opcode   Opcode
		expected bool
	}{
		{OpcodeCASESigma1, true},
		{OpcodeCASESigma2, true},
		{OpcodeCASESigma3, true},
		{OpcodeCASESigma2Resume, true},
		{OpcodePBKDFParamRequest, false},
		{OpcodeStatusReport, false},
	}

	for _, tc := range tests {
		t.Run(tc.opcode.String(), func(t *testing.T) {
			if got := IsCASEOpcode(tc.opcode); got != tc.expected {
				t.Errorf("IsCASEOpcode(%s) = %v, want %v", tc.opcode, got, tc.expected)
			}
		})
	}
}

func TestNewManager(t *testing.T) {
	sessionMgr := session.NewManager(session.ManagerConfig{})

	config := ManagerConfig{
		SessionManager: sessionMgr,
	}

	mgr := NewManager(config)
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}

	if mgr.ActiveHandshakeCount() != 0 {
		t.Errorf("new manager should have 0 active handshakes, got %d", mgr.ActiveHandshakeCount())
	}
}

func TestHandshakeTypeString(t *testing.T) {
	tests := []struct {
		ht       HandshakeType
		expected string
	}{
		{HandshakeTypePASE, "PASE"},
		{HandshakeTypeCASE, "CASE"},
		{HandshakeType(99), "Unknown"},
	}

	for _, tc := range tests {
		if got := tc.ht.String(); got != tc.expected {
			t.Errorf("HandshakeType(%d).String() = %q, want %q", tc.ht, got, tc.expected)
		}
	}
}

func TestRouteInvalidOpcode(t *testing.T) {
	sessionMgr := session.NewManager(session.ManagerConfig{})
	mgr := NewManager(ManagerConfig{SessionManager: sessionMgr})

	// Try to route a non-permitted opcode
	msg := &Message{Opcode: OpcodeMsgCounterSyncReq, Payload: nil}
	_, err := mgr.Route(1, msg)
	if err != ErrInvalidOpcode {
		t.Errorf("Route with invalid opcode should return ErrInvalidOpcode, got %v", err)
	}
}

func TestRouteStatusReport(t *testing.T) {
	sessionMgr := session.NewManager(session.ManagerConfig{})
	var busyCallbackCalled bool
	var busyWaitTime uint16

	mgr := NewManager(ManagerConfig{
		SessionManager: sessionMgr,
		Callbacks: Callbacks{
			OnResponderBusy: func(waitTimeMs uint16) {
				busyCallbackCalled = true
				busyWaitTime = waitTimeMs
			},
		},
	})

	// Create a Busy status report
	busy := Busy(500)
	busyBytes := busy.Encode()

	// Route the status report
	msg := &Message{Opcode: OpcodeStatusReport, Payload: busyBytes}
	_, err := mgr.Route(1, msg)
	if err != nil {
		t.Errorf("Route Busy status should not error, got %v", err)
	}

	if !busyCallbackCalled {
		t.Error("OnResponderBusy callback should have been called")
	}

	if busyWaitTime != 500 {
		t.Errorf("busyWaitTime = %d, want 500", busyWaitTime)
	}
}

func TestHasActiveHandshake(t *testing.T) {
	sessionMgr := session.NewManager(session.ManagerConfig{})
	mgr := NewManager(ManagerConfig{SessionManager: sessionMgr})

	// No active handshake initially
	if mgr.HasActiveHandshake(1) {
		t.Error("should not have active handshake on exchange 1")
	}

	// Start a PASE handshake
	_, err := mgr.StartPASE(1, 20202021)
	if err != nil {
		t.Fatalf("StartPASE failed: %v", err)
	}

	// Now should have active handshake
	if !mgr.HasActiveHandshake(1) {
		t.Error("should have active handshake on exchange 1")
	}

	// Different exchange should not have handshake
	if mgr.HasActiveHandshake(2) {
		t.Error("should not have active handshake on exchange 2")
	}
}

func TestGetHandshakeType(t *testing.T) {
	sessionMgr := session.NewManager(session.ManagerConfig{})
	mgr := NewManager(ManagerConfig{SessionManager: sessionMgr})

	// No handshake initially
	_, ok := mgr.GetHandshakeType(1)
	if ok {
		t.Error("GetHandshakeType should return false for no handshake")
	}

	// Start PASE
	_, err := mgr.StartPASE(1, 20202021)
	if err != nil {
		t.Fatalf("StartPASE failed: %v", err)
	}

	ht, ok := mgr.GetHandshakeType(1)
	if !ok {
		t.Error("GetHandshakeType should return true after StartPASE")
	}
	if ht != HandshakeTypePASE {
		t.Errorf("GetHandshakeType = %v, want PASE", ht)
	}
}

func TestStartPASE(t *testing.T) {
	sessionMgr := session.NewManager(session.ManagerConfig{})
	mgr := NewManager(ManagerConfig{SessionManager: sessionMgr})

	// Start PASE
	pbkdfReq, err := mgr.StartPASE(1, 20202021)
	if err != nil {
		t.Fatalf("StartPASE failed: %v", err)
	}

	if len(pbkdfReq) == 0 {
		t.Error("StartPASE should return non-empty PBKDFParamRequest")
	}

	// Try to start another PASE on same exchange
	_, err = mgr.StartPASE(1, 20202021)
	if err != ErrHandshakeInProgress {
		t.Errorf("second StartPASE on same exchange should return ErrHandshakeInProgress, got %v", err)
	}

	// Can start on different exchange
	_, err = mgr.StartPASE(2, 20202021)
	if err != nil {
		t.Errorf("StartPASE on different exchange should succeed, got %v", err)
	}
}

func TestStartPASE_InvalidPasscode(t *testing.T) {
	sessionMgr := session.NewManager(session.ManagerConfig{})
	mgr := NewManager(ManagerConfig{SessionManager: sessionMgr})

	// Invalid passcodes
	invalidPasscodes := []uint32{
		0,          // too low
		100000000,  // too high
		11111111,   // invalid pattern
		22222222,   // invalid pattern
		12345678,   // invalid pattern
	}

	for _, passcode := range invalidPasscodes {
		_, err := mgr.StartPASE(1, passcode)
		if err == nil {
			t.Errorf("StartPASE with passcode %d should fail", passcode)
		}
	}
}

func TestCleanupExpiredHandshakes(t *testing.T) {
	sessionMgr := session.NewManager(session.ManagerConfig{})
	var errorCalled bool

	mgr := NewManager(ManagerConfig{
		SessionManager: sessionMgr,
		Callbacks: Callbacks{
			OnSessionError: func(err error, stage string) {
				errorCalled = true
			},
		},
	})

	// Start a handshake
	_, err := mgr.StartPASE(1, 20202021)
	if err != nil {
		t.Fatalf("StartPASE failed: %v", err)
	}

	// Cleanup shouldn't remove it yet (not expired)
	mgr.CleanupExpiredHandshakes()
	if !mgr.HasActiveHandshake(1) {
		t.Error("handshake should not be cleaned up yet")
	}

	// Note: To properly test timeout, we'd need to modify startTime
	// This test just verifies the method doesn't panic
	_ = errorCalled
}

func TestActiveHandshakeCount(t *testing.T) {
	sessionMgr := session.NewManager(session.ManagerConfig{})
	mgr := NewManager(ManagerConfig{SessionManager: sessionMgr})

	if mgr.ActiveHandshakeCount() != 0 {
		t.Errorf("ActiveHandshakeCount = %d, want 0", mgr.ActiveHandshakeCount())
	}

	// Start PASE on exchange 1
	_, _ = mgr.StartPASE(1, 20202021)
	if mgr.ActiveHandshakeCount() != 1 {
		t.Errorf("ActiveHandshakeCount = %d, want 1", mgr.ActiveHandshakeCount())
	}

	// Start PASE on exchange 2
	_, _ = mgr.StartPASE(2, 20202021)
	if mgr.ActiveHandshakeCount() != 2 {
		t.Errorf("ActiveHandshakeCount = %d, want 2", mgr.ActiveHandshakeCount())
	}
}

func TestSetPASEResponder(t *testing.T) {
	sessionMgr := session.NewManager(session.ManagerConfig{})
	mgr := NewManager(ManagerConfig{SessionManager: sessionMgr})

	// Initially no PASE responder
	if mgr.HasPASEResponder() {
		t.Error("HasPASEResponder should be false initially")
	}

	// Generate verifier for passcode 20202021
	passcode := uint32(20202021)
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	iterations := uint32(1000)

	verifier, err := pase.GenerateVerifier(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("GenerateVerifier failed: %v", err)
	}

	// Set PASE responder
	err = mgr.SetPASEResponder(verifier, salt, iterations)
	if err != nil {
		t.Fatalf("SetPASEResponder failed: %v", err)
	}

	if !mgr.HasPASEResponder() {
		t.Error("HasPASEResponder should be true after SetPASEResponder")
	}

	// Clear PASE responder
	mgr.ClearPASEResponder()
	if mgr.HasPASEResponder() {
		t.Error("HasPASEResponder should be false after ClearPASEResponder")
	}
}

func TestSetPASEResponder_InvalidParams(t *testing.T) {
	sessionMgr := session.NewManager(session.ManagerConfig{})
	mgr := NewManager(ManagerConfig{SessionManager: sessionMgr})

	salt := make([]byte, 32)
	verifier, _ := pase.GenerateVerifier(20202021, salt, 1000)

	// Nil verifier
	err := mgr.SetPASEResponder(nil, salt, 1000)
	if err == nil {
		t.Error("SetPASEResponder with nil verifier should fail")
	}

	// Salt too short
	err = mgr.SetPASEResponder(verifier, make([]byte, 8), 1000)
	if err == nil {
		t.Error("SetPASEResponder with short salt should fail")
	}

	// Iterations too low
	err = mgr.SetPASEResponder(verifier, salt, 100)
	if err == nil {
		t.Error("SetPASEResponder with low iterations should fail")
	}
}

// TestPASEHandshake tests a full PASE handshake between initiator and responder managers.
func TestPASEHandshake(t *testing.T) {
	// Shared passcode and PBKDF parameters
	passcode := uint32(20202021)
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	iterations := uint32(1000)

	// Generate verifier
	verifier, err := pase.GenerateVerifier(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("GenerateVerifier failed: %v", err)
	}

	// Create initiator manager (controller)
	initiatorSessionMgr := session.NewManager(session.ManagerConfig{})
	var initiatorSessionEstablished bool
	initiatorMgr := NewManager(ManagerConfig{
		SessionManager: initiatorSessionMgr,
		Callbacks: Callbacks{
			OnSessionEstablished: func(ctx *session.SecureContext) {
				initiatorSessionEstablished = true
				t.Logf("Initiator: session established, localID=%d", ctx.LocalSessionID())
			},
			OnSessionError: func(err error, stage string) {
				t.Logf("Initiator error at %s: %v", stage, err)
			},
		},
	})

	// Create responder manager (device)
	responderSessionMgr := session.NewManager(session.ManagerConfig{})
	var responderSessionEstablished bool
	responderMgr := NewManager(ManagerConfig{
		SessionManager: responderSessionMgr,
		Callbacks: Callbacks{
			OnSessionEstablished: func(ctx *session.SecureContext) {
				responderSessionEstablished = true
				t.Logf("Responder: session established, localID=%d", ctx.LocalSessionID())
			},
			OnSessionError: func(err error, stage string) {
				t.Logf("Responder error at %s: %v", stage, err)
			},
		},
	})

	// Configure responder with PASE verifier
	err = responderMgr.SetPASEResponder(verifier, salt, iterations)
	if err != nil {
		t.Fatalf("SetPASEResponder failed: %v", err)
	}

	exchangeID := uint16(1)

	// Step 1: Initiator starts PASE (PBKDFParamRequest)
	pbkdfReq, err := initiatorMgr.StartPASE(exchangeID, passcode)
	if err != nil {
		t.Fatalf("StartPASE failed: %v", err)
	}
	t.Logf("Step 1: PBKDFParamRequest (%d bytes)", len(pbkdfReq))

	// Step 2: Responder handles PBKDFParamRequest -> PBKDFParamResponse
	pbkdfResp, err := responderMgr.Route(exchangeID, &Message{Opcode: OpcodePBKDFParamRequest, Payload: pbkdfReq})
	if err != nil {
		t.Fatalf("Route PBKDFParamRequest failed: %v", err)
	}
	t.Logf("Step 2: PBKDFParamResponse (%d bytes)", len(pbkdfResp.Payload))

	// Step 3: Initiator handles PBKDFParamResponse -> Pake1
	pake1, err := initiatorMgr.Route(exchangeID, pbkdfResp)
	if err != nil {
		t.Fatalf("Route PBKDFParamResponse failed: %v", err)
	}
	t.Logf("Step 3: Pake1 (%d bytes)", len(pake1.Payload))

	// Step 4: Responder handles Pake1 -> Pake2
	pake2, err := responderMgr.Route(exchangeID, pake1)
	if err != nil {
		t.Fatalf("Route Pake1 failed: %v", err)
	}
	t.Logf("Step 4: Pake2 (%d bytes)", len(pake2.Payload))

	// Step 5: Initiator handles Pake2 -> Pake3
	pake3, err := initiatorMgr.Route(exchangeID, pake2)
	if err != nil {
		t.Fatalf("Route Pake2 failed: %v", err)
	}
	t.Logf("Step 5: Pake3 (%d bytes)", len(pake3.Payload))

	// Step 6: Responder handles Pake3 -> StatusReport (success)
	statusReport, err := responderMgr.Route(exchangeID, pake3)
	if err != nil {
		t.Fatalf("Route Pake3 failed: %v", err)
	}
	t.Logf("Step 6: StatusReport (%d bytes)", len(statusReport.Payload))

	// Responder should have established session by now
	if !responderSessionEstablished {
		t.Error("Responder session should be established after Pake3")
	}

	// Step 7: Initiator handles StatusReport -> complete
	_, err = initiatorMgr.Route(exchangeID, statusReport)
	if err != nil {
		t.Fatalf("Route StatusReport failed: %v", err)
	}

	// Initiator should have established session
	if !initiatorSessionEstablished {
		t.Error("Initiator session should be established after StatusReport")
	}

	// Verify both session managers have secure contexts
	if initiatorSessionMgr.SecureSessionCount() != 1 {
		t.Errorf("Initiator should have 1 secure session, got %d", initiatorSessionMgr.SecureSessionCount())
	}
	if responderSessionMgr.SecureSessionCount() != 1 {
		t.Errorf("Responder should have 1 secure session, got %d", responderSessionMgr.SecureSessionCount())
	}

	// Verify peer session IDs are correctly set (cross-matched)
	var initiatorSession, responderSession *session.SecureContext
	initiatorSessionMgr.ForEachSecureSession(func(s *session.SecureContext) bool {
		initiatorSession = s
		return false
	})
	responderSessionMgr.ForEachSecureSession(func(s *session.SecureContext) bool {
		responderSession = s
		return false
	})

	if initiatorSession == nil || responderSession == nil {
		t.Fatal("Failed to get sessions")
	}

	// Initiator's peerSessionID should match responder's localSessionID
	if initiatorSession.PeerSessionID() != responderSession.LocalSessionID() {
		t.Errorf("Initiator peerSessionID (%d) should match responder localSessionID (%d)",
			initiatorSession.PeerSessionID(), responderSession.LocalSessionID())
	}

	// Responder's peerSessionID should match initiator's localSessionID
	if responderSession.PeerSessionID() != initiatorSession.LocalSessionID() {
		t.Errorf("Responder peerSessionID (%d) should match initiator localSessionID (%d)",
			responderSession.PeerSessionID(), initiatorSession.LocalSessionID())
	}

	// Verify peerSessionID is not 0 for the initiator (this was the bug we fixed)
	if initiatorSession.PeerSessionID() == 0 {
		t.Error("Initiator peerSessionID should not be 0")
	}

	t.Logf("Session IDs: initiator local=%d peer=%d, responder local=%d peer=%d",
		initiatorSession.LocalSessionID(), initiatorSession.PeerSessionID(),
		responderSession.LocalSessionID(), responderSession.PeerSessionID())

	t.Log("PASE handshake completed successfully!")
}
