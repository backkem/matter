package securechannel

import (
	"testing"

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
	_, err := mgr.Route(1, OpcodeMsgCounterSyncReq, nil)
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
	_, err := mgr.Route(1, OpcodeStatusReport, busyBytes)
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
