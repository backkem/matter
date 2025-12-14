package securechannel

import (
	"testing"

	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/session"
)

func TestUnsolicitedHandler_HandleStatusReport(t *testing.T) {
	sessionMgr := session.NewManager(session.ManagerConfig{})

	// Create a secure context
	ctx, err := session.NewSecureContext(session.SecureContextConfig{
		SessionType:    session.SessionTypePASE,
		Role:           session.SessionRoleInitiator,
		LocalSessionID: 1,
		PeerSessionID:  2,
		I2RKey:         make([]byte, 16),
		R2IKey:         make([]byte, 16),
	})
	if err != nil {
		t.Fatalf("failed to create secure context: %v", err)
	}

	err = sessionMgr.AddSecureContext(ctx)
	if err != nil {
		t.Fatalf("failed to add secure context: %v", err)
	}

	var closedSessionID uint16
	callbacks := Callbacks{
		OnSessionClosed: func(localSessionID uint16) {
			closedSessionID = localSessionID
		},
	}

	handler := NewUnsolicitedHandler(sessionMgr, callbacks)

	// Test CloseSession handling
	closeStatus := CloseSession()
	handled := handler.HandleStatusReport(1, closeStatus)

	if !handled {
		t.Error("CloseSession should be handled")
	}

	if closedSessionID != 1 {
		t.Errorf("closedSessionID = %d, want 1", closedSessionID)
	}

	// Session should be removed
	if sessionMgr.FindSecureContext(1) != nil {
		t.Error("session should be removed after CloseSession")
	}
}

func TestUnsolicitedHandler_HandleBusy(t *testing.T) {
	sessionMgr := session.NewManager(session.ManagerConfig{})

	var busyWaitTime uint16
	callbacks := Callbacks{
		OnResponderBusy: func(waitTimeMs uint16) {
			busyWaitTime = waitTimeMs
		},
	}

	handler := NewUnsolicitedHandler(sessionMgr, callbacks)

	// Test Busy handling
	busyStatus := Busy(1000)
	handled := handler.HandleStatusReport(1, busyStatus)

	if !handled {
		t.Error("Busy status should be handled")
	}

	if busyWaitTime != 1000 {
		t.Errorf("busyWaitTime = %d, want 1000", busyWaitTime)
	}
}

func TestUnsolicitedHandler_NonSecureChannelStatus(t *testing.T) {
	sessionMgr := session.NewManager(session.ManagerConfig{})
	handler := NewUnsolicitedHandler(sessionMgr, Callbacks{})

	// Create a non-secure-channel status report
	status := NewStatusReport(GeneralCodeSuccess, 0x00010000, 0x0001) // IM protocol
	handled := handler.HandleStatusReport(1, status)

	if handled {
		t.Error("non-secure-channel status should not be handled")
	}
}

func TestIsCloseSession(t *testing.T) {
	tests := []struct {
		name     string
		status   *StatusReport
		expected bool
	}{
		{
			name:     "CloseSession",
			status:   CloseSession(),
			expected: true,
		},
		{
			name:     "Success but not CloseSession",
			status:   Success(),
			expected: false,
		},
		{
			name:     "Busy",
			status:   Busy(500),
			expected: false,
		},
		{
			name:     "InvalidParam",
			status:   InvalidParam(),
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsCloseSession(tc.status); got != tc.expected {
				t.Errorf("IsCloseSession() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestIsBusyStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   *StatusReport
		expected bool
	}{
		{
			name:     "Busy",
			status:   Busy(500),
			expected: true,
		},
		{
			name:     "CloseSession",
			status:   CloseSession(),
			expected: false,
		},
		{
			name:     "Success",
			status:   Success(),
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsBusyStatus(tc.status); got != tc.expected {
				t.Errorf("IsBusyStatus() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestSendCloseSession(t *testing.T) {
	data := SendCloseSession()
	if len(data) < StatusReportMinSize {
		t.Errorf("SendCloseSession returned %d bytes, want at least %d", len(data), StatusReportMinSize)
	}

	// Decode and verify
	status, err := DecodeStatusReport(data)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if !IsCloseSession(status) {
		t.Error("decoded status should be CloseSession")
	}
}

func TestSendBusy(t *testing.T) {
	data := SendBusy(1234)
	if len(data) < StatusReportMinSize {
		t.Errorf("SendBusy returned %d bytes, want at least %d", len(data), StatusReportMinSize)
	}

	// Decode and verify
	status, err := DecodeStatusReport(data)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if !IsBusyStatus(status) {
		t.Error("decoded status should be Busy")
	}

	if status.BusyWaitTime() != 1234 {
		t.Errorf("BusyWaitTime = %d, want 1234", status.BusyWaitTime())
	}
}

func TestNoSharedTrustRoots(t *testing.T) {
	status := NoSharedTrustRoots()

	if status.GeneralCode != GeneralCodeFailure {
		t.Errorf("GeneralCode = %v, want FAILURE", status.GeneralCode)
	}

	if status.SecureChannelCode() != ProtocolCodeNoSharedRoot {
		t.Errorf("ProtocolCode = %v, want NO_SHARED_TRUST_ROOTS", status.SecureChannelCode())
	}
}

func TestSessionNotFound(t *testing.T) {
	status := SessionNotFound()

	if status.GeneralCode != GeneralCodeFailure {
		t.Errorf("GeneralCode = %v, want FAILURE", status.GeneralCode)
	}

	if status.SecureChannelCode() != ProtocolCodeSessionNotFound {
		t.Errorf("ProtocolCode = %v, want SESSION_NOT_FOUND", status.SecureChannelCode())
	}
}

func TestUnsolicitedHandler_CloseSession_SessionNotFound(t *testing.T) {
	sessionMgr := session.NewManager(session.ManagerConfig{})

	var closedSessionID uint16
	var callbackCalled bool
	callbacks := Callbacks{
		OnSessionClosed: func(localSessionID uint16) {
			callbackCalled = true
			closedSessionID = localSessionID
		},
	}

	handler := NewUnsolicitedHandler(sessionMgr, callbacks)

	// Send CloseSession for non-existent session
	closeStatus := CloseSession()
	handled := handler.HandleStatusReport(999, closeStatus)

	// Should still be handled (just does nothing)
	if !handled {
		t.Error("CloseSession should be handled even for non-existent session")
	}

	// Callback should NOT be called since session wasn't found
	if callbackCalled {
		t.Error("callback should not be called for non-existent session")
	}

	_ = closedSessionID
}

func TestUnsolicitedHandler_CloseSession_CASE(t *testing.T) {
	sessionMgr := session.NewManager(session.ManagerConfig{})

	// Create a CASE secure context with fabric info
	ctx, err := session.NewSecureContext(session.SecureContextConfig{
		SessionType:    session.SessionTypeCASE,
		Role:           session.SessionRoleInitiator,
		LocalSessionID: 42,
		PeerSessionID:  43,
		I2RKey:         make([]byte, 16),
		R2IKey:         make([]byte, 16),
		FabricIndex:    1,
		PeerNodeID:     fabric.NodeID(12345),
		LocalNodeID:    fabric.NodeID(67890),
	})
	if err != nil {
		t.Fatalf("failed to create secure context: %v", err)
	}

	err = sessionMgr.AddSecureContext(ctx)
	if err != nil {
		t.Fatalf("failed to add secure context: %v", err)
	}

	var closedSessionID uint16
	callbacks := Callbacks{
		OnSessionClosed: func(localSessionID uint16) {
			closedSessionID = localSessionID
		},
	}

	handler := NewUnsolicitedHandler(sessionMgr, callbacks)

	// Send CloseSession
	closeStatus := CloseSession()
	handled := handler.HandleStatusReport(42, closeStatus)

	if !handled {
		t.Error("CloseSession should be handled")
	}

	if closedSessionID != 42 {
		t.Errorf("closedSessionID = %d, want 42", closedSessionID)
	}

	// Session should be removed
	if sessionMgr.FindSecureContext(42) != nil {
		t.Error("CASE session should be removed after CloseSession")
	}
}
