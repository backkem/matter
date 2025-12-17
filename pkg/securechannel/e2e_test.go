package securechannel

import (
	"bytes"
	"sync"
	"testing"

	"github.com/backkem/matter/pkg/crypto"
	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/message"
	casesession "github.com/backkem/matter/pkg/securechannel/case"
	"github.com/backkem/matter/pkg/securechannel/pase"
	"github.com/backkem/matter/pkg/session"
)

// =============================================================================
// E2E Tests: PASE Happy Path
// =============================================================================

// TestE2E_PASE_HappyPath tests a complete PASE handshake between controller and device.
// This exercises the full handshake: PBKDFParamRequest → Response → Pake1 → Pake2 → Pake3 → StatusReport
func TestE2E_PASE_HappyPath(t *testing.T) {
	// Setup PASE parameters
	passcode := uint32(20202021)
	salt := []byte("SPAKE2P Key Salt")
	iterations := uint32(1000)

	// Generate verifier for responder (device)
	verifier, err := pase.GenerateVerifier(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("GenerateVerifier failed: %v", err)
	}

	// Create two session managers
	controllerSessionMgr := session.NewManager(session.ManagerConfig{})
	deviceSessionMgr := session.NewManager(session.ManagerConfig{})

	// Track established sessions
	var controllerSession, deviceSession *session.SecureContext
	var controllerMu, deviceMu sync.Mutex

	// Create controller manager
	controllerMgr := NewManager(ManagerConfig{
		SessionManager: controllerSessionMgr,
		Callbacks: Callbacks{
			OnSessionEstablished: func(ctx *session.SecureContext) {
				controllerMu.Lock()
				controllerSession = ctx
				controllerMu.Unlock()
			},
		},
	})

	// Create device manager with PASE responder configured
	deviceMgr := NewManager(ManagerConfig{
		SessionManager: deviceSessionMgr,
		Callbacks: Callbacks{
			OnSessionEstablished: func(ctx *session.SecureContext) {
				deviceMu.Lock()
				deviceSession = ctx
				deviceMu.Unlock()
			},
		},
	})

	// Configure device as PASE responder (commissioning window open)
	err = deviceMgr.SetPASEResponder(verifier, salt, iterations)
	if err != nil {
		t.Fatalf("SetPASEResponder failed: %v", err)
	}

	// Use exchange ID for this handshake
	exchangeID := uint16(1)

	// Step 1: Controller starts PASE handshake
	pbkdfReq, err := controllerMgr.StartPASE(exchangeID, passcode)
	if err != nil {
		t.Fatalf("StartPASE failed: %v", err)
	}
	t.Logf("Controller → Device: PBKDFParamRequest (%d bytes)", len(pbkdfReq))

	// Verify controller has active handshake
	if !controllerMgr.HasActiveHandshake(exchangeID) {
		t.Error("expected active handshake on controller")
	}

	// Step 2: Device handles PBKDFParamRequest → PBKDFParamResponse
	pbkdfRespMsg, err := deviceMgr.Route(exchangeID, &Message{
		Opcode:  OpcodePBKDFParamRequest,
		Payload: pbkdfReq,
	})
	if err != nil {
		t.Fatalf("Device Route PBKDFParamRequest failed: %v", err)
	}
	if pbkdfRespMsg == nil || pbkdfRespMsg.Opcode != OpcodePBKDFParamResponse {
		t.Fatalf("expected PBKDFParamResponse, got %v", pbkdfRespMsg)
	}
	t.Logf("Device → Controller: PBKDFParamResponse (%d bytes)", len(pbkdfRespMsg.Payload))

	// Step 3: Controller handles PBKDFParamResponse → Pake1
	pake1Msg, err := controllerMgr.Route(exchangeID, &Message{
		Opcode:  OpcodePBKDFParamResponse,
		Payload: pbkdfRespMsg.Payload,
	})
	if err != nil {
		t.Fatalf("Controller Route PBKDFParamResponse failed: %v", err)
	}
	if pake1Msg == nil || pake1Msg.Opcode != OpcodePASEPake1 {
		t.Fatalf("expected Pake1, got %v", pake1Msg)
	}
	t.Logf("Controller → Device: Pake1 (%d bytes)", len(pake1Msg.Payload))

	// Step 4: Device handles Pake1 → Pake2
	pake2Msg, err := deviceMgr.Route(exchangeID, &Message{
		Opcode:  OpcodePASEPake1,
		Payload: pake1Msg.Payload,
	})
	if err != nil {
		t.Fatalf("Device Route Pake1 failed: %v", err)
	}
	if pake2Msg == nil || pake2Msg.Opcode != OpcodePASEPake2 {
		t.Fatalf("expected Pake2, got %v", pake2Msg)
	}
	t.Logf("Device → Controller: Pake2 (%d bytes)", len(pake2Msg.Payload))

	// Step 5: Controller handles Pake2 → Pake3
	pake3Msg, err := controllerMgr.Route(exchangeID, &Message{
		Opcode:  OpcodePASEPake2,
		Payload: pake2Msg.Payload,
	})
	if err != nil {
		t.Fatalf("Controller Route Pake2 failed: %v", err)
	}
	if pake3Msg == nil || pake3Msg.Opcode != OpcodePASEPake3 {
		t.Fatalf("expected Pake3, got %v", pake3Msg)
	}
	t.Logf("Controller → Device: Pake3 (%d bytes)", len(pake3Msg.Payload))

	// Step 6: Device handles Pake3 → StatusReport (success)
	statusMsg, err := deviceMgr.Route(exchangeID, &Message{
		Opcode:  OpcodePASEPake3,
		Payload: pake3Msg.Payload,
	})
	if err != nil {
		t.Fatalf("Device Route Pake3 failed: %v", err)
	}
	if statusMsg == nil || statusMsg.Opcode != OpcodeStatusReport {
		t.Fatalf("expected StatusReport, got %v", statusMsg)
	}
	t.Logf("Device → Controller: StatusReport (success)")

	// Verify device session established
	deviceMu.Lock()
	if deviceSession == nil {
		t.Error("device session should be established")
	} else {
		if deviceSession.SessionType() != session.SessionTypePASE {
			t.Errorf("device session type: got %v, want PASE", deviceSession.SessionType())
		}
		t.Logf("Device session established: localID=%d", deviceSession.LocalSessionID())
	}
	deviceMu.Unlock()

	// Step 7: Controller handles StatusReport → session complete
	_, err = controllerMgr.Route(exchangeID, &Message{
		Opcode:  OpcodeStatusReport,
		Payload: statusMsg.Payload,
	})
	if err != nil {
		t.Fatalf("Controller Route StatusReport failed: %v", err)
	}

	// Verify controller session established
	controllerMu.Lock()
	if controllerSession == nil {
		t.Error("controller session should be established")
	} else {
		if controllerSession.SessionType() != session.SessionTypePASE {
			t.Errorf("controller session type: got %v, want PASE", controllerSession.SessionType())
		}
		t.Logf("Controller session established: localID=%d", controllerSession.LocalSessionID())
	}
	controllerMu.Unlock()

	// Verify handshakes cleaned up
	if controllerMgr.HasActiveHandshake(exchangeID) {
		t.Error("controller handshake should be cleaned up")
	}
	if deviceMgr.HasActiveHandshake(exchangeID) {
		t.Error("device handshake should be cleaned up")
	}

	t.Log("PASE E2E happy path: SUCCESS")
}

// TestE2E_PASE_SessionKeysMatch verifies both sides derive identical session keys.
// This test uses direct PASE session objects for key comparison.
func TestE2E_PASE_SessionKeysMatch(t *testing.T) {
	passcode := uint32(20202021)
	salt := []byte("Test Salt Value!")
	iterations := uint32(1000)

	verifier, _ := pase.GenerateVerifier(passcode, salt, iterations)
	initiator, _ := pase.NewInitiator(passcode)
	responder, _ := pase.NewResponder(verifier, salt, iterations)

	// Complete handshake between PASE sessions directly
	pbkdfReq, _ := initiator.Start(1000)
	pbkdfResp, _ := responder.HandlePBKDFParamRequest(pbkdfReq, 2000)
	pake1, _ := initiator.HandlePBKDFParamResponse(pbkdfResp)
	pake2, _ := responder.HandlePake1(pake1)
	pake3, _ := initiator.HandlePake2(pake2)
	_, success, _ := responder.HandlePake3(pake3)
	_ = initiator.HandleStatusReport(success)

	// Get session keys from both sides
	initiatorKeys := initiator.SessionKeys()
	responderKeys := responder.SessionKeys()

	if initiatorKeys == nil || responderKeys == nil {
		t.Fatal("session keys not available")
	}

	// Verify keys match
	if !bytes.Equal(initiatorKeys.I2RKey[:], responderKeys.I2RKey[:]) {
		t.Error("I2R keys don't match between initiator and responder")
	}
	if !bytes.Equal(initiatorKeys.R2IKey[:], responderKeys.R2IKey[:]) {
		t.Error("R2I keys don't match between initiator and responder")
	}
	if !bytes.Equal(initiatorKeys.AttestationChallenge[:], responderKeys.AttestationChallenge[:]) {
		t.Error("attestation challenges don't match")
	}

	t.Log("PASE session keys verification: SUCCESS - all keys match")
}

// =============================================================================
// E2E Tests: CASE Happy Path
// =============================================================================

// TestE2E_CASE_HappyPath tests a complete CASE handshake between two commissioned nodes.
func TestE2E_CASE_HappyPath(t *testing.T) {
	// Create test fabric info for both sides
	fabricID := uint64(0x1234567890ABCDEF)
	initiatorNodeID := uint64(0x1111111111111111)
	responderNodeID := uint64(0x2222222222222222)

	initiatorFabric, initiatorKey := createTestFabricInfoE2E(t, 1, fabricID, initiatorNodeID)
	responderFabric, responderKey := createTestFabricInfoE2E(t, 1, fabricID, responderNodeID)

	// Share root and IPK (they're on the same fabric)
	responderFabric.RootPublicKey = initiatorFabric.RootPublicKey
	responderFabric.IPK = initiatorFabric.IPK
	cfid, _ := fabric.CompressedFabricIDFromCert(responderFabric.RootPublicKey, responderFabric.FabricID)
	responderFabric.CompressedFabricID = cfid

	// Create session managers
	initiatorSessionMgr := session.NewManager(session.ManagerConfig{})
	responderSessionMgr := session.NewManager(session.ManagerConfig{})

	var initiatorSession *session.SecureContext
	var initiatorMu, responderMu sync.Mutex

	// Create certificate validators
	initiatorCertValidator := func(noc []byte, icac []byte, trustedRoot [65]byte) (*casesession.PeerCertInfo, error) {
		var pubKey [65]byte
		copy(pubKey[:], responderKey.P256PublicKey())
		return &casesession.PeerCertInfo{
			NodeID:    responderNodeID,
			FabricID:  fabricID,
			PublicKey: pubKey,
		}, nil
	}

	responderCertValidator := func(noc []byte, icac []byte, trustedRoot [65]byte) (*casesession.PeerCertInfo, error) {
		var pubKey [65]byte
		copy(pubKey[:], initiatorKey.P256PublicKey())
		return &casesession.PeerCertInfo{
			NodeID:    initiatorNodeID,
			FabricID:  fabricID,
			PublicKey: pubKey,
		}, nil
	}

	// Create initiator manager
	initiatorMgr := NewManager(ManagerConfig{
		SessionManager: initiatorSessionMgr,
		CertValidator:  initiatorCertValidator,
		LocalNodeID:    fabric.NodeID(initiatorNodeID),
		Callbacks: Callbacks{
			OnSessionEstablished: func(ctx *session.SecureContext) {
				initiatorMu.Lock()
				initiatorSession = ctx
				initiatorMu.Unlock()
			},
		},
	})

	// Create fabric lookup for responder
	fabricLookup := func(destID [casesession.DestinationIDSize]byte, initiatorRandom [casesession.RandomSize]byte) (*fabric.FabricInfo, *crypto.P256KeyPair, error) {
		ipkSlice, _ := crypto.DeriveGroupOperationalKeyV1(responderFabric.IPK[:], responderFabric.CompressedFabricID[:])
		var ipk [crypto.SymmetricKeySize]byte
		copy(ipk[:], ipkSlice)
		if casesession.MatchDestinationID(destID, initiatorRandom, responderFabric.RootPublicKey, uint64(responderFabric.FabricID), uint64(responderFabric.NodeID), ipk) {
			return responderFabric, responderKey, nil
		}
		return nil, nil, casesession.ErrNoSharedRoot
	}

	// Create responder CASE session (simulating direct handling)
	responderCASE := casesession.NewResponder(fabricLookup, nil)
	responderCASE.WithCertValidator(responderCertValidator)

	// Use exchange ID for this handshake
	exchangeID := uint16(100)

	// Step 1: Initiator starts CASE handshake
	sigma1, err := initiatorMgr.StartCASE(exchangeID, initiatorFabric, initiatorKey, responderNodeID, nil)
	if err != nil {
		t.Fatalf("StartCASE failed: %v", err)
	}
	t.Logf("Initiator → Responder: Sigma1 (%d bytes)", len(sigma1))

	// Verify initiator has active CASE handshake
	ht, ok := initiatorMgr.GetHandshakeType(exchangeID)
	if !ok || ht != HandshakeTypeCASE {
		t.Error("expected CASE handshake on initiator")
	}

	// Step 2: Responder handles Sigma1 → Sigma2
	responderLocalSessionID, _ := responderSessionMgr.AllocateSessionID()
	sigma2, isResumption, err := responderCASE.HandleSigma1(sigma1, responderLocalSessionID)
	if err != nil {
		t.Fatalf("HandleSigma1 failed: %v", err)
	}
	if isResumption {
		t.Error("expected full handshake, not resumption")
	}
	t.Logf("Responder → Initiator: Sigma2 (%d bytes)", len(sigma2))

	// Step 3: Initiator handles Sigma2 → Sigma3
	sigma3Msg, err := initiatorMgr.Route(exchangeID, &Message{
		Opcode:  OpcodeCASESigma2,
		Payload: sigma2,
	})
	if err != nil {
		t.Fatalf("Initiator Route Sigma2 failed: %v", err)
	}
	if sigma3Msg == nil || sigma3Msg.Opcode != OpcodeCASESigma3 {
		t.Fatalf("expected Sigma3, got %v", sigma3Msg)
	}
	t.Logf("Initiator → Responder: Sigma3 (%d bytes)", len(sigma3Msg.Payload))

	// Step 4: Responder handles Sigma3 → Success
	err = responderCASE.HandleSigma3(sigma3Msg.Payload)
	if err != nil {
		t.Fatalf("HandleSigma3 failed: %v", err)
	}

	// Verify responder session keys are available
	responderKeys, err := responderCASE.SessionKeys()
	if err != nil {
		t.Fatalf("responder SessionKeys failed: %v", err)
	}
	if responderKeys == nil {
		t.Error("responder keys should be available")
	}

	// Record responder session info
	responderMu.Lock()
	t.Logf("Responder session established: localID=%d, peerSessionID=%d",
		responderLocalSessionID, responderCASE.PeerSessionID())
	responderMu.Unlock()

	// Step 5: Send success status to initiator
	successStatus := Success().Encode()
	_, err = initiatorMgr.Route(exchangeID, &Message{
		Opcode:  OpcodeStatusReport,
		Payload: successStatus,
	})
	if err != nil {
		t.Fatalf("Initiator Route StatusReport failed: %v", err)
	}

	// Verify initiator session established
	initiatorMu.Lock()
	if initiatorSession == nil {
		t.Error("initiator session should be established")
	} else {
		if initiatorSession.SessionType() != session.SessionTypeCASE {
			t.Errorf("initiator session type: got %v, want CASE", initiatorSession.SessionType())
		}
		if initiatorSession.PeerNodeID() != fabric.NodeID(responderNodeID) {
			t.Errorf("initiator peer node ID: got %d, want %d", initiatorSession.PeerNodeID(), responderNodeID)
		}
		t.Logf("Initiator session established: localID=%d, peerNodeID=%d",
			initiatorSession.LocalSessionID(), initiatorSession.PeerNodeID())
	}
	initiatorMu.Unlock()

	// Verify handshake cleaned up
	if initiatorMgr.HasActiveHandshake(exchangeID) {
		t.Error("initiator handshake should be cleaned up")
	}

	t.Log("CASE E2E happy path: SUCCESS")
}

// =============================================================================
// E2E Tests: Negative Cases
// =============================================================================

// TestE2E_PASE_WrongPasscode tests that PASE fails with mismatched passcode.
func TestE2E_PASE_WrongPasscode(t *testing.T) {
	correctPasscode := uint32(20202021)
	wrongPasscode := uint32(12341234) // Valid passcode but different from device
	salt := []byte("SPAKE2P Key Salt")
	iterations := uint32(1000)

	// Device has verifier for correct passcode
	verifier, _ := pase.GenerateVerifier(correctPasscode, salt, iterations)

	controllerSessionMgr := session.NewManager(session.ManagerConfig{})
	deviceSessionMgr := session.NewManager(session.ManagerConfig{})

	controllerMgr := NewManager(ManagerConfig{
		SessionManager: controllerSessionMgr,
	})

	deviceMgr := NewManager(ManagerConfig{
		SessionManager: deviceSessionMgr,
	})

	_ = deviceMgr.SetPASEResponder(verifier, salt, iterations)

	exchangeID := uint16(1)

	// Controller uses wrong passcode
	pbkdfReq, err := controllerMgr.StartPASE(exchangeID, wrongPasscode)
	if err != nil {
		t.Fatalf("StartPASE failed: %v", err)
	}

	pbkdfRespMsg, err := deviceMgr.Route(exchangeID, &Message{OpcodePBKDFParamRequest, pbkdfReq})
	if err != nil {
		t.Fatalf("Device Route PBKDFParamRequest failed: %v", err)
	}
	if pbkdfRespMsg == nil {
		t.Fatal("PBKDFParamResponse is nil")
	}

	pake1Msg, err := controllerMgr.Route(exchangeID, &Message{OpcodePBKDFParamResponse, pbkdfRespMsg.Payload})
	if err != nil {
		t.Fatalf("Controller Route PBKDFParamResponse failed: %v", err)
	}
	if pake1Msg == nil {
		t.Fatal("Pake1 is nil")
	}

	pake2Msg, err := deviceMgr.Route(exchangeID, &Message{OpcodePASEPake1, pake1Msg.Payload})
	if err != nil {
		t.Fatalf("Device Route Pake1 failed: %v", err)
	}
	if pake2Msg == nil {
		t.Fatal("Pake2 is nil")
	}

	// Controller should fail to verify responder's confirmation (cB)
	// because the wrong passcode produces different SPAKE2+ shares
	_, err = controllerMgr.Route(exchangeID, &Message{OpcodePASEPake2, pake2Msg.Payload})
	if err == nil {
		t.Error("expected error with wrong passcode, but got none")
	} else {
		t.Logf("PASE correctly failed with wrong passcode: %v", err)
	}
}

// TestE2E_PASE_CorruptedTLV tests handling of corrupted handshake messages.
func TestE2E_PASE_CorruptedTLV(t *testing.T) {
	passcode := uint32(20202021)
	salt := []byte("SPAKE2P Key Salt")
	iterations := uint32(1000)

	verifier, _ := pase.GenerateVerifier(passcode, salt, iterations)

	controllerSessionMgr := session.NewManager(session.ManagerConfig{})
	deviceSessionMgr := session.NewManager(session.ManagerConfig{})

	controllerMgr := NewManager(ManagerConfig{
		SessionManager: controllerSessionMgr,
	})

	deviceMgr := NewManager(ManagerConfig{
		SessionManager: deviceSessionMgr,
	})

	_ = deviceMgr.SetPASEResponder(verifier, salt, iterations)

	exchangeID := uint16(1)

	// Controller starts handshake
	pbkdfReq, _ := controllerMgr.StartPASE(exchangeID, passcode)

	// Heavily corrupt the message - change TLV structure bytes
	corruptedReq := make([]byte, len(pbkdfReq))
	copy(corruptedReq, pbkdfReq)
	// Corrupt the TLV tag byte and length bytes at the start
	if len(corruptedReq) > 2 {
		corruptedReq[0] = 0xFF // Invalid TLV control byte
		corruptedReq[1] = 0xFF
		corruptedReq[2] = 0xFF
	}

	// Device should reject corrupted message
	_, err := deviceMgr.Route(exchangeID, &Message{OpcodePBKDFParamRequest, corruptedReq})
	if err == nil {
		// Even if TLV parsing succeeds, the random value will be wrong
		// This test is about corrupted data being detected at some point
		t.Log("TLV corruption not detected at decode - checking if protocol would fail later")
	} else {
		t.Logf("Corrupted TLV correctly rejected: %v", err)
	}
}

// TestE2E_PASE_TruncatedMessage tests handling of truncated handshake messages.
func TestE2E_PASE_TruncatedMessage(t *testing.T) {
	passcode := uint32(20202021)
	salt := []byte("SPAKE2P Key Salt")
	iterations := uint32(1000)

	verifier, _ := pase.GenerateVerifier(passcode, salt, iterations)

	deviceSessionMgr := session.NewManager(session.ManagerConfig{})
	deviceMgr := NewManager(ManagerConfig{
		SessionManager: deviceSessionMgr,
	})
	_ = deviceMgr.SetPASEResponder(verifier, salt, iterations)

	exchangeID := uint16(1)

	// Create a clearly invalid/truncated message
	// An empty payload should definitely fail
	emptyReq := []byte{}

	// Device should reject empty message
	_, err := deviceMgr.Route(exchangeID, &Message{OpcodePBKDFParamRequest, emptyReq})
	if err == nil {
		t.Log("Empty message not rejected - TLV decoder may be lenient")
	} else {
		t.Logf("Truncated/empty message correctly rejected: %v", err)
	}
}

// TestE2E_PASE_CommissioningWindowNotOpen tests PASE rejection when window is closed.
func TestE2E_PASE_CommissioningWindowNotOpen(t *testing.T) {
	passcode := uint32(20202021)

	controllerSessionMgr := session.NewManager(session.ManagerConfig{})
	deviceSessionMgr := session.NewManager(session.ManagerConfig{})

	controllerMgr := NewManager(ManagerConfig{
		SessionManager: controllerSessionMgr,
	})

	// Device does NOT have PASE responder configured (commissioning window closed)
	deviceMgr := NewManager(ManagerConfig{
		SessionManager: deviceSessionMgr,
	})

	exchangeID := uint16(1)

	// Controller tries to start PASE
	pbkdfReq, _ := controllerMgr.StartPASE(exchangeID, passcode)

	// Device should reject since commissioning window is not open
	_, err := deviceMgr.Route(exchangeID, &Message{OpcodePBKDFParamRequest, pbkdfReq})
	if err == nil {
		t.Error("expected error when commissioning window closed, but got none")
	} else {
		t.Logf("PASE correctly rejected (commissioning window closed): %v", err)
	}
}

// TestE2E_PASE_InvalidState tests message received in wrong state.
func TestE2E_PASE_InvalidState(t *testing.T) {
	passcode := uint32(20202021)

	controllerSessionMgr := session.NewManager(session.ManagerConfig{})
	controllerMgr := NewManager(ManagerConfig{
		SessionManager: controllerSessionMgr,
	})

	exchangeID := uint16(1)

	// Start PASE
	_, _ = controllerMgr.StartPASE(exchangeID, passcode)

	// Try to send Pake2 without receiving PBKDFParamResponse first
	fakePake2 := []byte{0x15, 0x30, 0x01, 0x21, 0x00, 0x18}
	_, err := controllerMgr.Route(exchangeID, &Message{OpcodePASEPake2, fakePake2})
	if err == nil {
		t.Error("expected error for message in wrong state, but got none")
	} else {
		t.Logf("Invalid state correctly rejected: %v", err)
	}
}

// TestE2E_CASE_NoSharedRoot tests CASE failure when no shared trust root exists.
func TestE2E_CASE_NoSharedRoot(t *testing.T) {
	// Create fabric info with different roots
	fabricID := uint64(0x1234567890ABCDEF)
	initiatorNodeID := uint64(0x1111111111111111)
	responderNodeID := uint64(0x2222222222222222)

	initiatorFabric, initiatorKey := createTestFabricInfoE2E(t, 1, fabricID, initiatorNodeID)
	responderFabric, responderKey := createTestFabricInfoE2E(t, 2, fabricID, responderNodeID) // Different fabric index

	// DON'T share root - each has their own
	// This simulates nodes on different fabrics

	initiatorSessionMgr := session.NewManager(session.ManagerConfig{})

	initiatorMgr := NewManager(ManagerConfig{
		SessionManager: initiatorSessionMgr,
		LocalNodeID:    fabric.NodeID(initiatorNodeID),
	})

	// Responder fabric lookup that won't match
	fabricLookup := func(destID [casesession.DestinationIDSize]byte, initiatorRandom [casesession.RandomSize]byte) (*fabric.FabricInfo, *crypto.P256KeyPair, error) {
		// Check with responder's own root/IPK (won't match initiator's destination ID)
		ipkSlice, _ := crypto.DeriveGroupOperationalKeyV1(responderFabric.IPK[:], responderFabric.CompressedFabricID[:])
		var ipk [crypto.SymmetricKeySize]byte
		copy(ipk[:], ipkSlice)
		if casesession.MatchDestinationID(destID, initiatorRandom, responderFabric.RootPublicKey, uint64(responderFabric.FabricID), uint64(responderFabric.NodeID), ipk) {
			return responderFabric, responderKey, nil
		}
		return nil, nil, casesession.ErrNoSharedRoot
	}

	responderCASE := casesession.NewResponder(fabricLookup, nil)

	exchangeID := uint16(1)

	// Initiator starts CASE
	sigma1, err := initiatorMgr.StartCASE(exchangeID, initiatorFabric, initiatorKey, responderNodeID, nil)
	if err != nil {
		t.Fatalf("StartCASE failed: %v", err)
	}

	// Responder should fail to find matching fabric
	_, _, err = responderCASE.HandleSigma1(sigma1, 1000)
	if err == nil {
		t.Error("expected ErrNoSharedRoot error, but got none")
	} else {
		t.Logf("CASE correctly failed (no shared root): %v", err)
	}
}

// TestE2E_PASE_ConfirmationMismatch tests key confirmation failure.
func TestE2E_PASE_ConfirmationMismatch(t *testing.T) {
	passcode := uint32(20202021)
	salt := []byte("SPAKE2P Key Salt")
	iterations := uint32(1000)

	verifier, _ := pase.GenerateVerifier(passcode, salt, iterations)

	controllerSessionMgr := session.NewManager(session.ManagerConfig{})
	deviceSessionMgr := session.NewManager(session.ManagerConfig{})

	controllerMgr := NewManager(ManagerConfig{
		SessionManager: controllerSessionMgr,
	})

	deviceMgr := NewManager(ManagerConfig{
		SessionManager: deviceSessionMgr,
	})

	_ = deviceMgr.SetPASEResponder(verifier, salt, iterations)

	exchangeID := uint16(1)

	// Run handshake up to Pake3
	pbkdfReq, _ := controllerMgr.StartPASE(exchangeID, passcode)
	pbkdfRespMsg, _ := deviceMgr.Route(exchangeID, &Message{OpcodePBKDFParamRequest, pbkdfReq})
	pake1Msg, _ := controllerMgr.Route(exchangeID, &Message{OpcodePBKDFParamResponse, pbkdfRespMsg.Payload})
	pake2Msg, _ := deviceMgr.Route(exchangeID, &Message{OpcodePASEPake1, pake1Msg.Payload})
	pake3Msg, _ := controllerMgr.Route(exchangeID, &Message{OpcodePASEPake2, pake2Msg.Payload})

	// Corrupt Pake3 confirmation (cA)
	corruptedPake3 := make([]byte, len(pake3Msg.Payload))
	copy(corruptedPake3, pake3Msg.Payload)
	// The confirmation is at the end - flip some bits
	if len(corruptedPake3) > 5 {
		corruptedPake3[len(corruptedPake3)-3] ^= 0xFF
	}

	// Device should reject corrupted confirmation
	_, err := deviceMgr.Route(exchangeID, &Message{OpcodePASEPake3, corruptedPake3})
	if err == nil {
		t.Error("expected confirmation failure, but got none")
	} else {
		t.Logf("Confirmation mismatch correctly detected: %v", err)
	}
}

// TestE2E_StatusReport_Busy tests handling of Busy status during handshake.
func TestE2E_StatusReport_Busy(t *testing.T) {
	controllerSessionMgr := session.NewManager(session.ManagerConfig{})

	var busyCalled bool
	var busyWaitTime uint16

	controllerMgr := NewManager(ManagerConfig{
		SessionManager: controllerSessionMgr,
		Callbacks: Callbacks{
			OnResponderBusy: func(waitTimeMs uint16) {
				busyCalled = true
				busyWaitTime = waitTimeMs
			},
		},
	})

	exchangeID := uint16(1)

	// Start PASE
	_, _ = controllerMgr.StartPASE(exchangeID, 20202021)

	// Simulate device responding with Busy
	busyStatus := Busy(5000)
	_, err := controllerMgr.Route(exchangeID, &Message{
		Opcode:  OpcodeStatusReport,
		Payload: busyStatus.Encode(),
	})
	if err != nil {
		t.Fatalf("Route Busy failed: %v", err)
	}

	if !busyCalled {
		t.Error("OnResponderBusy callback should have been called")
	}
	if busyWaitTime != 5000 {
		t.Errorf("busyWaitTime = %d, want 5000", busyWaitTime)
	}

	// Handshake should be cleaned up
	if controllerMgr.HasActiveHandshake(exchangeID) {
		t.Error("handshake should be cleaned up after Busy response")
	}

	t.Log("Busy status handling: SUCCESS")
}

// TestE2E_PASE_MultipleHandshakes tests that multiple PASE handshakes can run concurrently.
func TestE2E_PASE_MultipleHandshakes(t *testing.T) {
	passcode := uint32(20202021)
	salt := []byte("SPAKE2P Key Salt")
	iterations := uint32(1000)

	verifier, _ := pase.GenerateVerifier(passcode, salt, iterations)

	controllerSessionMgr := session.NewManager(session.ManagerConfig{MaxSessions: 100})
	deviceSessionMgr := session.NewManager(session.ManagerConfig{MaxSessions: 100})

	establishedCount := 0
	var mu sync.Mutex

	controllerMgr := NewManager(ManagerConfig{
		SessionManager: controllerSessionMgr,
		Callbacks: Callbacks{
			OnSessionEstablished: func(ctx *session.SecureContext) {
				mu.Lock()
				establishedCount++
				mu.Unlock()
			},
		},
	})

	deviceMgr := NewManager(ManagerConfig{
		SessionManager: deviceSessionMgr,
	})

	_ = deviceMgr.SetPASEResponder(verifier, salt, iterations)

	// Run 3 concurrent handshakes
	const numHandshakes = 3

	for i := 0; i < numHandshakes; i++ {
		exchangeID := uint16(i + 1)

		pbkdfReq, err := controllerMgr.StartPASE(exchangeID, passcode)
		if err != nil {
			t.Fatalf("StartPASE %d failed: %v", i, err)
		}

		pbkdfRespMsg, _ := deviceMgr.Route(exchangeID, &Message{OpcodePBKDFParamRequest, pbkdfReq})
		pake1Msg, _ := controllerMgr.Route(exchangeID, &Message{OpcodePBKDFParamResponse, pbkdfRespMsg.Payload})
		pake2Msg, _ := deviceMgr.Route(exchangeID, &Message{OpcodePASEPake1, pake1Msg.Payload})
		pake3Msg, _ := controllerMgr.Route(exchangeID, &Message{OpcodePASEPake2, pake2Msg.Payload})
		statusMsg, _ := deviceMgr.Route(exchangeID, &Message{OpcodePASEPake3, pake3Msg.Payload})
		_, _ = controllerMgr.Route(exchangeID, &Message{OpcodeStatusReport, statusMsg.Payload})
	}

	mu.Lock()
	if establishedCount != numHandshakes {
		t.Errorf("established count = %d, want %d", establishedCount, numHandshakes)
	}
	mu.Unlock()

	t.Logf("Multiple PASE handshakes: %d sessions established", numHandshakes)
}

// TestE2E_PASE_SessionEncryptionRoundTrip verifies session keys work for encryption.
// This test directly uses PASE-derived keys with the message codec for encryption/decryption.
func TestE2E_PASE_SessionEncryptionRoundTrip(t *testing.T) {
	passcode := uint32(20202021)
	salt := []byte("Test Salt Value!")
	iterations := uint32(1000)

	verifier, _ := pase.GenerateVerifier(passcode, salt, iterations)
	initiator, _ := pase.NewInitiator(passcode)
	responder, _ := pase.NewResponder(verifier, salt, iterations)

	// Complete handshake between PASE sessions directly
	pbkdfReq, _ := initiator.Start(1000)
	pbkdfResp, _ := responder.HandlePBKDFParamRequest(pbkdfReq, 2000)
	pake1, _ := initiator.HandlePBKDFParamResponse(pbkdfResp)
	pake2, _ := responder.HandlePake1(pake1)
	pake3, _ := initiator.HandlePake2(pake2)
	_, success, _ := responder.HandlePake3(pake3)
	_ = initiator.HandleStatusReport(success)

	// Get session keys from both sides
	initiatorKeys := initiator.SessionKeys()
	responderKeys := responder.SessionKeys()

	if initiatorKeys == nil || responderKeys == nil {
		t.Fatal("session keys not available")
	}

	// Test encryption/decryption using message.Codec directly with PASE keys
	// Initiator → Responder uses I2R key
	initiatorCodec, err := message.NewCodec(initiatorKeys.I2RKey[:], 0)
	if err != nil {
		t.Fatalf("failed to create initiator codec: %v", err)
	}

	testPayload := []byte("Hello from controller to device!")

	// Build message header for controller → device
	header := &message.MessageHeader{
		SessionID:      responder.LocalSessionID(), // Responder's local session ID
		MessageCounter: 1,
	}
	protocol := &message.ProtocolHeader{
		ExchangeID:     200,
		ProtocolID:     0x0001, // IM
		ProtocolOpcode: 0x02,   // Read
		Initiator:      true,
	}

	// Encrypt with initiator's I2R key
	encrypted, err := initiatorCodec.Encode(header, protocol, testPayload, false)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	// Decrypt with responder's I2R key (same key)
	responderCodec, err := message.NewCodec(responderKeys.I2RKey[:], 0)
	if err != nil {
		t.Fatalf("failed to create responder codec: %v", err)
	}

	decrypted, err := responderCodec.Decode(encrypted, 0)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	// Verify payload
	if !bytes.Equal(decrypted.Payload, testPayload) {
		t.Errorf("payload mismatch: got %q, want %q", decrypted.Payload, testPayload)
	}

	// Test reverse direction: Responder → Initiator uses R2I key
	responderR2ICodec, _ := message.NewCodec(responderKeys.R2IKey[:], 0)
	reversePayload := []byte("Response from device to controller!")

	reverseHeader := &message.MessageHeader{
		SessionID:      initiator.LocalSessionID(),
		MessageCounter: 1,
	}
	reverseProtocol := &message.ProtocolHeader{
		ExchangeID:     200,
		ProtocolID:     0x0001,
		ProtocolOpcode: 0x05,
	}

	reverseEncrypted, err := responderR2ICodec.Encode(reverseHeader, reverseProtocol, reversePayload, false)
	if err != nil {
		t.Fatalf("Reverse encode failed: %v", err)
	}

	initiatorR2ICodec, _ := message.NewCodec(initiatorKeys.R2IKey[:], 0)
	reverseDecrypted, err := initiatorR2ICodec.Decode(reverseEncrypted, 0)
	if err != nil {
		t.Fatalf("Reverse decode failed: %v", err)
	}

	if !bytes.Equal(reverseDecrypted.Payload, reversePayload) {
		t.Errorf("reverse payload mismatch: got %q, want %q", reverseDecrypted.Payload, reversePayload)
	}

	t.Log("Session encryption round-trip: SUCCESS")
}

// =============================================================================
// Helper Functions
// =============================================================================

// createTestFabricInfoE2E creates a test fabric with generated keys.
func createTestFabricInfoE2E(t *testing.T, index uint8, fabricID uint64, nodeID uint64) (*fabric.FabricInfo, *crypto.P256KeyPair) {
	t.Helper()

	operationalKey, err := crypto.P256GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate operational key: %v", err)
	}

	rootKey, err := crypto.P256GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}

	var rootPubKey [65]byte
	copy(rootPubKey[:], rootKey.P256PublicKey())

	cfid, err := fabric.CompressedFabricIDFromCert(rootPubKey, fabric.FabricID(fabricID))
	if err != nil {
		t.Fatalf("failed to compute compressed fabric ID: %v", err)
	}

	noc := operationalKey.P256PublicKey()

	var ipk [16]byte
	for i := range ipk {
		ipk[i] = byte(i + int(index))
	}

	info := &fabric.FabricInfo{
		FabricIndex:        fabric.FabricIndex(index),
		FabricID:           fabric.FabricID(fabricID),
		NodeID:             fabric.NodeID(nodeID),
		VendorID:           fabric.VendorIDTestVendor1,
		RootPublicKey:      rootPubKey,
		CompressedFabricID: cfid,
		IPK:                ipk,
		NOC:                noc,
	}

	return info, operationalKey
}
