package pase

import (
	"bytes"
	"testing"

	"github.com/backkem/matter/pkg/crypto"
)

func TestPASEHandshakeSuccess(t *testing.T) {
	// Test parameters
	passcode := uint32(20202021) // Default Matter test passcode
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	iterations := uint32(1000)

	// Generate verifier for responder
	verifier, err := GenerateVerifier(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("GenerateVerifier failed: %v", err)
	}

	// Create sessions
	initiator, err := NewInitiator(passcode)
	if err != nil {
		t.Fatalf("NewInitiator failed: %v", err)
	}

	responder, err := NewResponder(verifier, salt, iterations)
	if err != nil {
		t.Fatalf("NewResponder failed: %v", err)
	}

	// Step 1: Initiator sends PBKDFParamRequest
	pbkdfReq, err := initiator.Start(1000)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if initiator.State() != StateWaitingPBKDFResponse {
		t.Errorf("Expected state WaitingPBKDFResponse, got %v", initiator.State())
	}

	// Step 2: Responder handles request, sends PBKDFParamResponse
	pbkdfResp, err := responder.HandlePBKDFParamRequest(pbkdfReq, 2000)
	if err != nil {
		t.Fatalf("HandlePBKDFParamRequest failed: %v", err)
	}
	if responder.State() != StateWaitingPake1 {
		t.Errorf("Expected state WaitingPake1, got %v", responder.State())
	}

	// Step 3: Initiator handles response, sends Pake1
	pake1, err := initiator.HandlePBKDFParamResponse(pbkdfResp)
	if err != nil {
		t.Fatalf("HandlePBKDFParamResponse failed: %v", err)
	}
	if initiator.State() != StateWaitingPake2 {
		t.Errorf("Expected state WaitingPake2, got %v", initiator.State())
	}

	// Step 4: Responder handles Pake1, sends Pake2
	pake2, err := responder.HandlePake1(pake1)
	if err != nil {
		t.Fatalf("HandlePake1 failed: %v", err)
	}
	if responder.State() != StateWaitingPake3 {
		t.Errorf("Expected state WaitingPake3, got %v", responder.State())
	}

	// Step 5: Initiator handles Pake2, sends Pake3
	pake3, err := initiator.HandlePake2(pake2)
	if err != nil {
		t.Fatalf("HandlePake2 failed: %v", err)
	}
	if initiator.State() != StateWaitingStatusReport {
		t.Errorf("Expected state WaitingStatusReport, got %v", initiator.State())
	}

	// Step 6: Responder handles Pake3, returns success
	_, success, err := responder.HandlePake3(pake3)
	if err != nil {
		t.Fatalf("HandlePake3 failed: %v", err)
	}
	if !success {
		t.Error("Expected success=true")
	}
	if responder.State() != StateComplete {
		t.Errorf("Expected state Complete, got %v", responder.State())
	}

	// Step 7: Initiator handles StatusReport
	err = initiator.HandleStatusReport(true)
	if err != nil {
		t.Fatalf("HandleStatusReport failed: %v", err)
	}
	if initiator.State() != StateComplete {
		t.Errorf("Expected state Complete, got %v", initiator.State())
	}

	// Verify session keys match
	initiatorKeys := initiator.SessionKeys()
	responderKeys := responder.SessionKeys()

	if initiatorKeys == nil {
		t.Fatal("Initiator session keys are nil")
	}
	if responderKeys == nil {
		t.Fatal("Responder session keys are nil")
	}

	if !bytes.Equal(initiatorKeys.I2RKey[:], responderKeys.I2RKey[:]) {
		t.Error("I2R keys don't match")
	}
	if !bytes.Equal(initiatorKeys.R2IKey[:], responderKeys.R2IKey[:]) {
		t.Error("R2I keys don't match")
	}
	if !bytes.Equal(initiatorKeys.AttestationChallenge[:], responderKeys.AttestationChallenge[:]) {
		t.Error("Attestation challenges don't match")
	}

	// Verify session IDs
	if initiator.LocalSessionID() != 1000 {
		t.Errorf("Expected initiator local session ID 1000, got %d", initiator.LocalSessionID())
	}
	if initiator.PeerSessionID() != 2000 {
		t.Errorf("Expected initiator peer session ID 2000, got %d", initiator.PeerSessionID())
	}
	if responder.LocalSessionID() != 2000 {
		t.Errorf("Expected responder local session ID 2000, got %d", responder.LocalSessionID())
	}
	if responder.PeerSessionID() != 1000 {
		t.Errorf("Expected responder peer session ID 1000, got %d", responder.PeerSessionID())
	}
}

func TestPASEWrongPasscode(t *testing.T) {
	// Setup with different passcodes
	correctPasscode := uint32(20202021)
	wrongPasscode := uint32(12341234)
	salt := make([]byte, 32)
	iterations := uint32(1000)

	// Verifier is for correct passcode
	verifier, err := GenerateVerifier(correctPasscode, salt, iterations)
	if err != nil {
		t.Fatalf("GenerateVerifier failed: %v", err)
	}

	// Initiator uses wrong passcode
	initiator, err := NewInitiator(wrongPasscode)
	if err != nil {
		t.Fatalf("NewInitiator failed: %v", err)
	}

	responder, err := NewResponder(verifier, salt, iterations)
	if err != nil {
		t.Fatalf("NewResponder failed: %v", err)
	}

	// Run protocol until failure
	pbkdfReq, _ := initiator.Start(1000)
	pbkdfResp, _ := responder.HandlePBKDFParamRequest(pbkdfReq, 2000)
	pake1, _ := initiator.HandlePBKDFParamResponse(pbkdfResp)
	pake2, _ := responder.HandlePake1(pake1)

	// This should fail - wrong passcode means wrong w0/w1
	_, err = initiator.HandlePake2(pake2)
	if err == nil {
		t.Error("Expected error for wrong passcode, got nil")
	}
}

func TestPASEInitiatorWithKnownParams(t *testing.T) {
	passcode := uint32(20202021)
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	iterations := uint32(1000)

	verifier, err := GenerateVerifier(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("GenerateVerifier failed: %v", err)
	}

	// Initiator already knows PBKDF params
	initiator, err := NewInitiatorWithParams(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("NewInitiatorWithParams failed: %v", err)
	}

	responder, err := NewResponder(verifier, salt, iterations)
	if err != nil {
		t.Fatalf("NewResponder failed: %v", err)
	}

	// Complete handshake
	pbkdfReq, _ := initiator.Start(1000)
	pbkdfResp, _ := responder.HandlePBKDFParamRequest(pbkdfReq, 2000)
	pake1, _ := initiator.HandlePBKDFParamResponse(pbkdfResp)
	pake2, _ := responder.HandlePake1(pake1)
	pake3, _ := initiator.HandlePake2(pake2)
	_, success, _ := responder.HandlePake3(pake3)
	initiator.HandleStatusReport(success)

	// Verify success
	if initiator.State() != StateComplete {
		t.Errorf("Expected Complete, got %v", initiator.State())
	}
	if responder.State() != StateComplete {
		t.Errorf("Expected Complete, got %v", responder.State())
	}
}

func TestPASEInvalidStateTransitions(t *testing.T) {
	passcode := uint32(20202021)
	salt := make([]byte, 32)
	iterations := uint32(1000)

	t.Run("initiator_double_start", func(t *testing.T) {
		initiator, _ := NewInitiator(passcode)
		initiator.Start(1000)

		_, err := initiator.Start(1001)
		if err != ErrInvalidState {
			t.Errorf("Expected ErrInvalidState, got %v", err)
		}
	})

	t.Run("responder_start", func(t *testing.T) {
		verifier, _ := GenerateVerifier(passcode, salt, iterations)
		responder, _ := NewResponder(verifier, salt, iterations)

		_, err := responder.Start(1000)
		if err != ErrInvalidState {
			t.Errorf("Expected ErrInvalidState, got %v", err)
		}
	})

	t.Run("initiator_handle_pake1", func(t *testing.T) {
		initiator, _ := NewInitiator(passcode)

		_, err := initiator.HandlePake1([]byte{})
		if err != ErrInvalidState {
			t.Errorf("Expected ErrInvalidState, got %v", err)
		}
	})
}

func TestPASEStatusReportFailure(t *testing.T) {
	passcode := uint32(20202021)
	salt := make([]byte, 32)
	iterations := uint32(1000)

	verifier, _ := GenerateVerifier(passcode, salt, iterations)

	// Create fresh initiator and responder
	initiator, _ := NewInitiator(passcode)
	responder, _ := NewResponder(verifier, salt, iterations)

	// Run handshake to get initiator to WaitingStatusReport state
	pbkdfReq, _ := initiator.Start(1000)
	pbkdfResp, _ := responder.HandlePBKDFParamRequest(pbkdfReq, 2000)
	pake1, _ := initiator.HandlePBKDFParamResponse(pbkdfResp)
	pake2, _ := responder.HandlePake1(pake1)
	_, _ = initiator.HandlePake2(pake2)

	// Verify we're in the right state
	if initiator.State() != StateWaitingStatusReport {
		t.Fatalf("Expected WaitingStatusReport state, got %v", initiator.State())
	}

	// Handle failure status
	err := initiator.HandleStatusReport(false)
	if err != ErrInvalidStatusReport {
		t.Errorf("Expected ErrInvalidStatusReport, got %v", err)
	}

	if initiator.State() != StateFailed {
		t.Errorf("Expected Failed state, got %v", initiator.State())
	}
}

func TestPASEMRPParameterExchange(t *testing.T) {
	passcode := uint32(20202021)
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	iterations := uint32(1000)

	verifier, err := GenerateVerifier(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("GenerateVerifier failed: %v", err)
	}

	// Create sessions with MRP parameters
	initiator, _ := NewInitiator(passcode)
	initiatorMRP := &MRPParameters{
		IdleRetransTimeout:   1000,
		ActiveRetransTimeout: 2000,
		ActiveThreshold:      4000,
	}
	initiator.SetLocalMRPParams(initiatorMRP)

	responder, _ := NewResponder(verifier, salt, iterations)
	responderMRP := &MRPParameters{
		IdleRetransTimeout:   3000,
		ActiveRetransTimeout: 5000,
		ActiveThreshold:      6000,
	}
	responder.SetLocalMRPParams(responderMRP)

	// Complete handshake
	pbkdfReq, _ := initiator.Start(1000)
	pbkdfResp, _ := responder.HandlePBKDFParamRequest(pbkdfReq, 2000)
	pake1, _ := initiator.HandlePBKDFParamResponse(pbkdfResp)
	pake2, _ := responder.HandlePake1(pake1)
	pake3, _ := initiator.HandlePake2(pake2)
	_, success, _ := responder.HandlePake3(pake3)
	initiator.HandleStatusReport(success)

	// Verify MRP params were exchanged
	initiatorPeerMRP := initiator.PeerMRPParams()
	if initiatorPeerMRP == nil {
		t.Fatal("Initiator did not receive peer MRP params")
	}
	if initiatorPeerMRP.IdleRetransTimeout != responderMRP.IdleRetransTimeout {
		t.Errorf("Initiator peer IdleRetransTimeout = %d, want %d",
			initiatorPeerMRP.IdleRetransTimeout, responderMRP.IdleRetransTimeout)
	}
	if initiatorPeerMRP.ActiveRetransTimeout != responderMRP.ActiveRetransTimeout {
		t.Errorf("Initiator peer ActiveRetransTimeout = %d, want %d",
			initiatorPeerMRP.ActiveRetransTimeout, responderMRP.ActiveRetransTimeout)
	}
	if initiatorPeerMRP.ActiveThreshold != responderMRP.ActiveThreshold {
		t.Errorf("Initiator peer ActiveThreshold = %d, want %d",
			initiatorPeerMRP.ActiveThreshold, responderMRP.ActiveThreshold)
	}

	responderPeerMRP := responder.PeerMRPParams()
	if responderPeerMRP == nil {
		t.Fatal("Responder did not receive peer MRP params")
	}
	if responderPeerMRP.IdleRetransTimeout != initiatorMRP.IdleRetransTimeout {
		t.Errorf("Responder peer IdleRetransTimeout = %d, want %d",
			responderPeerMRP.IdleRetransTimeout, initiatorMRP.IdleRetransTimeout)
	}
	if responderPeerMRP.ActiveRetransTimeout != initiatorMRP.ActiveRetransTimeout {
		t.Errorf("Responder peer ActiveRetransTimeout = %d, want %d",
			responderPeerMRP.ActiveRetransTimeout, initiatorMRP.ActiveRetransTimeout)
	}
	if responderPeerMRP.ActiveThreshold != initiatorMRP.ActiveThreshold {
		t.Errorf("Responder peer ActiveThreshold = %d, want %d",
			responderPeerMRP.ActiveThreshold, initiatorMRP.ActiveThreshold)
	}
}

func TestPASEHandshakeWithoutMRP(t *testing.T) {
	// Verify handshake works without MRP params (nil peer MRP is expected)
	passcode := uint32(20202021)
	salt := make([]byte, 32)
	iterations := uint32(1000)

	verifier, _ := GenerateVerifier(passcode, salt, iterations)
	initiator, _ := NewInitiator(passcode)
	responder, _ := NewResponder(verifier, salt, iterations)

	// Complete handshake without setting MRP params
	pbkdfReq, _ := initiator.Start(1000)
	pbkdfResp, _ := responder.HandlePBKDFParamRequest(pbkdfReq, 2000)
	pake1, _ := initiator.HandlePBKDFParamResponse(pbkdfResp)
	pake2, _ := responder.HandlePake1(pake1)
	pake3, _ := initiator.HandlePake2(pake2)
	_, success, _ := responder.HandlePake3(pake3)
	initiator.HandleStatusReport(success)

	// Both should complete successfully
	if initiator.State() != StateComplete {
		t.Errorf("Initiator state = %v, want Complete", initiator.State())
	}
	if responder.State() != StateComplete {
		t.Errorf("Responder state = %v, want Complete", responder.State())
	}

	// MRP params should be nil when not exchanged
	if initiator.PeerMRPParams() != nil {
		t.Error("Expected nil peer MRP params for initiator")
	}
	if responder.PeerMRPParams() != nil {
		t.Error("Expected nil peer MRP params for responder")
	}
}

func TestPASEPake3ConfirmationFailure(t *testing.T) {
	passcode := uint32(20202021)
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	iterations := uint32(1000)

	verifier, _ := GenerateVerifier(passcode, salt, iterations)
	initiator, _ := NewInitiator(passcode)
	responder, _ := NewResponder(verifier, salt, iterations)

	// Run handshake up to Pake3
	pbkdfReq, _ := initiator.Start(1000)
	pbkdfResp, _ := responder.HandlePBKDFParamRequest(pbkdfReq, 2000)
	pake1, _ := initiator.HandlePBKDFParamResponse(pbkdfResp)
	pake2, _ := responder.HandlePake1(pake1)
	pake3Data, _ := initiator.HandlePake2(pake2)

	// Corrupt the Pake3 confirmation value
	// Pake3 is TLV: struct with CA (tag 1)
	// We'll decode, corrupt CA, and re-encode
	pake3, err := DecodePake3(pake3Data)
	if err != nil {
		t.Fatalf("DecodePake3 failed: %v", err)
	}

	// Corrupt the confirmation (flip a bit)
	pake3.CA[0] ^= 0xFF

	corruptedPake3, err := pake3.Encode()
	if err != nil {
		t.Fatalf("Failed to encode corrupted Pake3: %v", err)
	}

	// Responder should reject the corrupted confirmation
	_, success, err := responder.HandlePake3(corruptedPake3)
	if err != ErrConfirmationFailed {
		t.Errorf("Expected ErrConfirmationFailed, got %v", err)
	}
	if success {
		t.Error("Expected success=false for corrupted Pake3")
	}
	if responder.State() != StateFailed {
		t.Errorf("Expected Failed state, got %v", responder.State())
	}
}

func TestPASEMoreInvalidStateTransitions(t *testing.T) {
	passcode := uint32(20202021)
	salt := make([]byte, 32)
	iterations := uint32(1000)
	verifier, _ := GenerateVerifier(passcode, salt, iterations)

	t.Run("responder_handle_pake1_before_pbkdf", func(t *testing.T) {
		responder, _ := NewResponder(verifier, salt, iterations)
		_, err := responder.HandlePake1([]byte{})
		if err != ErrInvalidState {
			t.Errorf("Expected ErrInvalidState, got %v", err)
		}
	})

	t.Run("responder_handle_pake3_before_pake1", func(t *testing.T) {
		responder, _ := NewResponder(verifier, salt, iterations)
		_, _, err := responder.HandlePake3([]byte{})
		if err != ErrInvalidState {
			t.Errorf("Expected ErrInvalidState, got %v", err)
		}
	})

	t.Run("initiator_handle_pbkdf_response_before_start", func(t *testing.T) {
		initiator, _ := NewInitiator(passcode)
		_, err := initiator.HandlePBKDFParamResponse([]byte{})
		if err != ErrInvalidState {
			t.Errorf("Expected ErrInvalidState, got %v", err)
		}
	})

	t.Run("initiator_handle_pake2_before_pbkdf_response", func(t *testing.T) {
		initiator, _ := NewInitiator(passcode)
		initiator.Start(1000)
		_, err := initiator.HandlePake2([]byte{})
		if err != ErrInvalidState {
			t.Errorf("Expected ErrInvalidState, got %v", err)
		}
	})

	t.Run("initiator_handle_status_report_before_pake3", func(t *testing.T) {
		initiator, _ := NewInitiator(passcode)
		err := initiator.HandleStatusReport(true)
		if err != ErrInvalidState {
			t.Errorf("Expected ErrInvalidState, got %v", err)
		}
	})
}

// TestSessionKeyDerivationWithCReferenceVector verifies session key derivation
// using the test vector from the Matter C SDK (TestSessionKeystore.cpp).
// This proves our HKDF implementation is compatible with the reference.
//
// C Reference Test Vector:
//
//	secret = "secret", salt = "salt123", info = "info123"
//	I2R  = a134e284e8628486f4d620a711f3cb50
//	R2I  = 8a84a74c1550cf1dc57e5f8a099dcf37
//	Attestation = 739184dd1465856473706661f5116be5
func TestSessionKeyDerivationWithCReferenceVector(t *testing.T) {
	// Test vector from connectedhomeip/src/crypto/tests/TestSessionKeystore.cpp
	secret := []byte("secret")
	salt := []byte("salt123")
	info := []byte("info123")

	// Expected keys from C reference (comments in DeriveSessionKeysTestVector)
	expectedI2R := []byte{
		0xa1, 0x34, 0xe2, 0x84, 0xe8, 0x62, 0x84, 0x86,
		0xf4, 0xd6, 0x20, 0xa7, 0x11, 0xf3, 0xcb, 0x50,
	}
	expectedR2I := []byte{
		0x8a, 0x84, 0xa7, 0x4c, 0x15, 0x50, 0xcf, 0x1d,
		0xc5, 0x7e, 0x5f, 0x8a, 0x09, 0x9d, 0xcf, 0x37,
	}
	expectedAttestation := []byte{
		0x73, 0x91, 0x84, 0xdd, 0x14, 0x65, 0x85, 0x64,
		0x73, 0x70, 0x66, 0x61, 0xf5, 0x11, 0x6b, 0xe5,
	}

	// Derive 48 bytes using HKDF
	seKeys, err := crypto.HKDFSHA256(secret, salt, info, 48)
	if err != nil {
		t.Fatalf("HKDF failed: %v", err)
	}

	derivedI2R := seKeys[0:16]
	derivedR2I := seKeys[16:32]
	derivedAttestation := seKeys[32:48]

	if !bytes.Equal(derivedI2R, expectedI2R) {
		t.Errorf("I2R key mismatch:\ngot:  %x\nwant: %x", derivedI2R, expectedI2R)
	}
	if !bytes.Equal(derivedR2I, expectedR2I) {
		t.Errorf("R2I key mismatch:\ngot:  %x\nwant: %x", derivedR2I, expectedR2I)
	}
	if !bytes.Equal(derivedAttestation, expectedAttestation) {
		t.Errorf("Attestation mismatch:\ngot:  %x\nwant: %x", derivedAttestation, expectedAttestation)
	}
}

// TestSessionKeyDerivation verifies that both sides of a PASE handshake
// derive identical session keys.
func TestSessionKeyDerivation(t *testing.T) {
	passcode := uint32(20202021)
	salt := []byte("SPAKE2P Key Salt")
	iterations := uint32(1000)

	verifier, _ := GenerateVerifier(passcode, salt, iterations)
	initiator, _ := NewInitiator(passcode)
	responder, _ := NewResponder(verifier, salt, iterations)

	// Complete handshake
	pbkdfReq, _ := initiator.Start(1000)
	pbkdfResp, _ := responder.HandlePBKDFParamRequest(pbkdfReq, 2000)
	pake1, _ := initiator.HandlePBKDFParamResponse(pbkdfResp)
	pake2, _ := responder.HandlePake1(pake1)
	pake3, _ := initiator.HandlePake2(pake2)
	_, success, _ := responder.HandlePake3(pake3)
	initiator.HandleStatusReport(success)

	// Both sides should have the same keys
	initiatorKeys := initiator.SessionKeys()
	responderKeys := responder.SessionKeys()

	if !bytes.Equal(initiatorKeys.I2RKey[:], responderKeys.I2RKey[:]) {
		t.Error("I2R keys don't match between initiator and responder")
	}
	if !bytes.Equal(initiatorKeys.R2IKey[:], responderKeys.R2IKey[:]) {
		t.Error("R2I keys don't match between initiator and responder")
	}
	if !bytes.Equal(initiatorKeys.AttestationChallenge[:], responderKeys.AttestationChallenge[:]) {
		t.Error("Attestation challenges don't match between initiator and responder")
	}

	// Verify key sizes per spec
	if len(initiatorKeys.I2RKey) != 16 {
		t.Errorf("I2R key size = %d, want 16", len(initiatorKeys.I2RKey))
	}
	if len(initiatorKeys.R2IKey) != 16 {
		t.Errorf("R2I key size = %d, want 16", len(initiatorKeys.R2IKey))
	}
	if len(initiatorKeys.AttestationChallenge) != 16 {
		t.Errorf("Attestation challenge size = %d, want 16", len(initiatorKeys.AttestationChallenge))
	}
}
