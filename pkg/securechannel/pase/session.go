package pase

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"sync"

	"github.com/backkem/matter/pkg/crypto"
	"github.com/backkem/matter/pkg/crypto/spake2p"
)

// Role represents the PASE participant role.
type Role int

const (
	// RoleInitiator is the commissioner who knows the passcode.
	RoleInitiator Role = iota
	// RoleResponder is the commissionee who has the verifier.
	RoleResponder
)

// String returns the role name.
func (r Role) String() string {
	switch r {
	case RoleInitiator:
		return "Initiator"
	case RoleResponder:
		return "Responder"
	default:
		return "Unknown"
	}
}

// State represents the PASE protocol state machine.
type State int

const (
	StateInit State = iota
	StateWaitingPBKDFResponse  // Initiator: sent PBKDFParamRequest
	StateWaitingPake1          // Responder: sent PBKDFParamResponse
	StateWaitingPake2          // Initiator: sent Pake1
	StateWaitingPake3          // Responder: sent Pake2
	StateWaitingStatusReport   // Initiator: sent Pake3
	StateComplete              // Session established
	StateFailed
)

// String returns the state name.
func (s State) String() string {
	switch s {
	case StateInit:
		return "Init"
	case StateWaitingPBKDFResponse:
		return "WaitingPBKDFResponse"
	case StateWaitingPake1:
		return "WaitingPake1"
	case StateWaitingPake2:
		return "WaitingPake2"
	case StateWaitingPake3:
		return "WaitingPake3"
	case StateWaitingStatusReport:
		return "WaitingStatusReport"
	case StateComplete:
		return "Complete"
	case StateFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// Session implements the PASE protocol state machine.
//
// Usage (Initiator):
//
//	session := pase.NewInitiator(passcode)
//	pbkdfReq, _ := session.Start(localSessionID)
//	// send pbkdfReq, receive pbkdfResp
//	pake1, _ := session.HandlePBKDFParamResponse(pbkdfResp)
//	// send pake1, receive pake2
//	pake3, _ := session.HandlePake2(pake2)
//	// send pake3, receive statusReport
//	session.HandleStatusReport(statusReport)
//	keys := session.SessionKeys()
//
// Usage (Responder):
//
//	verifier, _ := pase.GenerateVerifier(passcode, salt, iterations)
//	session := pase.NewResponder(verifier, salt, iterations)
//	// receive pbkdfReq
//	pbkdfResp, _ := session.HandlePBKDFParamRequest(pbkdfReq, localSessionID)
//	// send pbkdfResp, receive pake1
//	pake2, _ := session.HandlePake1(pake1)
//	// send pake2, receive pake3
//	statusReport, _ := session.HandlePake3(pake3)
//	// send statusReport
//	keys := session.SessionKeys()
type Session struct {
	role  Role
	state State

	// Passcode/verifier
	passcode   uint32    // Initiator only
	verifier   *Verifier // Responder only
	salt       []byte    // PBKDF salt
	iterations uint32    // PBKDF iterations

	// Session IDs
	localSessionID uint16
	peerSessionID  uint16

	// Random values
	localRandom [RandomSize]byte
	peerRandom  [RandomSize]byte

	// Commissioning hash context (for SPAKE2+ transcript)
	commissioningHash []byte

	// SPAKE2+ instance
	spake *spake2p.SPAKE2P

	// Raw message bytes for transcript
	pbkdfReqBytes  []byte
	pbkdfRespBytes []byte

	// Derived session keys
	sessionKeys *SessionKeys

	// MRP parameters
	localMRPParams *MRPParameters
	peerMRPParams  *MRPParameters

	// For testing: injectable random source
	rand io.Reader

	mu sync.Mutex
}

// NewInitiator creates a new PASE session as the initiator (commissioner).
//
// The initiator knows the passcode and will receive PBKDF parameters from the responder.
func NewInitiator(passcode uint32) (*Session, error) {
	if err := ValidatePasscode(passcode); err != nil {
		return nil, err
	}

	return &Session{
		role:     RoleInitiator,
		state:    StateInit,
		passcode: passcode,
		rand:     rand.Reader,
	}, nil
}

// NewInitiatorWithParams creates a new PASE session with known PBKDF parameters.
//
// Use this when the initiator already knows the salt and iterations
// (e.g., from a previous exchange or out-of-band configuration).
func NewInitiatorWithParams(passcode uint32, salt []byte, iterations uint32) (*Session, error) {
	if err := ValidatePasscode(passcode); err != nil {
		return nil, err
	}
	if err := validatePBKDFParams(salt, iterations); err != nil {
		return nil, err
	}

	return &Session{
		role:       RoleInitiator,
		state:      StateInit,
		passcode:   passcode,
		salt:       copyBytes(salt),
		iterations: iterations,
		rand:       rand.Reader,
	}, nil
}

// NewResponder creates a new PASE session as the responder (commissionee).
//
// The responder has a pre-computed verifier and provides PBKDF parameters.
func NewResponder(verifier *Verifier, salt []byte, iterations uint32) (*Session, error) {
	if verifier == nil {
		return nil, ErrInvalidMessage
	}
	if err := validatePBKDFParams(salt, iterations); err != nil {
		return nil, err
	}

	return &Session{
		role:       RoleResponder,
		state:      StateInit,
		verifier:   verifier,
		salt:       copyBytes(salt),
		iterations: iterations,
		rand:       rand.Reader,
	}, nil
}

// Start begins the PASE handshake (Initiator only).
// Returns the PBKDFParamRequest message bytes.
func (s *Session) Start(localSessionID uint16) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.role != RoleInitiator {
		return nil, ErrInvalidState
	}
	if s.state != StateInit {
		return nil, ErrInvalidState
	}

	s.localSessionID = localSessionID

	// Generate random
	if _, err := io.ReadFull(s.rand, s.localRandom[:]); err != nil {
		return nil, err
	}

	// Build PBKDFParamRequest
	req := &PBKDFParamRequest{
		InitiatorRandom:    s.localRandom,
		InitiatorSessionID: localSessionID,
		PasscodeID:         DefaultPasscodeID,
		HasPBKDFParameters: s.salt != nil && s.iterations > 0,
		MRPParams:          s.localMRPParams,
	}

	data, err := req.Encode()
	if err != nil {
		return nil, err
	}

	s.pbkdfReqBytes = data
	s.state = StateWaitingPBKDFResponse

	return data, nil
}

// HandlePBKDFParamRequest processes a PBKDFParamRequest (Responder only).
// Returns the PBKDFParamResponse message bytes.
func (s *Session) HandlePBKDFParamRequest(data []byte, localSessionID uint16) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.role != RoleResponder {
		return nil, ErrInvalidState
	}
	if s.state != StateInit {
		return nil, ErrInvalidState
	}

	// Decode request
	req, err := DecodePBKDFParamRequest(data)
	if err != nil {
		return nil, err
	}

	// Validate passcode ID
	if req.PasscodeID != DefaultPasscodeID {
		return nil, ErrInvalidPasscodeID
	}

	// Store request data for transcript
	s.pbkdfReqBytes = data
	s.localSessionID = localSessionID
	s.peerSessionID = req.InitiatorSessionID
	s.peerRandom = req.InitiatorRandom
	s.peerMRPParams = req.MRPParams

	// Generate our random
	if _, err := io.ReadFull(s.rand, s.localRandom[:]); err != nil {
		return nil, err
	}

	// Build response
	resp := &PBKDFParamResponse{
		InitiatorRandom:    req.InitiatorRandom,
		ResponderRandom:    s.localRandom,
		ResponderSessionID: localSessionID,
		MRPParams:          s.localMRPParams,
	}

	// Include PBKDF params if initiator doesn't have them
	if !req.HasPBKDFParameters {
		resp.PBKDFParams = &PBKDFParameters{
			Iterations: s.iterations,
			Salt:       s.salt,
		}
	}

	respData, err := resp.Encode()
	if err != nil {
		return nil, err
	}

	s.pbkdfRespBytes = respData

	// Compute commissioning hash context
	if err := s.computeContext(); err != nil {
		return nil, err
	}

	// Setup SPAKE2+ as verifier
	s.spake, err = spake2p.NewVerifier(s.commissioningHash, nil, nil, s.verifier.W0, s.verifier.L)
	if err != nil {
		return nil, err
	}

	s.state = StateWaitingPake1

	return respData, nil
}

// HandlePBKDFParamResponse processes a PBKDFParamResponse (Initiator only).
// Returns the Pake1 message bytes.
func (s *Session) HandlePBKDFParamResponse(data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.role != RoleInitiator {
		return nil, ErrInvalidState
	}
	if s.state != StateWaitingPBKDFResponse {
		return nil, ErrInvalidState
	}

	// Decode response
	resp, err := DecodePBKDFParamResponse(data)
	if err != nil {
		return nil, err
	}

	// Verify initiator random matches
	if subtle.ConstantTimeCompare(resp.InitiatorRandom[:], s.localRandom[:]) != 1 {
		return nil, ErrRandomMismatch
	}

	s.pbkdfRespBytes = data
	s.peerSessionID = resp.ResponderSessionID
	s.peerRandom = resp.ResponderRandom
	s.peerMRPParams = resp.MRPParams

	// Use received PBKDF params if we don't have them
	if s.salt == nil && resp.PBKDFParams != nil {
		s.salt = resp.PBKDFParams.Salt
		s.iterations = resp.PBKDFParams.Iterations
	}

	if s.salt == nil || s.iterations == 0 {
		return nil, ErrInvalidMessage
	}

	// Compute commissioning hash context
	if err := s.computeContext(); err != nil {
		return nil, err
	}

	// Compute w0 and w1 from passcode
	w0, w1, err := ComputeW0W1(s.passcode, s.salt, s.iterations)
	if err != nil {
		return nil, err
	}

	// Setup SPAKE2+ as prover
	s.spake, err = spake2p.NewProver(s.commissioningHash, nil, nil, w0, w1)
	if err != nil {
		return nil, err
	}

	// Generate our share (pA)
	pA, err := s.spake.GenerateShare()
	if err != nil {
		return nil, err
	}

	// Build Pake1
	pake1 := &Pake1{PA: pA}
	pake1Data, err := pake1.Encode()
	if err != nil {
		return nil, err
	}

	s.state = StateWaitingPake2

	return pake1Data, nil
}

// HandlePake1 processes a Pake1 message (Responder only).
// Returns the Pake2 message bytes.
func (s *Session) HandlePake1(data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.role != RoleResponder {
		return nil, ErrInvalidState
	}
	if s.state != StateWaitingPake1 {
		return nil, ErrInvalidState
	}

	// Decode Pake1
	pake1, err := DecodePake1(data)
	if err != nil {
		return nil, err
	}

	// Generate our share (pB)
	pB, err := s.spake.GenerateShare()
	if err != nil {
		return nil, err
	}

	// Process peer's share
	if err := s.spake.ProcessPeerShare(pake1.PA); err != nil {
		return nil, err
	}

	// Get our confirmation (cB)
	cB, err := s.spake.Confirmation()
	if err != nil {
		return nil, err
	}

	// Build Pake2
	pake2 := &Pake2{PB: pB, CB: cB}
	pake2Data, err := pake2.Encode()
	if err != nil {
		return nil, err
	}

	s.state = StateWaitingPake3

	return pake2Data, nil
}

// HandlePake2 processes a Pake2 message (Initiator only).
// Returns the Pake3 message bytes.
func (s *Session) HandlePake2(data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.role != RoleInitiator {
		return nil, ErrInvalidState
	}
	if s.state != StateWaitingPake2 {
		return nil, ErrInvalidState
	}

	// Decode Pake2
	pake2, err := DecodePake2(data)
	if err != nil {
		return nil, err
	}

	// Process peer's share
	if err := s.spake.ProcessPeerShare(pake2.PB); err != nil {
		return nil, err
	}

	// Verify peer's confirmation (cB)
	if err := s.spake.VerifyPeerConfirmation(pake2.CB); err != nil {
		return nil, ErrConfirmationFailed
	}

	// Get our confirmation (cA)
	cA, err := s.spake.Confirmation()
	if err != nil {
		return nil, err
	}

	// Build Pake3
	pake3 := &Pake3{CA: cA}
	pake3Data, err := pake3.Encode()
	if err != nil {
		return nil, err
	}

	s.state = StateWaitingStatusReport

	return pake3Data, nil
}

// HandlePake3 processes a Pake3 message (Responder only).
// Returns StatusReport bytes (success or error) and whether the handshake succeeded.
func (s *Session) HandlePake3(data []byte) (statusReport []byte, success bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.role != RoleResponder {
		return nil, false, ErrInvalidState
	}
	if s.state != StateWaitingPake3 {
		return nil, false, ErrInvalidState
	}

	// Decode Pake3
	pake3, err := DecodePake3(data)
	if err != nil {
		return nil, false, err
	}

	// Verify peer's confirmation (cA)
	if err := s.spake.VerifyPeerConfirmation(pake3.CA); err != nil {
		s.state = StateFailed
		return nil, false, ErrConfirmationFailed
	}

	// Derive session keys
	if err := s.deriveSessionKeys(); err != nil {
		return nil, false, err
	}

	s.state = StateComplete

	// Return success status report (caller encodes with securechannel.Success())
	return nil, true, nil
}

// HandleStatusReport processes a StatusReport (Initiator only).
// This completes the handshake on the initiator side.
//
// The caller should decode the raw status bytes using securechannel.DecodeStatusReport
// to check for errors before calling this method.
func (s *Session) HandleStatusReport(isSuccess bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.role != RoleInitiator {
		return ErrInvalidState
	}
	if s.state != StateWaitingStatusReport {
		return ErrInvalidState
	}

	if !isSuccess {
		s.state = StateFailed
		return ErrInvalidStatusReport
	}

	// Derive session keys
	if err := s.deriveSessionKeys(); err != nil {
		return err
	}

	s.state = StateComplete
	return nil
}

// computeContext computes the commissioning hash context.
// Context = SHA256(ContextPrefix || PBKDFParamRequest || PBKDFParamResponse)
func (s *Session) computeContext() error {
	h := sha256.New()
	h.Write([]byte(ContextPrefix))
	h.Write(s.pbkdfReqBytes)
	h.Write(s.pbkdfRespBytes)
	s.commissioningHash = h.Sum(nil)
	return nil
}

// deriveSessionKeys derives the I2R, R2I, and attestation challenge keys.
// SEKeys = HKDF-SHA-256(Ke, salt=[], info="SessionKeys", length=48)
func (s *Session) deriveSessionKeys() error {
	ke := s.spake.SharedSecret()
	if len(ke) == 0 {
		return ErrSessionNotReady
	}

	// Derive session keys
	info := []byte("SessionKeys")
	seKeys, err := crypto.HKDFSHA256(ke, nil, info, 48)
	if err != nil {
		return err
	}

	s.sessionKeys = &SessionKeys{}
	copy(s.sessionKeys.I2RKey[:], seKeys[0:16])
	copy(s.sessionKeys.R2IKey[:], seKeys[16:32])
	copy(s.sessionKeys.AttestationChallenge[:], seKeys[32:48])

	return nil
}

// State returns the current protocol state.
func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Role returns the session role.
func (s *Session) Role() Role {
	return s.role
}

// SessionKeys returns the derived session keys.
// Returns nil if the session is not complete.
func (s *Session) SessionKeys() *SessionKeys {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != StateComplete {
		return nil
	}
	return s.sessionKeys
}

// LocalSessionID returns the local session ID.
func (s *Session) LocalSessionID() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.localSessionID
}

// PeerSessionID returns the peer's session ID.
func (s *Session) PeerSessionID() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerSessionID
}

// SetLocalMRPParams sets the local MRP parameters to include in messages.
// Must be called before Start() for initiators or HandlePBKDFParamRequest() for responders.
func (s *Session) SetLocalMRPParams(params *MRPParameters) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localMRPParams = params
}

// PeerMRPParams returns the peer's MRP parameters received during the handshake.
// Returns nil if no MRP parameters were received.
func (s *Session) PeerMRPParams() *MRPParameters {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerMRPParams
}

// SetRandom sets the random source for testing purposes.
func (s *Session) SetRandom(r io.Reader) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rand = r
}

func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
