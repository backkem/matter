package casesession

import (
	"crypto/rand"
	"fmt"
	"io"
	"sync"

	"github.com/backkem/matter/pkg/crypto"
	"github.com/backkem/matter/pkg/fabric"
)

// FabricLookupFunc finds a fabric matching the destination ID.
// Used by responder to identify which fabric the initiator is targeting.
//
// Parameters:
//   - destinationID: 32-byte destination identifier from Sigma1
//   - initiatorRandom: 32-byte random from Sigma1 (needed to compute candidate IDs)
//
// Returns the matching FabricInfo and operational key pair, or error if not found.
type FabricLookupFunc func(
	destinationID [DestinationIDSize]byte,
	initiatorRandom [RandomSize]byte,
) (*fabric.FabricInfo, *crypto.P256KeyPair, error)

// ResumptionLookupFunc finds a previous session for resumption.
// Used by responder to look up shared secret and validate resumption.
//
// Parameters:
//   - resumptionID: 16-byte resumption ID from Sigma1
//
// Returns the previous session's shared secret and fabric info, or nil if not found.
type ResumptionLookupFunc func(
	resumptionID [ResumptionIDSize]byte,
) (sharedSecret []byte, fabricInfo *fabric.FabricInfo, operationalKey *crypto.P256KeyPair, ok bool)

// Session manages the state of a CASE handshake.
//
// For initiator:
//  1. Create session with NewInitiator()
//  2. Call Start() to get Sigma1 bytes
//  3. Call HandleSigma2() or HandleSigma2Resume() based on response
//  4. Call HandleStatusReport() after receiving final status
//  5. Call SessionKeys() to get the derived keys
//
// For responder:
//  1. Create session with NewResponder()
//  2. Call HandleSigma1() to process Sigma1, get Sigma2/Sigma2Resume response
//  3. If full handshake: call HandleSigma3() to process Sigma3
//  4. Call SessionKeys() to get the derived keys
type Session struct {
	role  Role
	state State

	// Configuration
	fabricInfo     *fabric.FabricInfo   // Our fabric credentials
	operationalKey *crypto.P256KeyPair  // Our NOC private key
	targetNodeID   uint64               // For initiator: target peer node ID

	// Lookup functions (responder)
	fabricLookup     FabricLookupFunc
	resumptionLookup ResumptionLookupFunc

	// Certificate validation callback (optional)
	// If not set, certificate validation is skipped (suitable for testing only)
	certValidator ValidatePeerCertChainFunc

	// Session IDs
	localSessionID uint16
	peerSessionID  uint16

	// Random values
	localRandom [RandomSize]byte
	peerRandom  [RandomSize]byte

	// Ephemeral key pair and peer's ephemeral public key
	ephKeyPair    *crypto.P256KeyPair
	peerEphPubKey [crypto.P256PublicKeySizeBytes]byte

	// ECDH shared secret
	sharedSecret []byte

	// IPK (derived operational group key)
	ipk [crypto.SymmetricKeySize]byte

	// Resumption state (input for initiator trying to resume)
	resumptionInfo *ResumptionInfo

	// Resumption ID for new session (output)
	newResumptionID [ResumptionIDSize]byte

	// Raw message bytes (for transcript hash)
	msg1Bytes []byte
	msg2Bytes []byte
	msg3Bytes []byte

	// Derived session keys
	sessionKeys *SessionKeys

	// Whether resumption was used
	usedResumption bool

	// Peer certificate info (validated)
	peerNOC    []byte
	peerICAC   []byte
	peerNodeID uint64

	// MRP parameters
	localMRPParams *MRPParameters
	peerMRPParams  *MRPParameters

	// Random source (injectable for testing)
	rand io.Reader

	mu sync.Mutex
}

// NewInitiator creates a CASE session as initiator.
//
// Parameters:
//   - fabricInfo: Our fabric credentials (NOC chain, IPK, etc.)
//   - operationalKey: Our NOC private key for signing
//   - targetNodeID: The peer node ID we want to connect to
func NewInitiator(
	fabricInfo *fabric.FabricInfo,
	operationalKey *crypto.P256KeyPair,
	targetNodeID uint64,
) *Session {
	// Derive IPK from epoch key and compressed fabric ID
	ipkSlice, _ := crypto.DeriveGroupOperationalKeyV1(fabricInfo.IPK[:], fabricInfo.CompressedFabricID[:])
	var ipk [crypto.SymmetricKeySize]byte
	copy(ipk[:], ipkSlice)

	return &Session{
		role:           RoleInitiator,
		state:          StateInit,
		fabricInfo:     fabricInfo,
		operationalKey: operationalKey,
		targetNodeID:   targetNodeID,
		ipk:            ipk,
		rand:           rand.Reader,
	}
}

// NewResponder creates a CASE session as responder.
//
// Parameters:
//   - fabricLookup: Function to find fabric by destination ID
//   - resumptionLookup: Function to find previous session for resumption (optional)
func NewResponder(
	fabricLookup FabricLookupFunc,
	resumptionLookup ResumptionLookupFunc,
) *Session {
	return &Session{
		role:             RoleResponder,
		state:            StateInit,
		fabricLookup:     fabricLookup,
		resumptionLookup: resumptionLookup,
		rand:             rand.Reader,
	}
}

// WithResumption adds resumption info for attempting session resumption.
// Only valid for initiator.
func (s *Session) WithResumption(info *ResumptionInfo) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resumptionInfo = info
	return s
}

// WithMRPParams sets local MRP parameters to advertise.
func (s *Session) WithMRPParams(params *MRPParameters) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localMRPParams = params
	return s
}

// WithCertValidator sets the certificate validation callback.
// This callback is called during handshake to validate the peer's certificate chain
// and extract the peer's node ID and public key for signature verification.
//
// If not set, certificate validation and signature verification are skipped.
// This is suitable for testing but MUST be set in production deployments.
func (s *Session) WithCertValidator(validator ValidatePeerCertChainFunc) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certValidator = validator
	return s
}

// Start begins the CASE handshake (initiator only).
// Returns the encoded Sigma1 message to send to the responder.
func (s *Session) Start(localSessionID uint16) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.role != RoleInitiator {
		return nil, fmt.Errorf("%w: Start() only valid for initiator", ErrInvalidState)
	}
	if s.state != StateInit {
		return nil, fmt.Errorf("%w: expected Init state, got %s", ErrInvalidState, s.state)
	}

	s.localSessionID = localSessionID

	// Generate random value
	if _, err := io.ReadFull(s.rand, s.localRandom[:]); err != nil {
		return nil, fmt.Errorf("failed to generate random: %w", err)
	}

	// Generate ephemeral key pair
	var err error
	s.ephKeyPair, err = crypto.P256GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Compute destination ID
	var rootPubKey [crypto.P256PublicKeySizeBytes]byte
	copy(rootPubKey[:], s.fabricInfo.RootPublicKey[:])

	destinationID := GenerateDestinationID(
		s.localRandom,
		rootPubKey,
		uint64(s.fabricInfo.FabricID),
		s.targetNodeID,
		s.ipk,
	)

	// Build Sigma1
	sigma1 := &Sigma1{
		InitiatorRandom:    s.localRandom,
		InitiatorSessionID: s.localSessionID,
		DestinationID:      destinationID,
		MRPParams:          s.localMRPParams,
	}
	copy(sigma1.InitiatorEphPubKey[:], s.ephKeyPair.P256PublicKey())

	// Add resumption fields if attempting resumption
	if s.resumptionInfo != nil {
		sigma1.ResumptionID = &s.resumptionInfo.ResumptionID

		// Derive S1RK and compute Resume1MIC
		s1rk, err := DeriveS1RK(s.resumptionInfo.SharedSecret, s.localRandom, s.resumptionInfo.ResumptionID)
		if err != nil {
			return nil, fmt.Errorf("failed to derive S1RK: %w", err)
		}

		mic, err := ComputeResumeMIC(s1rk, Resume1Nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to compute Resume1MIC: %w", err)
		}
		sigma1.InitiatorResumeMIC = &mic
	}

	// Encode Sigma1
	msg1Bytes, err := sigma1.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode Sigma1: %w", err)
	}
	s.msg1Bytes = msg1Bytes

	// Update state based on whether we're attempting resumption
	if s.resumptionInfo != nil {
		s.state = StateWaitingSigma2Resume
	} else {
		s.state = StateWaitingSigma2
	}

	return msg1Bytes, nil
}

// HandleSigma1 processes an incoming Sigma1 message (responder only).
// Returns the response (Sigma2 or Sigma2Resume) and whether resumption was used.
func (s *Session) HandleSigma1(data []byte, localSessionID uint16) (response []byte, isResumption bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.role != RoleResponder {
		return nil, false, fmt.Errorf("%w: HandleSigma1() only valid for responder", ErrInvalidState)
	}
	if s.state != StateInit {
		return nil, false, fmt.Errorf("%w: expected Init state, got %s", ErrInvalidState, s.state)
	}

	// Decode Sigma1
	sigma1, err := DecodeSigma1(data)
	if err != nil {
		return nil, false, fmt.Errorf("failed to decode Sigma1: %w", err)
	}

	// Validate: resumption fields must be both present or both absent
	hasResumptionID := sigma1.ResumptionID != nil
	hasResumeMIC := sigma1.InitiatorResumeMIC != nil
	if hasResumptionID != hasResumeMIC {
		return nil, false, ErrMissingResumptionField
	}

	s.msg1Bytes = data
	s.localSessionID = localSessionID
	s.peerSessionID = sigma1.InitiatorSessionID
	s.peerRandom = sigma1.InitiatorRandom
	s.peerMRPParams = sigma1.MRPParams
	copy(s.peerEphPubKey[:], sigma1.InitiatorEphPubKey[:])

	// Try resumption if fields are present
	if hasResumptionID && s.resumptionLookup != nil {
		sharedSecret, fabricInfo, operationalKey, ok := s.resumptionLookup(*sigma1.ResumptionID)
		if ok {
			// Derive S1RK and verify Resume1MIC
			s1rk, err := DeriveS1RK(sharedSecret, sigma1.InitiatorRandom, *sigma1.ResumptionID)
			if err == nil && VerifyResumeMIC(s1rk, Resume1Nonce, *sigma1.InitiatorResumeMIC) {
				// Resumption validated, generate Sigma2Resume
				s.fabricInfo = fabricInfo
				s.operationalKey = operationalKey
				s.sharedSecret = sharedSecret

				// Derive IPK
				ipkSlice, _ := crypto.DeriveGroupOperationalKeyV1(fabricInfo.IPK[:], fabricInfo.CompressedFabricID[:])
				copy(s.ipk[:], ipkSlice)

				return s.generateSigma2Resume(sigma1)
			}
		}
		// Resumption failed, fall through to full handshake
	}

	// Full handshake: look up fabric by destination ID
	fabricInfo, operationalKey, err := s.fabricLookup(sigma1.DestinationID, sigma1.InitiatorRandom)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrNoSharedRoot, err)
	}
	s.fabricInfo = fabricInfo
	s.operationalKey = operationalKey

	// Derive IPK
	ipkSlice, _ := crypto.DeriveGroupOperationalKeyV1(fabricInfo.IPK[:], fabricInfo.CompressedFabricID[:])
	copy(s.ipk[:], ipkSlice)

	// Generate Sigma2
	return s.generateSigma2(sigma1)
}

func (s *Session) generateSigma2(sigma1 *Sigma1) ([]byte, bool, error) {
	// Generate responder random
	if _, err := io.ReadFull(s.rand, s.localRandom[:]); err != nil {
		return nil, false, fmt.Errorf("failed to generate random: %w", err)
	}

	// Generate ephemeral key pair
	var err error
	s.ephKeyPair, err = crypto.P256GenerateKeyPair()
	if err != nil {
		return nil, false, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Generate new resumption ID
	if _, err := io.ReadFull(s.rand, s.newResumptionID[:]); err != nil {
		return nil, false, fmt.Errorf("failed to generate resumption ID: %w", err)
	}

	// Compute ECDH shared secret
	s.sharedSecret, err = crypto.P256ECDH(s.ephKeyPair, sigma1.InitiatorEphPubKey[:])
	if err != nil {
		return nil, false, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Get our ephemeral public key
	var responderEphPubKey [crypto.P256PublicKeySizeBytes]byte
	copy(responderEphPubKey[:], s.ephKeyPair.P256PublicKey())

	// Build TBSData2 and sign
	tbsData2 := &TBSData2{
		ResponderNOC:       s.fabricInfo.NOC,
		ResponderICAC:      s.fabricInfo.ICAC,
		ResponderEphPubKey: responderEphPubKey,
		InitiatorEphPubKey: sigma1.InitiatorEphPubKey,
	}
	tbsData2Bytes, err := tbsData2.Encode()
	if err != nil {
		return nil, false, fmt.Errorf("failed to encode TBSData2: %w", err)
	}

	signature, err := crypto.P256Sign(s.operationalKey, tbsData2Bytes)
	if err != nil {
		return nil, false, fmt.Errorf("failed to sign TBSData2: %w", err)
	}

	// Build TBEData2
	tbeData2 := &TBEData2{
		ResponderNOC:  s.fabricInfo.NOC,
		ResponderICAC: s.fabricInfo.ICAC,
		ResumptionID:  s.newResumptionID,
	}
	copy(tbeData2.Signature[:], signature)

	tbeData2Bytes, err := tbeData2.Encode()
	if err != nil {
		return nil, false, fmt.Errorf("failed to encode TBEData2: %w", err)
	}

	// Derive S2K and encrypt
	s2k, err := DeriveS2K(s.sharedSecret, s.ipk, s.localRandom, responderEphPubKey, s.msg1Bytes)
	if err != nil {
		return nil, false, fmt.Errorf("failed to derive S2K: %w", err)
	}

	encrypted2, err := EncryptTBEData(s2k, tbeData2Bytes, Sigma2Nonce, nil)
	if err != nil {
		return nil, false, fmt.Errorf("failed to encrypt TBEData2: %w", err)
	}

	// Build Sigma2
	sigma2 := &Sigma2{
		ResponderRandom:    s.localRandom,
		ResponderSessionID: s.localSessionID,
		ResponderEphPubKey: responderEphPubKey,
		Encrypted2:         encrypted2,
		MRPParams:          s.localMRPParams,
	}

	msg2Bytes, err := sigma2.Encode()
	if err != nil {
		return nil, false, fmt.Errorf("failed to encode Sigma2: %w", err)
	}
	s.msg2Bytes = msg2Bytes

	s.state = StateWaitingSigma3
	return msg2Bytes, false, nil
}

func (s *Session) generateSigma2Resume(sigma1 *Sigma1) ([]byte, bool, error) {
	// Generate new resumption ID
	if _, err := io.ReadFull(s.rand, s.newResumptionID[:]); err != nil {
		return nil, false, fmt.Errorf("failed to generate resumption ID: %w", err)
	}

	// Derive S2RK and compute Resume2MIC
	s2rk, err := DeriveS2RK(s.sharedSecret, sigma1.InitiatorRandom, s.newResumptionID)
	if err != nil {
		return nil, false, fmt.Errorf("failed to derive S2RK: %w", err)
	}

	resume2MIC, err := ComputeResumeMIC(s2rk, Resume2Nonce)
	if err != nil {
		return nil, false, fmt.Errorf("failed to compute Resume2MIC: %w", err)
	}

	// Build Sigma2Resume
	sigma2Resume := &Sigma2Resume{
		ResumptionID:       s.newResumptionID,
		Resume2MIC:         resume2MIC,
		ResponderSessionID: s.localSessionID,
		MRPParams:          s.localMRPParams,
	}

	msg2Bytes, err := sigma2Resume.Encode()
	if err != nil {
		return nil, false, fmt.Errorf("failed to encode Sigma2Resume: %w", err)
	}
	s.msg2Bytes = msg2Bytes
	s.usedResumption = true

	// Derive session keys immediately for resumption
	s.sessionKeys, err = DeriveResumptionSessionKeys(s.sharedSecret, s.ipk, s.msg1Bytes, s.msg2Bytes)
	if err != nil {
		return nil, false, fmt.Errorf("failed to derive session keys: %w", err)
	}

	s.state = StateComplete
	return msg2Bytes, true, nil
}

// HandleSigma2 processes an incoming Sigma2 message (initiator only).
// Returns the encoded Sigma3 message to send.
func (s *Session) HandleSigma2(data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.role != RoleInitiator {
		return nil, fmt.Errorf("%w: HandleSigma2() only valid for initiator", ErrInvalidState)
	}
	// Allow handling Sigma2 even if we were expecting Sigma2Resume (fallback)
	if s.state != StateWaitingSigma2 && s.state != StateWaitingSigma2Resume {
		return nil, fmt.Errorf("%w: expected WaitingSigma2 state, got %s", ErrInvalidState, s.state)
	}

	// Decode Sigma2
	sigma2, err := DecodeSigma2(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Sigma2: %w", err)
	}

	s.msg2Bytes = data
	s.peerSessionID = sigma2.ResponderSessionID
	s.peerRandom = sigma2.ResponderRandom
	s.peerMRPParams = sigma2.MRPParams
	copy(s.peerEphPubKey[:], sigma2.ResponderEphPubKey[:])

	// Compute ECDH shared secret
	s.sharedSecret, err = crypto.P256ECDH(s.ephKeyPair, sigma2.ResponderEphPubKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive S2K and decrypt TBEData2
	s2k, err := DeriveS2K(s.sharedSecret, s.ipk, sigma2.ResponderRandom, sigma2.ResponderEphPubKey, s.msg1Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive S2K: %w", err)
	}

	tbeData2Bytes, err := DecryptTBEData(s2k, sigma2.Encrypted2, Sigma2Nonce, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	tbeData2, err := DecodeTBEData2(tbeData2Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TBEData2: %w", err)
	}

	// Store peer certificate info
	s.peerNOC = tbeData2.ResponderNOC
	s.peerICAC = tbeData2.ResponderICAC
	s.newResumptionID = tbeData2.ResumptionID

	// Validate certificate chain and verify signature if validator is set
	if s.certValidator != nil {
		// Validate responder certificate chain against our trusted root
		peerCertInfo, err := s.certValidator(
			tbeData2.ResponderNOC,
			tbeData2.ResponderICAC,
			s.fabricInfo.RootPublicKey,
		)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
		}

		// Verify peer node ID matches target
		if peerCertInfo.NodeID != s.targetNodeID {
			return nil, fmt.Errorf("%w: peer node ID %d does not match target %d",
				ErrInvalidCertificate, peerCertInfo.NodeID, s.targetNodeID)
		}

		// Store validated peer node ID
		s.peerNodeID = peerCertInfo.NodeID

		// Verify TBSData2 signature using peer's public key
		var initiatorEphPubKey [crypto.P256PublicKeySizeBytes]byte
		copy(initiatorEphPubKey[:], s.ephKeyPair.P256PublicKey())

		tbsData2 := &TBSData2{
			ResponderNOC:       tbeData2.ResponderNOC,
			ResponderICAC:      tbeData2.ResponderICAC,
			ResponderEphPubKey: sigma2.ResponderEphPubKey,
			InitiatorEphPubKey: initiatorEphPubKey,
		}

		tbsData2Bytes, err := tbsData2.Encode()
		if err != nil {
			return nil, fmt.Errorf("failed to encode TBSData2 for verification: %w", err)
		}

		// Verify signature
		valid, err := crypto.P256Verify(peerCertInfo.PublicKey[:], tbsData2Bytes, tbeData2.Signature[:])
		if err != nil || !valid {
			return nil, fmt.Errorf("%w: TBSData2 signature verification failed", ErrSignatureInvalid)
		}
	}

	// Generate Sigma3
	return s.generateSigma3()
}

func (s *Session) generateSigma3() ([]byte, error) {
	// Get our ephemeral public key
	var initiatorEphPubKey [crypto.P256PublicKeySizeBytes]byte
	copy(initiatorEphPubKey[:], s.ephKeyPair.P256PublicKey())

	// Build TBSData3 and sign
	tbsData3 := &TBSData3{
		InitiatorNOC:       s.fabricInfo.NOC,
		InitiatorICAC:      s.fabricInfo.ICAC,
		InitiatorEphPubKey: initiatorEphPubKey,
		ResponderEphPubKey: s.peerEphPubKey,
	}
	tbsData3Bytes, err := tbsData3.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode TBSData3: %w", err)
	}

	signature, err := crypto.P256Sign(s.operationalKey, tbsData3Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to sign TBSData3: %w", err)
	}

	// Build TBEData3
	tbeData3 := &TBEData3{
		InitiatorNOC:  s.fabricInfo.NOC,
		InitiatorICAC: s.fabricInfo.ICAC,
	}
	copy(tbeData3.Signature[:], signature)

	tbeData3Bytes, err := tbeData3.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode TBEData3: %w", err)
	}

	// Derive S3K and encrypt
	s3k, err := DeriveS3K(s.sharedSecret, s.ipk, s.msg1Bytes, s.msg2Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive S3K: %w", err)
	}

	encrypted3, err := EncryptTBEData(s3k, tbeData3Bytes, Sigma3Nonce, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt TBEData3: %w", err)
	}

	// Build Sigma3
	sigma3 := &Sigma3{
		Encrypted3: encrypted3,
	}

	msg3Bytes, err := sigma3.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode Sigma3: %w", err)
	}
	s.msg3Bytes = msg3Bytes

	s.state = StateWaitingStatusReport
	return msg3Bytes, nil
}

// HandleSigma2Resume processes a Sigma2Resume message (initiator only, for resumption).
func (s *Session) HandleSigma2Resume(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.role != RoleInitiator {
		return fmt.Errorf("%w: HandleSigma2Resume() only valid for initiator", ErrInvalidState)
	}
	if s.state != StateWaitingSigma2Resume {
		return fmt.Errorf("%w: expected WaitingSigma2Resume state, got %s", ErrInvalidState, s.state)
	}
	if s.resumptionInfo == nil {
		return fmt.Errorf("%w: no resumption info available", ErrResumptionFailed)
	}

	// Decode Sigma2Resume
	sigma2Resume, err := DecodeSigma2Resume(data)
	if err != nil {
		return fmt.Errorf("failed to decode Sigma2Resume: %w", err)
	}

	s.msg2Bytes = data
	s.peerSessionID = sigma2Resume.ResponderSessionID
	s.peerMRPParams = sigma2Resume.MRPParams
	s.newResumptionID = sigma2Resume.ResumptionID

	// Use shared secret from previous session
	s.sharedSecret = s.resumptionInfo.SharedSecret

	// Verify Resume2MIC
	s2rk, err := DeriveS2RK(s.sharedSecret, s.localRandom, sigma2Resume.ResumptionID)
	if err != nil {
		return fmt.Errorf("failed to derive S2RK: %w", err)
	}

	if !VerifyResumeMIC(s2rk, Resume2Nonce, sigma2Resume.Resume2MIC) {
		return ErrInvalidResumeMIC
	}

	// Derive session keys
	s.sessionKeys, err = DeriveResumptionSessionKeys(s.sharedSecret, s.ipk, s.msg1Bytes, s.msg2Bytes)
	if err != nil {
		return fmt.Errorf("failed to derive session keys: %w", err)
	}

	s.usedResumption = true
	s.state = StateComplete
	return nil
}

// HandleSigma3 processes an incoming Sigma3 message (responder only).
// Returns true if handshake succeeded.
func (s *Session) HandleSigma3(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.role != RoleResponder {
		return fmt.Errorf("%w: HandleSigma3() only valid for responder", ErrInvalidState)
	}
	if s.state != StateWaitingSigma3 {
		return fmt.Errorf("%w: expected WaitingSigma3 state, got %s", ErrInvalidState, s.state)
	}

	// Decode Sigma3
	sigma3, err := DecodeSigma3(data)
	if err != nil {
		return fmt.Errorf("failed to decode Sigma3: %w", err)
	}

	s.msg3Bytes = data

	// Derive S3K and decrypt TBEData3
	s3k, err := DeriveS3K(s.sharedSecret, s.ipk, s.msg1Bytes, s.msg2Bytes)
	if err != nil {
		return fmt.Errorf("failed to derive S3K: %w", err)
	}

	tbeData3Bytes, err := DecryptTBEData(s3k, sigma3.Encrypted3, Sigma3Nonce, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	tbeData3, err := DecodeTBEData3(tbeData3Bytes)
	if err != nil {
		return fmt.Errorf("failed to decode TBEData3: %w", err)
	}

	// Store peer certificate info
	s.peerNOC = tbeData3.InitiatorNOC
	s.peerICAC = tbeData3.InitiatorICAC

	// Validate certificate chain and verify signature if validator is set
	if s.certValidator != nil {
		// Validate initiator certificate chain against our trusted root
		peerCertInfo, err := s.certValidator(
			tbeData3.InitiatorNOC,
			tbeData3.InitiatorICAC,
			s.fabricInfo.RootPublicKey,
		)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
		}

		// Verify fabric ID matches our fabric
		if peerCertInfo.FabricID != uint64(s.fabricInfo.FabricID) {
			return fmt.Errorf("%w: peer fabric ID %d does not match expected %d",
				ErrInvalidCertificate, peerCertInfo.FabricID, s.fabricInfo.FabricID)
		}

		// Store validated peer node ID
		s.peerNodeID = peerCertInfo.NodeID

		// Verify TBSData3 signature using peer's public key
		var responderEphPubKey [crypto.P256PublicKeySizeBytes]byte
		copy(responderEphPubKey[:], s.ephKeyPair.P256PublicKey())

		tbsData3 := &TBSData3{
			InitiatorNOC:       tbeData3.InitiatorNOC,
			InitiatorICAC:      tbeData3.InitiatorICAC,
			InitiatorEphPubKey: s.peerEphPubKey,
			ResponderEphPubKey: responderEphPubKey,
		}

		tbsData3Bytes, err := tbsData3.Encode()
		if err != nil {
			return fmt.Errorf("failed to encode TBSData3 for verification: %w", err)
		}

		// Verify signature
		valid, err := crypto.P256Verify(peerCertInfo.PublicKey[:], tbsData3Bytes, tbeData3.Signature[:])
		if err != nil || !valid {
			return fmt.Errorf("%w: TBSData3 signature verification failed", ErrSignatureInvalid)
		}
	}

	// Derive session keys
	s.sessionKeys, err = DeriveSessionKeys(s.sharedSecret, s.ipk, s.msg1Bytes, s.msg2Bytes, s.msg3Bytes)
	if err != nil {
		return fmt.Errorf("failed to derive session keys: %w", err)
	}

	s.state = StateComplete
	return nil
}

// HandleStatusReport processes the final status report (initiator only).
func (s *Session) HandleStatusReport(success bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.role != RoleInitiator {
		return fmt.Errorf("%w: HandleStatusReport() only valid for initiator", ErrInvalidState)
	}
	if s.state != StateWaitingStatusReport {
		return fmt.Errorf("%w: expected WaitingStatusReport state, got %s", ErrInvalidState, s.state)
	}

	if !success {
		s.state = StateFailed
		return ErrInvalidStatusReport
	}

	// Derive session keys
	var err error
	s.sessionKeys, err = DeriveSessionKeys(s.sharedSecret, s.ipk, s.msg1Bytes, s.msg2Bytes, s.msg3Bytes)
	if err != nil {
		return fmt.Errorf("failed to derive session keys: %w", err)
	}

	s.state = StateComplete
	return nil
}

// SessionKeys returns the derived session keys.
// Only valid after the session is complete.
func (s *Session) SessionKeys() (*SessionKeys, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != StateComplete {
		return nil, ErrSessionNotReady
	}
	return s.sessionKeys, nil
}

// State returns the current session state.
func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// LocalSessionID returns our session ID.
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

// UsedResumption returns whether session resumption was used.
func (s *Session) UsedResumption() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.usedResumption
}

// ResumptionID returns the new resumption ID for future session resumption.
func (s *Session) ResumptionID() [ResumptionIDSize]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.newResumptionID
}

// SharedSecret returns the ECDH shared secret (for resumption storage).
func (s *Session) SharedSecret() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret := make([]byte, len(s.sharedSecret))
	copy(secret, s.sharedSecret)
	return secret
}

// PeerMRPParams returns the peer's MRP parameters (if provided).
func (s *Session) PeerMRPParams() *MRPParameters {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerMRPParams
}
