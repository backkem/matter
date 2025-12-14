// Package casesession implements CASE (Certificate Authenticated Session Establishment).
//
// CASE is the Sigma protocol used to establish secure sessions between commissioned
// Matter nodes using operational certificates. It provides mutual authentication and
// key derivation for encrypted communication.
//
// The package supports:
//   - Full handshake: Sigma1 → Sigma2 → Sigma3 → StatusReport
//   - Session resumption: Sigma1 (with resumption) → Sigma2_Resume → StatusReport
//
// Spec References:
//   - Section 4.14.2: Certificate Authenticated Session Establishment (CASE)
//   - Section 4.14.2.3: Protocol Details (Sigma1/2/3 message flows)
//   - Section 4.14.2.4: Field Descriptions (Destination Identifier)
//   - Section 4.14.2.6: Key Derivation
package casesession

import (
	"errors"
)

// Size constants.
const (
	// RandomSize is the size of random values in CASE messages (32 bytes).
	RandomSize = 32

	// ResumptionIDSize is the size of the resumption ID (16 bytes).
	ResumptionIDSize = 16

	// MICSize is the AEAD MIC size (16 bytes).
	MICSize = 16

	// DestinationIDSize is the size of the destination identifier (32 bytes, SHA-256 output).
	DestinationIDSize = 32

	// SessionKeySize is the size of session encryption keys (16 bytes).
	SessionKeySize = 16
)

// AEAD nonces for CASE operations (13 bytes each).
var (
	// Sigma2Nonce is the nonce for TBEData2 encryption.
	Sigma2Nonce = []byte("NCASE_Sigma2N")

	// Sigma3Nonce is the nonce for TBEData3 encryption.
	Sigma3Nonce = []byte("NCASE_Sigma3N")

	// Resume1Nonce is the nonce for Sigma1 resumption MIC.
	Resume1Nonce = []byte("NCASE_SigmaS1")

	// Resume2Nonce is the nonce for Sigma2_Resume MIC.
	Resume2Nonce = []byte("NCASE_SigmaS2")
)

// Key derivation info strings.
var (
	// S2KInfo is the info string for Sigma2 key derivation.
	S2KInfo = []byte("Sigma2")

	// S3KInfo is the info string for Sigma3 key derivation.
	S3KInfo = []byte("Sigma3")

	// S1RKInfo is the info string for Sigma1 resumption key.
	S1RKInfo = []byte("Sigma1_Resume")

	// S2RKInfo is the info string for Sigma2 resumption key.
	S2RKInfo = []byte("Sigma2_Resume")

	// SEKeysInfo is the info string for session encryption keys.
	SEKeysInfo = []byte("SessionKeys")
)

// Role represents the CASE participant role.
type Role int

const (
	// RoleInitiator is the node initiating the CASE handshake.
	RoleInitiator Role = iota
	// RoleResponder is the node responding to the CASE handshake.
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

// State represents the CASE protocol state machine.
type State int

const (
	// StateInit is the initial state before handshake begins.
	StateInit State = iota
	// StateWaitingSigma2 means initiator sent Sigma1, waiting for Sigma2.
	StateWaitingSigma2
	// StateWaitingSigma2Resume means initiator sent Sigma1 with resumption, waiting for Sigma2_Resume.
	StateWaitingSigma2Resume
	// StateWaitingSigma3 means responder sent Sigma2, waiting for Sigma3.
	StateWaitingSigma3
	// StateWaitingStatusReport means initiator sent Sigma3, waiting for StatusReport.
	StateWaitingStatusReport
	// StateComplete means the session is established.
	StateComplete
	// StateFailed means the handshake failed.
	StateFailed
)

// String returns the state name.
func (s State) String() string {
	switch s {
	case StateInit:
		return "Init"
	case StateWaitingSigma2:
		return "WaitingSigma2"
	case StateWaitingSigma2Resume:
		return "WaitingSigma2Resume"
	case StateWaitingSigma3:
		return "WaitingSigma3"
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

// SessionKeys holds the derived session encryption keys.
type SessionKeys struct {
	// I2RKey encrypts messages from initiator to responder.
	I2RKey [SessionKeySize]byte

	// R2IKey encrypts messages from responder to initiator.
	R2IKey [SessionKeySize]byte

	// AttestationChallenge is used for attestation during commissioning.
	AttestationChallenge [SessionKeySize]byte
}

// ResumptionInfo stores state needed for session resumption.
type ResumptionInfo struct {
	// ResumptionID is the identifier for the previous session.
	ResumptionID [ResumptionIDSize]byte

	// SharedSecret is the ECDH shared secret from the previous session.
	SharedSecret []byte

	// PeerNodeID is the peer's operational node ID.
	PeerNodeID uint64

	// PeerCATs are the peer's CASE Authenticated Tags (optional).
	PeerCATs []uint32
}

// PeerCertInfo contains information extracted from a validated peer certificate chain.
type PeerCertInfo struct {
	// NodeID is the peer's operational node ID extracted from the NOC.
	NodeID uint64

	// FabricID is the fabric ID from the NOC.
	FabricID uint64

	// PublicKey is the peer's public key (65 bytes with 0x04 prefix).
	PublicKey [65]byte
}

// ValidatePeerCertChainFunc validates the peer's certificate chain.
// Called during CASE handshake to verify the peer's NOC chains to a trusted root.
//
// The callback should:
//  1. Parse the NOC (and ICAC if present) from Matter TLV format
//  2. Verify the certificate chain: NOC → ICAC (optional) → trusted root
//  3. Extract and return the node ID, fabric ID, and public key from the NOC
//
// Parameters:
//   - noc: Peer's Node Operational Certificate (Matter TLV encoded)
//   - icac: Peer's ICAC if present (nil if NOC chains directly to root)
//   - trustedRootPubKey: The expected root public key (65 bytes with 0x04 prefix)
//
// Returns PeerCertInfo with extracted fields, or error if validation fails.
type ValidatePeerCertChainFunc func(
	noc []byte,
	icac []byte,
	trustedRootPubKey [65]byte,
) (*PeerCertInfo, error)

// Errors returned by CASE operations.
var (
	// ErrInvalidState is returned when an operation is invalid for the current state.
	ErrInvalidState = errors.New("case: invalid state for operation")

	// ErrNoSharedRoot is returned when no shared trust root is found.
	ErrNoSharedRoot = errors.New("case: no shared trust roots")

	// ErrInvalidDestination is returned when destination ID validation fails.
	ErrInvalidDestination = errors.New("case: invalid destination identifier")

	// ErrInvalidCertificate is returned when certificate validation fails.
	ErrInvalidCertificate = errors.New("case: certificate validation failed")

	// ErrSignatureInvalid is returned when signature verification fails.
	ErrSignatureInvalid = errors.New("case: signature verification failed")

	// ErrDecryptionFailed is returned when AEAD decryption fails.
	ErrDecryptionFailed = errors.New("case: decryption failed")

	// ErrResumptionFailed is returned when session resumption fails.
	ErrResumptionFailed = errors.New("case: session resumption failed")

	// ErrInvalidResumeMIC is returned when resumption MIC verification fails.
	ErrInvalidResumeMIC = errors.New("case: invalid resumption MIC")

	// ErrInvalidMessage is returned when a message is malformed.
	ErrInvalidMessage = errors.New("case: invalid message format")

	// ErrInvalidRandom is returned when a random value has wrong size.
	ErrInvalidRandom = errors.New("case: invalid random size")

	// ErrMissingResumptionField is returned when resumption fields are incomplete.
	ErrMissingResumptionField = errors.New("case: resumption requires both resumptionID and initiatorResumeMIC")

	// ErrInvalidStatusReport is returned when status report indicates failure.
	ErrInvalidStatusReport = errors.New("case: received failure status report")

	// ErrSessionNotReady is returned when trying to get keys before session is complete.
	ErrSessionNotReady = errors.New("case: session not yet established")
)
