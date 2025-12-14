// Package pase implements Passcode-Authenticated Session Establishment (PASE).
//
// PASE establishes the first secure session between a Commissioner (initiator)
// and a Commissionee (responder) using a shared passcode. It uses the SPAKE2+
// protocol for password-authenticated key exchange.
//
// See Matter Specification Section 4.14.1.
//
// # Protocol Flow
//
// The PASE protocol consists of the following message exchange:
//
//	Initiator (Commissioner)              Responder (Commissionee)
//	------------------------              ------------------------
//	NewInitiator(passcode)                NewResponder(verifier)
//	                                      |
//	msg = Start()            ------>      HandleMessage(msg)
//	                         <------      msg (PBKDFParamResponse)
//	HandleMessage(msg)
//	                         ------>      HandleMessage(msg) [Pake1]
//	                         <------      msg (Pake2)
//	HandleMessage(msg)
//	                         ------>      HandleMessage(msg) [Pake3]
//	                         <------      msg (StatusReport)
//	HandleMessage(msg)
//	Complete!                             Complete!
//
// # Usage
//
// Initiator (Commissioner):
//
//	session, err := pase.NewInitiator(passcode, salt, iterations)
//	msg, err := session.Start()
//	// send msg, receive response
//	msg, err = session.HandleMessage(response)
//	// repeat until session.State() == StateComplete
//	keys := session.SessionKeys()
//
// Responder (Commissionee):
//
//	verifier, err := pase.GenerateVerifier(passcode, salt, iterations)
//	session, err := pase.NewResponder(verifier, salt, iterations)
//	// receive msg
//	response, err := session.HandleMessage(msg)
//	// send response, repeat until session.State() == StateComplete
//	keys := session.SessionKeys()
package pase

import (
	"errors"
)

// Protocol constants.
const (
	// ContextPrefix is the context string for SPAKE2+ transcript.
	// Note: It's "PAKE" not "PASE" per the C reference implementation.
	ContextPrefix = "CHIP PAKE V1 Commissioning"

	// RandomSize is the size of random values in PBKDF messages.
	RandomSize = 32

	// DefaultPasscodeID is the default passcode ID (always 0).
	DefaultPasscodeID = 0

	// SessionKeySize is the size of I2R/R2I keys.
	SessionKeySize = 16

	// AttestationChallengeSize is the size of the attestation challenge.
	AttestationChallengeSize = 16
)

// PBKDF parameter constraints (Section 3.9).
const (
	PBKDFMinSaltLength = 16
	PBKDFMaxSaltLength = 32
	PBKDFMinIterations = 1000
	PBKDFMaxIterations = 100000
)

// Errors.
var (
	ErrInvalidState        = errors.New("pase: invalid protocol state")
	ErrInvalidMessage      = errors.New("pase: invalid message")
	ErrInvalidPasscode     = errors.New("pase: invalid passcode")
	ErrInvalidSalt         = errors.New("pase: invalid salt length")
	ErrInvalidIterations   = errors.New("pase: invalid iteration count")
	ErrInvalidPasscodeID   = errors.New("pase: invalid passcode ID")
	ErrInvalidRandom       = errors.New("pase: invalid random value")
	ErrRandomMismatch      = errors.New("pase: initiator random mismatch")
	ErrConfirmationFailed  = errors.New("pase: key confirmation failed")
	ErrUnexpectedMessage   = errors.New("pase: unexpected message type")
	ErrSessionNotReady     = errors.New("pase: session not ready")
	ErrPeerBusy            = errors.New("pase: peer is busy")
	ErrInvalidStatusReport = errors.New("pase: invalid status report")
)

// SessionKeys contains the derived session encryption keys.
type SessionKeys struct {
	I2RKey               [SessionKeySize]byte          // Initiator-to-Responder key
	R2IKey               [SessionKeySize]byte          // Responder-to-Initiator key
	AttestationChallenge [AttestationChallengeSize]byte // For device attestation
}
