// Package spake2p implements the SPAKE2+ Password-Authenticated Key Exchange protocol.
//
// SPAKE2+ is an augmented PAKE protocol where only one party (the Prover) knows the
// password directly, while the other party (the Verifier) stores a registration record
// derived from the password.
//
// This implementation follows:
//   - RFC 9383: SPAKE2+, an Augmented PAKE Protocol
//   - Matter Specification Section 3.10: Password-Authenticated Key Exchange (PAKE)
//
// The ciphersuite is P256-SHA256-HKDF-HMAC as required by Matter.
//
// Protocol flow:
//
//	Prover (Commissioner)              Verifier (Commissionee)
//	-------------------                ---------------------
//	NewProver(w0, w1)                  NewVerifier(w0, L)
//	X = GenerateShare() ----X---->     ProcessPeerShare(X)
//	                    <---Y----      Y = GenerateShare()
//	ProcessPeerShare(Y)                confirmV = Confirmation()
//	                    <-confirmV--
//	VerifyPeerConfirmation(confirmV)
//	confirmP = Confirmation() --confirmP-->
//	                                   VerifyPeerConfirmation(confirmP)
//	Ke = SharedSecret()                Ke = SharedSecret()
package spake2p

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"github.com/backkem/matter/pkg/crypto"
)

// Protocol constants from Matter Specification Section 3.10.
const (
	// GroupSizeBytes is the size of a P-256 scalar (32 bytes).
	GroupSizeBytes = 32

	// PointSizeBytes is the size of an uncompressed P-256 point (65 bytes).
	PointSizeBytes = 65

	// HashSizeBytes is the SHA-256 output size (32 bytes).
	HashSizeBytes = 32

	// WsSizeBytes is the size of w0s/w1s from PBKDF2 (40 bytes = 32 + 8 for bias reduction).
	WsSizeBytes = 40
)

// M and N are the SPAKE2+ generator points for P-256.
// These are from Matter Specification Section 3.10 / RFC 9383 Section 4.
// Format: uncompressed point (0x04 || x || y).
var (
	// M is used by the Prover: X = x*P + w0*M
	pointM = mustDecodePoint([]byte{
		0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2, 0x99,
		0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f, 0x5f,
		0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65, 0xff, 0x02, 0xac, 0x8e, 0x5c, 0x7b,
		0xe0, 0x94, 0x19, 0xc7, 0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d, 0x20,
	})

	// N is used by the Verifier: Y = y*P + w0*N
	pointN = mustDecodePoint([]byte{
		0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77, 0x07,
		0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49, 0x07,
		0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68, 0xc6, 0x4d, 0x9b,
		0xd3, 0x60, 0x34, 0x80, 0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb, 0xe7,
	})

	// Serialized M and N for transcript
	pointMBytes = []byte{
		0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2, 0x99,
		0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f, 0x5f,
		0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65, 0xff, 0x02, 0xac, 0x8e, 0x5c, 0x7b,
		0xe0, 0x94, 0x19, 0xc7, 0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d, 0x20,
	}
	pointNBytes = []byte{
		0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77, 0x07,
		0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49, 0x07,
		0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68, 0xc6, 0x4d, 0x9b,
		0xd3, 0x60, 0x34, 0x80, 0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb, 0xe7,
	}
)

// p256 is the P-256 curve used for all operations.
var p256 = elliptic.P256()

// Role represents the SPAKE2+ participant role.
type Role int

const (
	// RoleProver is the commissioner/initiator who knows the password.
	RoleProver Role = iota
	// RoleVerifier is the commissionee/responder who has the registration record.
	RoleVerifier
)

// State represents the protocol state machine.
type state int

const (
	stateInit state = iota
	stateShareGenerated
	stateSharedSecretComputed
	stateConfirmed
)

// Errors
var (
	ErrInvalidW0Size       = errors.New("spake2p: w0 must be 32 bytes")
	ErrInvalidW1Size       = errors.New("spake2p: w1 must be 32 bytes")
	ErrInvalidLSize        = errors.New("spake2p: L must be 65 bytes (uncompressed point)")
	ErrInvalidShareSize    = errors.New("spake2p: share must be 65 bytes (uncompressed point)")
	ErrInvalidPointOnCurve = errors.New("spake2p: point is not on the curve")
	ErrInvalidState        = errors.New("spake2p: invalid protocol state for this operation")
	ErrConfirmationFailed  = errors.New("spake2p: key confirmation failed")
)

// SPAKE2P implements the SPAKE2+ protocol with P256-SHA256-HKDF-HMAC ciphersuite.
type SPAKE2P struct {
	role       Role
	context    []byte
	idProver   []byte
	idVerifier []byte

	// Secret inputs
	w0 *big.Int // Shared secret scalar
	w1 *big.Int // Prover only: second secret scalar
	L  *point   // Verifier only: L = w1*P

	// Protocol state
	myRandom  *big.Int // x (prover) or y (verifier)
	myShare   []byte   // X (prover) or Y (verifier)
	peerShare []byte   // Y (prover) or X (verifier)
	Z         []byte   // Shared DH value
	V         []byte   // Shared verification value

	// Derived keys (from SDK key schedule)
	Ka  []byte // Authentication key (first half of hash)
	Ke  []byte // Encryption key / shared secret (second half of hash)
	KcA []byte // Prover confirmation key
	KcB []byte // Verifier confirmation key

	state state
	rand  io.Reader // For testing: injectable random source
}

// point represents a point on P-256.
type point struct {
	x, y *big.Int
}

// NewProver creates a SPAKE2+ instance as the prover (commissioner/initiator).
//
// Parameters:
//   - context: Protocol context (e.g., hash of PBKDF parameters)
//   - idProver: Prover identity (may be empty)
//   - idVerifier: Verifier identity (may be empty)
//   - w0: 32-byte secret derived from password (w0s mod p)
//   - w1: 32-byte secret derived from password (w1s mod p)
func NewProver(context, idProver, idVerifier, w0, w1 []byte) (*SPAKE2P, error) {
	if len(w0) != GroupSizeBytes {
		return nil, ErrInvalidW0Size
	}
	if len(w1) != GroupSizeBytes {
		return nil, ErrInvalidW1Size
	}

	s := &SPAKE2P{
		role:       RoleProver,
		context:    copyBytes(context),
		idProver:   copyBytes(idProver),
		idVerifier: copyBytes(idVerifier),
		w0:         new(big.Int).SetBytes(w0),
		w1:         new(big.Int).SetBytes(w1),
		state:      stateInit,
		rand:       rand.Reader,
	}

	return s, nil
}

// NewVerifier creates a SPAKE2+ instance as the verifier (commissionee/responder).
//
// Parameters:
//   - context: Protocol context (e.g., hash of PBKDF parameters)
//   - idProver: Prover identity (may be empty)
//   - idVerifier: Verifier identity (may be empty)
//   - w0: 32-byte secret derived from password (w0s mod p)
//   - L: 65-byte uncompressed point L = w1*P
func NewVerifier(context, idProver, idVerifier, w0, L []byte) (*SPAKE2P, error) {
	if len(w0) != GroupSizeBytes {
		return nil, ErrInvalidW0Size
	}
	if len(L) != PointSizeBytes {
		return nil, ErrInvalidLSize
	}

	// Parse L
	Lpoint, err := decodePoint(L)
	if err != nil {
		return nil, err
	}

	s := &SPAKE2P{
		role:       RoleVerifier,
		context:    copyBytes(context),
		idProver:   copyBytes(idProver),
		idVerifier: copyBytes(idVerifier),
		w0:         new(big.Int).SetBytes(w0),
		L:          Lpoint,
		state:      stateInit,
		rand:       rand.Reader,
	}

	return s, nil
}

// GenerateShare generates this party's public share.
// For Prover: X = x*P + w0*M
// For Verifier: Y = y*P + w0*N
func (s *SPAKE2P) GenerateShare() ([]byte, error) {
	if s.state != stateInit {
		return nil, ErrInvalidState
	}

	// Generate random scalar
	myRandom, err := generateRandomScalar(s.rand)
	if err != nil {
		return nil, err
	}
	s.myRandom = myRandom

	// Compute share based on role
	var share *point
	if s.role == RoleProver {
		// X = x*P + w0*M
		share = computeShare(myRandom, s.w0, pointM)
	} else {
		// Y = y*P + w0*N
		share = computeShare(myRandom, s.w0, pointN)
	}

	s.myShare = encodePoint(share)
	s.state = stateShareGenerated

	return copyBytes(s.myShare), nil
}

// ProcessPeerShare processes the peer's public share and computes shared secrets.
// This computes Z, V, and derives all session keys.
func (s *SPAKE2P) ProcessPeerShare(peerShare []byte) error {
	if s.state != stateShareGenerated {
		return ErrInvalidState
	}
	if len(peerShare) != PointSizeBytes {
		return ErrInvalidShareSize
	}

	// Parse and validate peer's share
	peer, err := decodePoint(peerShare)
	if err != nil {
		return err
	}

	s.peerShare = copyBytes(peerShare)

	// Compute Z and V based on role
	if s.role == RoleProver {
		// Z = x*(Y - w0*N), V = w1*(Y - w0*N)
		// Note: P-256 has cofactor h=1, so no cofactor multiplication needed
		s.Z, s.V, err = s.computeProverSecrets(peer)
	} else {
		// Z = y*(X - w0*M), V = y*L
		s.Z, s.V, err = s.computeVerifierSecrets(peer)
	}
	if err != nil {
		return err
	}

	// Derive keys
	if err := s.deriveKeys(); err != nil {
		return err
	}

	s.state = stateSharedSecretComputed
	return nil
}

// Confirmation returns this party's key confirmation message.
// Prover: MAC(KcA, Y)
// Verifier: MAC(KcB, X)
func (s *SPAKE2P) Confirmation() ([]byte, error) {
	if s.state != stateSharedSecretComputed && s.state != stateConfirmed {
		return nil, ErrInvalidState
	}

	if s.role == RoleProver {
		// Prover confirms with KcA over verifier's share (Y)
		return hmacSHA256(s.KcA, s.peerShare), nil
	}
	// Verifier confirms with KcB over prover's share (X)
	return hmacSHA256(s.KcB, s.peerShare), nil
}

// VerifyPeerConfirmation verifies the peer's key confirmation message.
func (s *SPAKE2P) VerifyPeerConfirmation(peerConfirm []byte) error {
	if s.state != stateSharedSecretComputed && s.state != stateConfirmed {
		return ErrInvalidState
	}

	var expected []byte
	if s.role == RoleProver {
		// Prover expects KcB over prover's share (X)
		expected = hmacSHA256(s.KcB, s.myShare)
	} else {
		// Verifier expects KcA over verifier's share (Y)
		expected = hmacSHA256(s.KcA, s.myShare)
	}

	if !hmac.Equal(expected, peerConfirm) {
		return ErrConfirmationFailed
	}

	s.state = stateConfirmed
	return nil
}

// SharedSecret returns the established shared secret (Ke).
// This should only be called after successful key confirmation.
func (s *SPAKE2P) SharedSecret() []byte {
	return copyBytes(s.Ke)
}

// computeProverSecrets computes Z and V for the prover.
// Z = x*(Y - w0*N), V = w1*(Y - w0*N)
func (s *SPAKE2P) computeProverSecrets(Y *point) ([]byte, []byte, error) {
	// Compute Y - w0*N
	w0N := scalarMult(pointN, s.w0)
	YminusW0N := pointSub(Y, w0N)

	// Z = x * (Y - w0*N)
	Z := scalarMult(YminusW0N, s.myRandom)

	// V = w1 * (Y - w0*N)
	V := scalarMult(YminusW0N, s.w1)

	return encodePoint(Z), encodePoint(V), nil
}

// computeVerifierSecrets computes Z and V for the verifier.
// Z = y*(X - w0*M), V = y*L
func (s *SPAKE2P) computeVerifierSecrets(X *point) ([]byte, []byte, error) {
	// Compute X - w0*M
	w0M := scalarMult(pointM, s.w0)
	XminusW0M := pointSub(X, w0M)

	// Z = y * (X - w0*M)
	Z := scalarMult(XminusW0M, s.myRandom)

	// V = y * L
	V := scalarMult(s.L, s.myRandom)

	return encodePoint(Z), encodePoint(V), nil
}

// deriveKeys derives Ka, Ke, KcA, KcB from the transcript.
func (s *SPAKE2P) deriveKeys() error {
	// Build transcript TT
	tt := s.buildTranscript()

	// Hash transcript: Kae = SHA256(TT)
	Kae := sha256.Sum256(tt)

	// Split Kae into Ka (first 16 bytes) and Ke (last 16 bytes)
	s.Ka = make([]byte, 16)
	s.Ke = make([]byte, 16)
	copy(s.Ka, Kae[:16])
	copy(s.Ke, Kae[16:])

	// Derive confirmation keys: KcA || KcB = HKDF(Ka, nil, "ConfirmationKeys", 32)
	info := []byte("ConfirmationKeys")
	Kcab, err := crypto.HKDFSHA256(s.Ka, nil, info, 32)
	if err != nil {
		return err
	}

	s.KcA = make([]byte, 16)
	s.KcB = make([]byte, 16)
	copy(s.KcA, Kcab[:16])
	copy(s.KcB, Kcab[16:])

	return nil
}

// buildTranscript builds the protocol transcript TT.
// TT = len(Context) || Context
//
//	|| len(idProver) || idProver
//	|| len(idVerifier) || idVerifier
//	|| len(M) || M
//	|| len(N) || N
//	|| len(X) || X
//	|| len(Y) || Y
//	|| len(Z) || Z
//	|| len(V) || V
//	|| len(w0) || w0
func (s *SPAKE2P) buildTranscript() []byte {
	var X, Y []byte
	if s.role == RoleProver {
		X = s.myShare
		Y = s.peerShare
	} else {
		X = s.peerShare
		Y = s.myShare
	}

	// Serialize w0 as 32 bytes
	w0Bytes := make([]byte, GroupSizeBytes)
	s.w0.FillBytes(w0Bytes)

	// Build transcript with 8-byte little-endian length prefixes
	var tt []byte
	tt = appendWithLen64(tt, s.context)
	tt = appendWithLen64(tt, s.idProver)
	tt = appendWithLen64(tt, s.idVerifier)
	tt = appendWithLen64(tt, pointMBytes)
	tt = appendWithLen64(tt, pointNBytes)
	tt = appendWithLen64(tt, X)
	tt = appendWithLen64(tt, Y)
	tt = appendWithLen64(tt, s.Z)
	tt = appendWithLen64(tt, s.V)
	tt = appendWithLen64(tt, w0Bytes)

	return tt
}

// appendWithLen64 appends data with an 8-byte little-endian length prefix.
func appendWithLen64(dst, data []byte) []byte {
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(data)))
	dst = append(dst, lenBuf[:]...)
	dst = append(dst, data...)
	return dst
}

// Point operations

func mustDecodePoint(data []byte) *point {
	p, err := decodePoint(data)
	if err != nil {
		panic(err)
	}
	return p
}

func decodePoint(data []byte) (*point, error) {
	if len(data) != PointSizeBytes {
		return nil, ErrInvalidShareSize
	}
	if data[0] != 0x04 {
		return nil, ErrInvalidPointOnCurve
	}

	x := new(big.Int).SetBytes(data[1:33])
	y := new(big.Int).SetBytes(data[33:65])

	if !p256.IsOnCurve(x, y) {
		return nil, ErrInvalidPointOnCurve
	}

	return &point{x: x, y: y}, nil
}

func encodePoint(p *point) []byte {
	result := make([]byte, PointSizeBytes)
	result[0] = 0x04
	p.x.FillBytes(result[1:33])
	p.y.FillBytes(result[33:65])
	return result
}

func scalarMult(p *point, k *big.Int) *point {
	x, y := p256.ScalarMult(p.x, p.y, k.Bytes())
	return &point{x: x, y: y}
}

func pointAdd(p1, p2 *point) *point {
	x, y := p256.Add(p1.x, p1.y, p2.x, p2.y)
	return &point{x: x, y: y}
}

func pointSub(p1, p2 *point) *point {
	// Negate p2: (x, -y) on the curve
	negY := new(big.Int).Neg(p2.y)
	negY.Mod(negY, p256.Params().P)
	x, y := p256.Add(p1.x, p1.y, p2.x, negY)
	return &point{x: x, y: y}
}

// computeShare computes share = random*P + w0*generator
func computeShare(random, w0 *big.Int, generator *point) *point {
	// random * P (base point)
	rP_x, rP_y := p256.ScalarBaseMult(random.Bytes())
	rP := &point{x: rP_x, y: rP_y}

	// w0 * generator
	w0G := scalarMult(generator, w0)

	// Add them
	return pointAdd(rP, w0G)
}

func generateRandomScalar(r io.Reader) (*big.Int, error) {
	n := p256.Params().N
	for {
		b := make([]byte, GroupSizeBytes)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		k := new(big.Int).SetBytes(b)
		// Ensure 0 < k < n
		if k.Sign() > 0 && k.Cmp(n) < 0 {
			return k, nil
		}
	}
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

// SetRandom sets the random source for testing purposes.
// This should only be used in tests to inject deterministic random values.
func (s *SPAKE2P) SetRandom(r io.Reader) {
	s.rand = r
}
