package pase

import (
	"crypto/elliptic"
	"encoding/binary"
	"math/big"

	"github.com/backkem/matter/pkg/crypto"
	"github.com/backkem/matter/pkg/crypto/spake2p"
)

// Verifier contains the PASE verifier values derived from a passcode.
// This is stored by the commissionee (responder) and used to verify
// the commissioner (initiator) knows the correct passcode.
type Verifier struct {
	W0 []byte // 32 bytes, w0s mod p
	L  []byte // 65 bytes, L = w1*P (uncompressed point)
}

// GenerateVerifier creates a PASE verifier from a passcode.
//
// This implements the verifier generation per Matter Specification Section 3.10:
//  1. ws = PBKDF2-SHA256(passcode_le, salt, iterations, 80)
//  2. w0s = ws[0:40], w1s = ws[40:80]
//  3. w0 = w0s mod p, w1 = w1s mod p
//  4. L = w1 * P (base point multiplication)
//
// Parameters:
//   - passcode: 8-digit setup code (27-bit value, 0-99999999)
//   - salt: Random salt (16-32 bytes)
//   - iterations: PBKDF2 iteration count (1000-100000)
//
// Returns the Verifier containing W0 and L.
func GenerateVerifier(passcode uint32, salt []byte, iterations uint32) (*Verifier, error) {
	if err := ValidatePasscode(passcode); err != nil {
		return nil, err
	}
	if err := validatePBKDFParams(salt, iterations); err != nil {
		return nil, err
	}

	// Compute w0 and w1
	w0, w1, err := ComputeW0W1(passcode, salt, iterations)
	if err != nil {
		return nil, err
	}

	// Compute L = w1 * P
	L, err := computeL(w1)
	if err != nil {
		return nil, err
	}

	return &Verifier{
		W0: w0,
		L:  L,
	}, nil
}

// ComputeW0W1 derives w0 and w1 from passcode using PBKDF2.
//
// This is used by both the initiator (commissioner) who knows the passcode
// and during verifier generation.
//
// Per Spec 3.10:
//
//	ws = PBKDF2(passcode_le, salt, iterations, 80)
//	w0s = ws[0:40], w1s = ws[40:80]
//	w0 = w0s mod p, w1 = w1s mod p
//
// Returns w0 and w1 as 32-byte scalars.
func ComputeW0W1(passcode uint32, salt []byte, iterations uint32) (w0, w1 []byte, err error) {
	// Encode passcode as little-endian 4 bytes (per C reference)
	passcodeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(passcodeBytes, passcode)

	// PBKDF2 to get 80 bytes: w0s (40) || w1s (40)
	ws := crypto.PBKDF2SHA256(passcodeBytes, salt, int(iterations), 2*spake2p.WsSizeBytes)

	// Split into w0s and w1s
	w0s := ws[:spake2p.WsSizeBytes]
	w1s := ws[spake2p.WsSizeBytes:]

	// Reduce mod p to get 32-byte scalars
	w0 = reduceModP(w0s)
	w1 = reduceModP(w1s)

	return w0, w1, nil
}

// p256 is the P-256 curve for point operations.
var p256 = elliptic.P256()

// reduceModP reduces a 40-byte value modulo the curve order p.
// This implements the bias-resistant reduction from RFC 9383.
func reduceModP(ws []byte) []byte {
	// Interpret ws as big-endian integer
	wsInt := new(big.Int).SetBytes(ws)

	// Reduce modulo curve order
	n := p256.Params().N
	wsInt.Mod(wsInt, n)

	// Return as fixed 32-byte big-endian
	result := make([]byte, spake2p.GroupSizeBytes)
	wsInt.FillBytes(result)
	return result
}

// computeL computes L = w1 * P (base point multiplication).
func computeL(w1 []byte) ([]byte, error) {
	// Scalar multiplication with base point
	x, y := p256.ScalarBaseMult(w1)

	// Encode as uncompressed point
	L := make([]byte, spake2p.PointSizeBytes)
	L[0] = 0x04
	x.FillBytes(L[1:33])
	y.FillBytes(L[33:65])

	return L, nil
}

// ValidatePasscode checks if a passcode is valid per Section 5.1.7.
//
// Invalid values are:
//   - 00000000, 11111111, 22222222, ..., 99999999 (all same digit)
//   - 12345678, 87654321 (sequential)
//   - Values >= 100000000 (more than 8 digits)
func ValidatePasscode(passcode uint32) error {
	// Must be at most 8 digits (27 bits, max 99999999)
	if passcode > 99999999 {
		return ErrInvalidPasscode
	}

	// Check for invalid patterns
	invalidPasscodes := []uint32{
		00000000, 11111111, 22222222, 33333333, 44444444,
		55555555, 66666666, 77777777, 88888888, 99999999,
		12345678, 87654321,
	}

	for _, invalid := range invalidPasscodes {
		if passcode == invalid {
			return ErrInvalidPasscode
		}
	}

	return nil
}

// validatePBKDFParams validates salt length and iteration count.
func validatePBKDFParams(salt []byte, iterations uint32) error {
	if len(salt) < PBKDFMinSaltLength || len(salt) > PBKDFMaxSaltLength {
		return ErrInvalidSalt
	}
	if iterations < PBKDFMinIterations || iterations > PBKDFMaxIterations {
		return ErrInvalidIterations
	}
	return nil
}

// Serialize returns the verifier as a concatenation of W0 and L (97 bytes).
func (v *Verifier) Serialize() []byte {
	result := make([]byte, spake2p.GroupSizeBytes+spake2p.PointSizeBytes)
	copy(result[:spake2p.GroupSizeBytes], v.W0)
	copy(result[spake2p.GroupSizeBytes:], v.L)
	return result
}

// DeserializeVerifier parses a serialized verifier.
func DeserializeVerifier(data []byte) (*Verifier, error) {
	expected := spake2p.GroupSizeBytes + spake2p.PointSizeBytes
	if len(data) != expected {
		return nil, ErrInvalidMessage
	}

	v := &Verifier{
		W0: make([]byte, spake2p.GroupSizeBytes),
		L:  make([]byte, spake2p.PointSizeBytes),
	}
	copy(v.W0, data[:spake2p.GroupSizeBytes])
	copy(v.L, data[spake2p.GroupSizeBytes:])

	return v, nil
}
