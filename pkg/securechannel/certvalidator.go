package securechannel

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/backkem/matter/pkg/credentials"
	casesession "github.com/backkem/matter/pkg/securechannel/case"
)

// Certificate validation errors.
var (
	ErrCertificateParseFailed  = errors.New("securechannel: failed to parse certificate")
	ErrCertificateTypeMismatch = errors.New("securechannel: certificate type mismatch")
	ErrCertificateExpired      = errors.New("securechannel: certificate expired")
	ErrCertificateNotYetValid  = errors.New("securechannel: certificate not yet valid")
	ErrCertificateChainBroken  = errors.New("securechannel: certificate chain validation failed")
	ErrSignatureVerifyFailed   = errors.New("securechannel: signature verification failed")
	ErrPublicKeyMismatch       = errors.New("securechannel: root public key mismatch")
	ErrMissingNodeID           = errors.New("securechannel: NOC missing node ID")
	ErrMissingFabricID         = errors.New("securechannel: NOC missing fabric ID")
	ErrFabricIDMismatch        = errors.New("securechannel: fabric ID mismatch in certificate chain")
)

// NewCertValidator creates a ValidatePeerCertChainFunc that uses pkg/credentials
// to parse and validate certificates.
//
// This validator:
//  1. Parses the NOC (and ICAC if present) from Matter TLV format
//  2. Verifies the certificate signatures form a valid chain
//  3. Validates certificate types (NOC → ICAC → RCAC)
//  4. Checks certificate validity periods
//  5. Extracts and returns the peer's node ID, fabric ID, and public key
//
// The trustedRootPubKey parameter must be the expected RCAC public key (65 bytes).
func NewCertValidator() casesession.ValidatePeerCertChainFunc {
	return func(nocBytes []byte, icacBytes []byte, trustedRootPubKey [65]byte) (*casesession.PeerCertInfo, error) {
		// 1. Parse NOC
		noc, err := credentials.DecodeTLV(nocBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: NOC: %v", ErrCertificateParseFailed, err)
		}

		// 2. Verify NOC is actually a NOC
		if noc.Type() != credentials.CertTypeNOC {
			return nil, fmt.Errorf("%w: expected NOC, got %s", ErrCertificateTypeMismatch, noc.Type())
		}

		// 3. Parse ICAC if present
		var icac *credentials.Certificate
		if len(icacBytes) > 0 {
			icac, err = credentials.DecodeTLV(icacBytes)
			if err != nil {
				return nil, fmt.Errorf("%w: ICAC: %v", ErrCertificateParseFailed, err)
			}

			// Verify ICAC is actually an ICAC
			if icac.Type() != credentials.CertTypeICAC {
				return nil, fmt.Errorf("%w: expected ICAC, got %s", ErrCertificateTypeMismatch, icac.Type())
			}
		}

		// 4. Validate certificate chain
		if err := validateCertChain(noc, icac, trustedRootPubKey); err != nil {
			return nil, err
		}

		// 5. Validate validity periods
		now := time.Now()
		if err := validateCertTime(noc, now); err != nil {
			return nil, fmt.Errorf("NOC: %w", err)
		}
		if icac != nil {
			if err := validateCertTime(icac, now); err != nil {
				return nil, fmt.Errorf("ICAC: %w", err)
			}
		}

		// 6. Extract peer info from NOC
		nodeID := noc.NodeID()
		if nodeID == 0 {
			return nil, ErrMissingNodeID
		}

		fabricID := noc.FabricID()
		if fabricID == 0 {
			return nil, ErrMissingFabricID
		}

		// 7. Extract public key
		var pubKey [65]byte
		if len(noc.ECPubKey) != 65 {
			return nil, fmt.Errorf("%w: invalid public key length %d", ErrCertificateParseFailed, len(noc.ECPubKey))
		}
		copy(pubKey[:], noc.ECPubKey)

		return &casesession.PeerCertInfo{
			NodeID:    nodeID,
			FabricID:  fabricID,
			PublicKey: pubKey,
		}, nil
	}
}

// validateCertChain validates the certificate chain: NOC → ICAC (optional) → RCAC.
// The trustedRootPubKey is the expected RCAC public key.
func validateCertChain(noc, icac *credentials.Certificate, trustedRootPubKey [65]byte) error {
	// Determine the signing key for NOC
	var nocSignerPubKey [65]byte

	if icac != nil {
		// NOC should be signed by ICAC
		copy(nocSignerPubKey[:], icac.ECPubKey)

		// ICAC should be signed by RCAC (trustedRootPubKey)
		if err := verifySignature(icac, trustedRootPubKey); err != nil {
			return fmt.Errorf("ICAC signature: %w", err)
		}

		// Verify fabric IDs match
		nocFabricID := noc.FabricID()
		icacFabricID := icac.FabricID()
		if icacFabricID != 0 && nocFabricID != icacFabricID {
			return ErrFabricIDMismatch
		}
	} else {
		// NOC should be signed directly by RCAC
		nocSignerPubKey = trustedRootPubKey
	}

	// Verify NOC signature
	if err := verifySignature(noc, nocSignerPubKey); err != nil {
		return fmt.Errorf("NOC signature: %w", err)
	}

	return nil
}

// verifySignature verifies that the certificate was signed by the given public key.
func verifySignature(cert *credentials.Certificate, signerPubKey [65]byte) error {
	// Parse the public key
	pubKey, err := parseP256PublicKey(signerPubKey[:])
	if err != nil {
		return fmt.Errorf("parse signer key: %w", err)
	}

	// Get the TBS (to-be-signed) data - certificate without signature
	tbsData, err := getTBSData(cert)
	if err != nil {
		return fmt.Errorf("get TBS data: %w", err)
	}

	// Hash the TBS data
	hash := sha256.Sum256(tbsData)

	// Parse the signature (raw r||s format, 64 bytes)
	if len(cert.Signature) != 64 {
		return fmt.Errorf("invalid signature length: %d", len(cert.Signature))
	}

	r := new(big.Int).SetBytes(cert.Signature[:32])
	s := new(big.Int).SetBytes(cert.Signature[32:])

	// Verify
	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return ErrSignatureVerifyFailed
	}

	return nil
}

// parseP256PublicKey parses an uncompressed P-256 public key (65 bytes with 0x04 prefix).
func parseP256PublicKey(data []byte) (*ecdsa.PublicKey, error) {
	if len(data) != 65 || data[0] != 0x04 {
		return nil, fmt.Errorf("invalid uncompressed public key")
	}

	x := new(big.Int).SetBytes(data[1:33])
	y := new(big.Int).SetBytes(data[33:65])

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

// getTBSData returns the TBS (to-be-signed) portion of the certificate.
// This is the certificate without the signature field.
func getTBSData(cert *credentials.Certificate) ([]byte, error) {
	// Create a copy of the certificate without signature
	tbsCert := &credentials.Certificate{
		SerialNum:  cert.SerialNum,
		SigAlgo:    cert.SigAlgo,
		Issuer:     cert.Issuer,
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		Subject:    cert.Subject,
		PubKeyAlgo: cert.PubKeyAlgo,
		ECCurveID:  cert.ECCurveID,
		ECPubKey:   cert.ECPubKey,
		Extensions: cert.Extensions,
		// Signature omitted
	}

	// Encode to TLV
	var buf bytes.Buffer
	// We need to encode just the structure without the signature
	// For Matter certificates, the TBS data is the structure up to but not including tag 11 (signature)
	tlvBytes, err := tbsCert.EncodeTLV()
	if err != nil {
		return nil, err
	}

	// The TBS data needs the signature removed
	// For proper implementation, we should use a custom encoder that stops at signature
	// For now, we return the full cert encoding minus the signature at the end
	buf.Write(tlvBytes)

	return buf.Bytes(), nil
}

// validateCertTime validates the certificate's validity period.
func validateCertTime(cert *credentials.Certificate, now time.Time) error {
	notBefore := cert.NotBeforeTime()
	if now.Before(notBefore) {
		return ErrCertificateNotYetValid
	}

	notAfter := cert.NotAfterTime()
	// Zero time means no expiration
	if !notAfter.IsZero() && now.After(notAfter) {
		return ErrCertificateExpired
	}

	return nil
}

// NewSkipCertValidator creates a validator that skips certificate validation.
// This is for testing only and should NEVER be used in production.
func NewSkipCertValidator() casesession.ValidatePeerCertChainFunc {
	return func(nocBytes []byte, icacBytes []byte, trustedRootPubKey [65]byte) (*casesession.PeerCertInfo, error) {
		// Parse NOC to extract info, but don't validate signatures
		noc, err := credentials.DecodeTLV(nocBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: NOC: %v", ErrCertificateParseFailed, err)
		}

		nodeID := noc.NodeID()
		if nodeID == 0 {
			nodeID = 1 // Default for testing
		}

		fabricID := noc.FabricID()
		if fabricID == 0 {
			fabricID = 1 // Default for testing
		}

		var pubKey [65]byte
		if len(noc.ECPubKey) == 65 {
			copy(pubKey[:], noc.ECPubKey)
		}

		return &casesession.PeerCertInfo{
			NodeID:    nodeID,
			FabricID:  fabricID,
			PublicKey: pubKey,
		}, nil
	}
}
