package fabric

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/backkem/matter/pkg/credentials"
)

// Validation errors.
var (
	// ErrInvalidCertificate is returned when a certificate cannot be parsed.
	ErrInvalidCertificate = errors.New("fabric: invalid certificate")
	// ErrMissingFabricID is returned when the fabric ID is missing from a certificate.
	ErrMissingFabricID = errors.New("fabric: missing fabric ID in certificate")
	// ErrMissingNodeID is returned when the node ID is missing from an NOC.
	ErrMissingNodeID = errors.New("fabric: missing node ID in NOC")
	// ErrInvalidNodeID is returned when the node ID is not a valid operational node ID.
	ErrInvalidNodeID = errors.New("fabric: invalid operational node ID")
	// ErrFabricIDMismatch is returned when fabric IDs don't match in the chain.
	ErrFabricIDMismatch = errors.New("fabric: fabric ID mismatch in certificate chain")
	// ErrInvalidCertificateType is returned when a certificate has an unexpected type.
	ErrInvalidCertificateType = errors.New("fabric: invalid certificate type")
	// ErrChainValidationFailed is returned when certificate chain validation fails.
	ErrChainValidationFailed = errors.New("fabric: certificate chain validation failed")
	// ErrMissingRootPublicKey is returned when the root public key is invalid.
	ErrMissingRootPublicKey = errors.New("fabric: missing or invalid root public key")
)

// ParseCertificate parses a Matter TLV-encoded certificate.
func ParseCertificate(certTLV []byte) (*credentials.Certificate, error) {
	if len(certTLV) == 0 {
		return nil, ErrInvalidCertificate
	}
	cert, err := credentials.DecodeTLV(certTLV)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}
	return cert, nil
}

// ExtractFabricID extracts the fabric ID from a certificate's subject DN.
// Returns ErrMissingFabricID if the fabric ID is not present.
//
// Note: Fabric ID is REQUIRED in NOC certificates but OPTIONAL in ICAC and RCAC.
// Use ExtractFabricIDOptional for ICAC/RCAC where absence is acceptable.
func ExtractFabricID(cert *credentials.Certificate) (FabricID, error) {
	fid := cert.FabricID()
	if fid == 0 {
		return 0, ErrMissingFabricID
	}
	return FabricID(fid), nil
}

// ExtractFabricIDOptional extracts the fabric ID from a certificate's subject DN.
// Returns (0, false) if the fabric ID is not present (which is valid for ICAC/RCAC).
// Returns (fabricID, true) if the fabric ID is present.
func ExtractFabricIDOptional(cert *credentials.Certificate) (FabricID, bool) {
	fid := cert.FabricID()
	if fid == 0 {
		return 0, false
	}
	return FabricID(fid), true
}

// ExtractNodeID extracts the node ID from an NOC's subject DN.
func ExtractNodeID(cert *credentials.Certificate) (NodeID, error) {
	if cert.Type() != credentials.CertTypeNOC {
		return 0, ErrInvalidCertificateType
	}
	nid := cert.NodeID()
	if nid == 0 {
		return 0, ErrMissingNodeID
	}
	nodeID := NodeID(nid)
	if !nodeID.IsOperational() {
		return 0, fmt.Errorf("%w: 0x%016X", ErrInvalidNodeID, nid)
	}
	return nodeID, nil
}

// ExtractRootPublicKey extracts the 65-byte uncompressed public key from an RCAC.
func ExtractRootPublicKey(cert *credentials.Certificate) ([RootPublicKeySize]byte, error) {
	var key [RootPublicKeySize]byte
	if len(cert.ECPubKey) != RootPublicKeySize {
		return key, fmt.Errorf("%w: got %d bytes", ErrMissingRootPublicKey, len(cert.ECPubKey))
	}
	copy(key[:], cert.ECPubKey)
	return key, nil
}

// ValidateNOCChain validates an NOC certificate chain.
//
// This function validates:
// - All certificates can be parsed
// - Certificate types are correct (RCAC -> ICAC (optional) -> NOC)
// - Fabric IDs are consistent across the chain
// - Node ID is valid for the NOC
// - Issuer/Subject relationships match (via Authority/Subject Key ID)
//
// Fabric ID handling (matching C reference implementation):
// - NOC: Fabric ID is REQUIRED
// - ICAC: Fabric ID is OPTIONAL - if present, must match NOC's fabric ID
// - RCAC: Fabric ID is OPTIONAL - if present, must match NOC's fabric ID
//
// Note: This does NOT verify cryptographic signatures. For full signature
// verification, use crypto.VerifyChain() or x509 verification.
func ValidateNOCChain(rootCertTLV, nocTLV, icacTLV []byte) error {
	// Parse root certificate
	rootCert, err := ParseCertificate(rootCertTLV)
	if err != nil {
		return fmt.Errorf("root certificate: %w", err)
	}
	if rootCert.Type() != credentials.CertTypeRCAC {
		return fmt.Errorf("root certificate: %w: expected RCAC, got %s",
			ErrInvalidCertificateType, rootCert.Type())
	}

	// Parse NOC
	nocCert, err := ParseCertificate(nocTLV)
	if err != nil {
		return fmt.Errorf("NOC: %w", err)
	}
	if nocCert.Type() != credentials.CertTypeNOC {
		return fmt.Errorf("NOC: %w: expected NOC, got %s",
			ErrInvalidCertificateType, nocCert.Type())
	}

	// Extract fabric ID and node ID from NOC (required)
	nocFabricID, err := ExtractFabricID(nocCert)
	if err != nil {
		return fmt.Errorf("NOC: %w", err)
	}
	_, err = ExtractNodeID(nocCert)
	if err != nil {
		return fmt.Errorf("NOC: %w", err)
	}

	// Check RCAC fabric ID if present (optional in RCAC)
	if rcacFabricID, found := ExtractFabricIDOptional(rootCert); found {
		if rcacFabricID != nocFabricID {
			return fmt.Errorf("RCAC: %w: RCAC fabric ID (0x%X) != NOC fabric ID (0x%X)",
				ErrFabricIDMismatch, rcacFabricID, nocFabricID)
		}
	}

	// Validate ICAC if present
	if len(icacTLV) > 0 {
		icacCert, err := ParseCertificate(icacTLV)
		if err != nil {
			return fmt.Errorf("ICAC: %w", err)
		}
		if icacCert.Type() != credentials.CertTypeICAC {
			return fmt.Errorf("ICAC: %w: expected ICAC, got %s",
				ErrInvalidCertificateType, icacCert.Type())
		}

		// Check ICAC fabric ID if present (optional in ICAC)
		if icacFabricID, found := ExtractFabricIDOptional(icacCert); found {
			if icacFabricID != nocFabricID {
				return fmt.Errorf("ICAC: %w: ICAC fabric ID (0x%X) != NOC fabric ID (0x%X)",
					ErrFabricIDMismatch, icacFabricID, nocFabricID)
			}
		}

		// Verify ICAC is signed by root (issuer check via key IDs)
		if !bytes.Equal(icacCert.AuthorityKeyID(), rootCert.SubjectKeyID()) {
			return fmt.Errorf("ICAC: issuer does not match root (AKID mismatch)")
		}

		// Verify NOC is signed by ICAC (issuer check via key IDs)
		if !bytes.Equal(nocCert.AuthorityKeyID(), icacCert.SubjectKeyID()) {
			return fmt.Errorf("NOC: issuer does not match ICAC (AKID mismatch)")
		}
	} else {
		// No ICAC - NOC should be directly signed by root
		// Verify NOC is signed by root (issuer check via key IDs)
		if !bytes.Equal(nocCert.AuthorityKeyID(), rootCert.SubjectKeyID()) {
			return fmt.Errorf("NOC: issuer does not match root (AKID mismatch)")
		}
	}

	return nil
}

// ChainInfo contains key information extracted from a validated certificate chain.
// This should be populated after ValidateNOCChain succeeds.
type ChainInfo struct {
	FabricID      FabricID
	NodeID        NodeID
	RootPublicKey [RootPublicKeySize]byte
	NOCCATs       []uint32 // CASE Authenticated Tags from NOC
}

// ExtractChainInfo extracts information from a certificate chain.
// The fabric ID is extracted from the NOC (not the RCAC, which doesn't have one).
func ExtractChainInfo(rootCertTLV, nocTLV []byte) (*ChainInfo, error) {
	rootCert, err := ParseCertificate(rootCertTLV)
	if err != nil {
		return nil, err
	}

	nocCert, err := ParseCertificate(nocTLV)
	if err != nil {
		return nil, err
	}

	// Fabric ID comes from the NOC (RCAC doesn't have fabric ID)
	fabricID, err := ExtractFabricID(nocCert)
	if err != nil {
		return nil, err
	}

	nodeID, err := ExtractNodeID(nocCert)
	if err != nil {
		return nil, err
	}

	rootPubKey, err := ExtractRootPublicKey(rootCert)
	if err != nil {
		return nil, err
	}

	return &ChainInfo{
		FabricID:      fabricID,
		NodeID:        nodeID,
		RootPublicKey: rootPubKey,
		NOCCATs:       nocCert.NOCCATs(),
	}, nil
}
