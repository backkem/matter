package commissioning

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/backkem/matter/pkg/im"
	"github.com/backkem/matter/pkg/session"
	"github.com/backkem/matter/pkg/transport"
)

// AttestationVerifier is the interface for verifying device attestation.
//
// This interface allows pluggable attestation verification strategies:
//   - AcceptAllVerifier: Always accepts (for development/testing)
//   - DCLVerifier: Validates against Distributed Compliance Ledger (future)
//   - Custom: User-provided verification logic
//
// Design Decision:
// The Matter spec requires sending AttestationRequest and receiving
// AttestationResponse during commissioning. However, the actual cryptographic
// verification (DAC chain validation, DCL lookup, revocation checks) is
// complex and varies by ecosystem. By making verification pluggable:
//  1. We satisfy the protocol requirement (messages are exchanged)
//  2. We enable easy testing with AcceptAllVerifier
//  3. We allow production systems to implement full DCL verification
//  4. We let library users implement custom policies
//
// See docs/pkgs/attestation.md for detailed design rationale.
type AttestationVerifier interface {
	// Verify performs device attestation verification.
	//
	// Parameters:
	//   - ctx: Context for cancellation
	//   - info: Attestation information received from device
	//
	// Returns:
	//   - *AttestationResult: Verification result details
	//   - error: nil if verification passed, error otherwise
	//
	// Implementations should:
	//  1. Validate the attestation signature
	//  2. Verify the DAC certificate chain
	//  3. Check the certification declaration
	//  4. Optionally check DCL and revocation lists
	Verify(ctx context.Context, info *AttestationInfo) (*AttestationResult, error)
}

// AttestationInfo contains the attestation data received from a device.
type AttestationInfo struct {
	// AttestationNonce is the 32-byte random nonce sent in the request.
	AttestationNonce []byte

	// AttestationElements is the TLV-encoded attestation elements.
	// Contains: certification_declaration, attestation_nonce, timestamp, firmware_information (optional)
	AttestationElements []byte

	// AttestationSignature is the ECDSA signature over the elements.
	AttestationSignature []byte

	// DAC is the Device Attestation Certificate (DER encoded).
	DAC []byte

	// PAI is the Product Attestation Intermediate certificate (DER encoded).
	PAI []byte
}

// OperationalCredentialsClusterID is the cluster ID for Operational Credentials.
const OperationalCredentialsClusterID uint32 = 0x003E

// Operational Credentials command IDs.
const (
	CmdAttestationRequest       uint32 = 0x00
	CmdAttestationResponse      uint32 = 0x01
	CmdCertificateChainRequest  uint32 = 0x02
	CmdCertificateChainResponse uint32 = 0x03
	CmdCSRRequest               uint32 = 0x04
	CmdCSRResponse              uint32 = 0x05
	CmdAddNOC                   uint32 = 0x06
	CmdUpdateNOC                uint32 = 0x09
	CmdNOCResponse              uint32 = 0x08
)

// CertificateChainType identifies the certificate type to request.
type CertificateChainType uint8

const (
	// CertificateChainTypeDAC requests the Device Attestation Certificate.
	CertificateChainTypeDAC CertificateChainType = 1
	// CertificateChainTypePAI requests the Product Attestation Intermediate.
	CertificateChainTypePAI CertificateChainType = 2
)

// AcceptAllVerifier is an attestation verifier that always accepts.
//
// WARNING: This verifier should only be used for development and testing.
// It does NOT perform any actual cryptographic verification.
//
// For production use, implement a proper AttestationVerifier that:
//   - Validates the DAC chain against known PAAs
//   - Verifies attestation signatures
//   - Checks the DCL for device compliance
//   - Validates certification declarations
type AcceptAllVerifier struct{}

// NewAcceptAllVerifier creates a new AcceptAllVerifier.
func NewAcceptAllVerifier() *AcceptAllVerifier {
	return &AcceptAllVerifier{}
}

// Verify always returns success without performing actual verification.
func (v *AcceptAllVerifier) Verify(ctx context.Context, info *AttestationInfo) (*AttestationResult, error) {
	// Extract basic info from DAC if possible (best effort)
	// For now, just mark as verified but untrusted
	return &AttestationResult{
		Verified:               true,  // Protocol was followed
		Trusted:                false, // No actual verification performed
		AttestationNonce:       info.AttestationNonce,
		CertificateDeclaration: nil, // Would need to parse from elements
	}, nil
}

// PerformDeviceAttestation executes the device attestation protocol.
//
// This function implements the Matter Device Attestation Procedure (Spec 6.2.3):
//  1. Generate random 32-byte attestation nonce
//  2. Send AttestationRequest command
//  3. Receive AttestationResponse with signed attestation info
//  4. Request DAC via CertificateChainRequest
//  5. Request PAI via CertificateChainRequest
//  6. Pass all info to the AttestationVerifier
//
// The verifier is responsible for actual cryptographic verification.
func PerformDeviceAttestation(
	ctx context.Context,
	imClient *im.Client,
	sess *session.SecureContext,
	peerAddr transport.PeerAddress,
	verifier AttestationVerifier,
) (*AttestationResult, error) {
	if verifier == nil {
		return nil, errors.New("attestation: verifier is nil")
	}

	// Step 1: Generate random 32-byte nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("attestation: generate nonce: %w", err)
	}

	// Step 2: Send AttestationRequest
	attestResp, err := sendAttestationRequest(ctx, imClient, sess, peerAddr, nonce)
	if err != nil {
		return nil, fmt.Errorf("attestation: request failed: %w", err)
	}

	// Step 3: Request DAC certificate
	dac, err := sendCertificateChainRequest(ctx, imClient, sess, peerAddr, CertificateChainTypeDAC)
	if err != nil {
		return nil, fmt.Errorf("attestation: get DAC failed: %w", err)
	}

	// Step 4: Request PAI certificate
	pai, err := sendCertificateChainRequest(ctx, imClient, sess, peerAddr, CertificateChainTypePAI)
	if err != nil {
		return nil, fmt.Errorf("attestation: get PAI failed: %w", err)
	}

	// Step 5: Build attestation info and verify
	info := &AttestationInfo{
		AttestationNonce:     nonce,
		AttestationElements:  attestResp.Elements,
		AttestationSignature: attestResp.Signature,
		DAC:                  dac,
		PAI:                  pai,
	}

	return verifier.Verify(ctx, info)
}

// attestationResponse holds the decoded AttestationResponse.
type attestationResponse struct {
	Elements  []byte
	Signature []byte
}

// sendAttestationRequest sends the AttestationRequest command and returns the response.
func sendAttestationRequest(
	ctx context.Context,
	imClient *im.Client,
	sess *session.SecureContext,
	peerAddr transport.PeerAddress,
	nonce []byte,
) (*attestationResponse, error) {
	// Encode AttestationRequest TLV
	reqData, err := encodeAttestationRequest(nonce)
	if err != nil {
		return nil, err
	}

	// Send command
	respData, err := imClient.InvokeRequest(
		ctx,
		sess,
		peerAddr,
		0, // Endpoint 0
		OperationalCredentialsClusterID,
		CmdAttestationRequest,
		reqData,
	)
	if err != nil {
		return nil, err
	}

	// Decode response
	return decodeAttestationResponse(respData)
}

// sendCertificateChainRequest requests a certificate from the device.
func sendCertificateChainRequest(
	ctx context.Context,
	imClient *im.Client,
	sess *session.SecureContext,
	peerAddr transport.PeerAddress,
	certType CertificateChainType,
) ([]byte, error) {
	// Encode CertificateChainRequest TLV
	reqData, err := encodeCertificateChainRequest(certType)
	if err != nil {
		return nil, err
	}

	// Send command
	respData, err := imClient.InvokeRequest(
		ctx,
		sess,
		peerAddr,
		0, // Endpoint 0
		OperationalCredentialsClusterID,
		CmdCertificateChainRequest,
		reqData,
	)
	if err != nil {
		return nil, err
	}

	// Decode response
	return decodeCertificateChainResponse(respData)
}
