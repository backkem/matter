package commissioning

import (
	"bytes"
	"errors"

	"github.com/backkem/matter/pkg/tlv"
)

// TLV encoding/decoding for Operational Credentials attestation commands.
// Spec Reference: Section 11.18.6.1-4

// encodeAttestationRequest encodes an AttestationRequest command.
//
// Spec: Section 11.18.6.1
// Fields:
//   - AttestationNonce (tag 0): 32-byte random nonce
func encodeAttestationRequest(nonce []byte) ([]byte, error) {
	if len(nonce) != 32 {
		return nil, errors.New("attestation nonce must be 32 bytes")
	}

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	// AttestationNonce (field 0)
	if err := w.PutBytes(tlv.ContextTag(0), nonce); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// decodeAttestationResponse decodes an AttestationResponse command.
//
// Spec: Section 11.18.6.2
// Fields:
//   - AttestationElements (tag 0): TLV-encoded attestation data
//   - AttestationSignature (tag 1): ECDSA signature
func decodeAttestationResponse(data []byte) (*attestationResponse, error) {
	r := tlv.NewReader(bytes.NewReader(data))

	resp := &attestationResponse{}

	// Enter structure
	if err := r.Next(); err != nil {
		return nil, err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return nil, errors.New("expected structure")
	}

	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	// Read fields
	for {
		if err := r.Next(); err != nil {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}

		switch tag.TagNumber() {
		case 0: // AttestationElements
			val, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			resp.Elements = val
		case 1: // AttestationSignature
			val, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			resp.Signature = val
		}
	}

	if err := r.ExitContainer(); err != nil {
		return nil, err
	}

	if resp.Elements == nil || resp.Signature == nil {
		return nil, errors.New("missing required fields in AttestationResponse")
	}

	return resp, nil
}

// encodeCertificateChainRequest encodes a CertificateChainRequest command.
//
// Spec: Section 11.18.6.3
// Fields:
//   - CertificateType (tag 0): CertificateChainTypeEnum (1=DAC, 2=PAI)
func encodeCertificateChainRequest(certType CertificateChainType) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	// CertificateType (field 0)
	if err := w.PutUint(tlv.ContextTag(0), uint64(certType)); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// decodeCertificateChainResponse decodes a CertificateChainResponse command.
//
// Spec: Section 11.18.6.4
// Fields:
//   - Certificate (tag 0): DER-encoded certificate
func decodeCertificateChainResponse(data []byte) ([]byte, error) {
	r := tlv.NewReader(bytes.NewReader(data))

	// Enter structure
	if err := r.Next(); err != nil {
		return nil, err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return nil, errors.New("expected structure")
	}

	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	var certificate []byte

	// Read fields
	for {
		if err := r.Next(); err != nil {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}

		switch tag.TagNumber() {
		case 0: // Certificate
			val, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			certificate = val
		}
	}

	if err := r.ExitContainer(); err != nil {
		return nil, err
	}

	if certificate == nil {
		return nil, errors.New("missing certificate in CertificateChainResponse")
	}

	return certificate, nil
}
