package commissioning

import (
	"bytes"
	"testing"
)

// Test vectors derived from CHIP SDK:
// src/credentials/tests/TestDeviceAttestationConstruction.cpp

// TestEncodeAttestationRequest tests that AttestationRequest TLV encoding
// matches the spec (Section 11.18.6.1).
func TestEncodeAttestationRequest(t *testing.T) {
	// Test vector: 32-byte attestation nonce
	attestationNonce := []byte{
		0xe0, 0x42, 0x1b, 0x91, 0xc6, 0xfd, 0xcd, 0xb4,
		0x0e, 0x2a, 0x4d, 0x2c, 0xf3, 0x1d, 0xb2, 0xb4,
		0xe1, 0x8b, 0x41, 0x1b, 0x1d, 0x3a, 0xd4, 0xd1,
		0x2a, 0x9d, 0x90, 0xaa, 0x8e, 0x52, 0xfa, 0xe2,
	}

	encoded, err := encodeAttestationRequest(attestationNonce)
	if err != nil {
		t.Fatalf("encodeAttestationRequest failed: %v", err)
	}

	// Expected TLV structure:
	// 15             - Structure, anonymous tag
	// 30 00 20       - Bytes, context tag 0, length 32
	// <32 bytes of nonce>
	// 18             - End of container

	// Check structure start (anonymous structure)
	if encoded[0] != 0x15 {
		t.Errorf("expected structure start 0x15, got 0x%02x", encoded[0])
	}

	// Check context tag 0 with octet string type (0x30)
	if encoded[1] != 0x30 {
		t.Errorf("expected bytes type 0x30, got 0x%02x", encoded[1])
	}

	// Check tag is context 0
	if encoded[2] != 0x00 {
		t.Errorf("expected context tag 0, got 0x%02x", encoded[2])
	}

	// Check length is 32
	if encoded[3] != 0x20 {
		t.Errorf("expected length 32 (0x20), got 0x%02x", encoded[3])
	}

	// Check nonce bytes
	if !bytes.Equal(encoded[4:36], attestationNonce) {
		t.Errorf("nonce bytes mismatch")
	}

	// Check end of container
	if encoded[36] != 0x18 {
		t.Errorf("expected end container 0x18, got 0x%02x", encoded[36])
	}

	// Total length should be 37 bytes: 1 (struct) + 3 (tag+type+len) + 32 (nonce) + 1 (end)
	if len(encoded) != 37 {
		t.Errorf("expected length 37, got %d", len(encoded))
	}
}

// TestEncodeAttestationRequestInvalidNonce tests that invalid nonce sizes are rejected.
func TestEncodeAttestationRequestInvalidNonce(t *testing.T) {
	tests := []struct {
		name  string
		nonce []byte
	}{
		{"empty", []byte{}},
		{"too short", make([]byte, 31)},
		{"too long", make([]byte, 33)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := encodeAttestationRequest(tc.nonce)
			if err == nil {
				t.Error("expected error for invalid nonce size")
			}
		})
	}
}

// TestEncodeCertificateChainRequest tests CertificateChainRequest TLV encoding
// (Section 11.18.6.3).
func TestEncodeCertificateChainRequest(t *testing.T) {
	tests := []struct {
		name     string
		certType CertificateChainType
		// Expected tag 0 value byte
		expectedVal byte
	}{
		{"DAC", CertificateChainTypeDAC, 1},
		{"PAI", CertificateChainTypePAI, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := encodeCertificateChainRequest(tc.certType)
			if err != nil {
				t.Fatalf("encodeCertificateChainRequest failed: %v", err)
			}

			// Expected TLV structure:
			// 15          - Structure, anonymous tag
			// 24 00 XX    - Uint8, context tag 0, value XX
			// 18          - End of container

			if encoded[0] != 0x15 {
				t.Errorf("expected structure start 0x15, got 0x%02x", encoded[0])
			}

			// Check uint8 type (0x04) in control byte
			// Control byte: elem type (5 bits) | tag form (3 bits)
			// For UInt8 with context tag: 0x04 (uint8) | 0x20 (context) = 0x24
			if encoded[1] != 0x24 {
				t.Errorf("expected uint8 with context tag 0x24, got 0x%02x", encoded[1])
			}

			// Context tag 0
			if encoded[2] != 0x00 {
				t.Errorf("expected context tag 0, got 0x%02x", encoded[2])
			}

			// Value
			if encoded[3] != tc.expectedVal {
				t.Errorf("expected value %d, got %d", tc.expectedVal, encoded[3])
			}

			// End of container
			if encoded[4] != 0x18 {
				t.Errorf("expected end container 0x18, got 0x%02x", encoded[4])
			}
		})
	}
}

// TestDecodeAttestationResponse tests decoding of AttestationResponse TLV
// (Section 11.18.6.2).
func TestDecodeAttestationResponse(t *testing.T) {
	// Build a test AttestationResponse TLV:
	// {
	//   0: <attestation_elements bytes>
	//   1: <attestation_signature bytes>
	// }
	testElements := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	testSignature := []byte{0xaa, 0xbb, 0xcc, 0xdd}

	// Construct TLV manually
	// 15 - Structure start
	// 30 00 05 01 02 03 04 05 - Bytes tag 0, length 5, elements
	// 30 01 04 aa bb cc dd    - Bytes tag 1, length 4, signature
	// 18 - End container
	tlvData := []byte{
		0x15,                         // Structure, anonymous
		0x30, 0x00, 0x05,             // Bytes, context tag 0, length 5
		0x01, 0x02, 0x03, 0x04, 0x05, // elements
		0x30, 0x01, 0x04, // Bytes, context tag 1, length 4
		0xaa, 0xbb, 0xcc, 0xdd, // signature
		0x18, // End container
	}

	resp, err := decodeAttestationResponse(tlvData)
	if err != nil {
		t.Fatalf("decodeAttestationResponse failed: %v", err)
	}

	if !bytes.Equal(resp.Elements, testElements) {
		t.Errorf("elements mismatch: got %x, want %x", resp.Elements, testElements)
	}

	if !bytes.Equal(resp.Signature, testSignature) {
		t.Errorf("signature mismatch: got %x, want %x", resp.Signature, testSignature)
	}
}

// TestDecodeAttestationResponseMissingFields tests that missing required fields cause errors.
func TestDecodeAttestationResponseMissingFields(t *testing.T) {
	tests := []struct {
		name    string
		tlvData []byte
	}{
		{
			"missing signature",
			[]byte{
				0x15,                         // Structure
				0x30, 0x00, 0x05,             // Bytes, context tag 0, length 5
				0x01, 0x02, 0x03, 0x04, 0x05, // elements only
				0x18, // End container
			},
		},
		{
			"missing elements",
			[]byte{
				0x15,             // Structure
				0x30, 0x01, 0x04, // Bytes, context tag 1, length 4
				0xaa, 0xbb, 0xcc, 0xdd, // signature only
				0x18, // End container
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeAttestationResponse(tc.tlvData)
			if err == nil {
				t.Error("expected error for missing fields")
			}
		})
	}
}

// TestDecodeCertificateChainResponse tests decoding of CertificateChainResponse TLV
// (Section 11.18.6.4).
func TestDecodeCertificateChainResponse(t *testing.T) {
	// Test certificate data
	testCert := []byte{0x30, 0x82, 0x01, 0x00} // Partial DER cert header

	// Construct TLV:
	// 15 - Structure start
	// 30 00 04 30 82 01 00 - Bytes tag 0, length 4, cert
	// 18 - End container
	tlvData := []byte{
		0x15,                   // Structure, anonymous
		0x30, 0x00, 0x04,       // Bytes, context tag 0, length 4
		0x30, 0x82, 0x01, 0x00, // certificate
		0x18, // End container
	}

	cert, err := decodeCertificateChainResponse(tlvData)
	if err != nil {
		t.Fatalf("decodeCertificateChainResponse failed: %v", err)
	}

	if !bytes.Equal(cert, testCert) {
		t.Errorf("certificate mismatch: got %x, want %x", cert, testCert)
	}
}

// TestDecodeCertificateChainResponseMissingCert tests that missing certificate causes error.
func TestDecodeCertificateChainResponseMissingCert(t *testing.T) {
	// Empty structure
	tlvData := []byte{
		0x15, // Structure
		0x18, // End container
	}

	_, err := decodeCertificateChainResponse(tlvData)
	if err == nil {
		t.Error("expected error for missing certificate")
	}
}

// TestAcceptAllVerifier tests the AcceptAllVerifier implementation.
func TestAcceptAllVerifier(t *testing.T) {
	verifier := NewAcceptAllVerifier()

	nonce := []byte{
		0xe0, 0x42, 0x1b, 0x91, 0xc6, 0xfd, 0xcd, 0xb4,
		0x0e, 0x2a, 0x4d, 0x2c, 0xf3, 0x1d, 0xb2, 0xb4,
		0xe1, 0x8b, 0x41, 0x1b, 0x1d, 0x3a, 0xd4, 0xd1,
		0x2a, 0x9d, 0x90, 0xaa, 0x8e, 0x52, 0xfa, 0xe2,
	}

	info := &AttestationInfo{
		AttestationNonce:     nonce,
		AttestationElements:  []byte{0x01, 0x02, 0x03},
		AttestationSignature: []byte{0xaa, 0xbb, 0xcc},
		DAC:                  []byte{0x30, 0x82},
		PAI:                  []byte{0x30, 0x82},
	}

	result, err := verifier.Verify(nil, info)
	if err != nil {
		t.Fatalf("AcceptAllVerifier.Verify failed: %v", err)
	}

	// AcceptAllVerifier should return Verified=true, Trusted=false
	if !result.Verified {
		t.Error("expected Verified=true")
	}

	if result.Trusted {
		t.Error("expected Trusted=false for AcceptAllVerifier")
	}

	if !bytes.Equal(result.AttestationNonce, nonce) {
		t.Error("nonce should be preserved in result")
	}
}
