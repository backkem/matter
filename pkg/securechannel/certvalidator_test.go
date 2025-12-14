package securechannel

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/backkem/matter/pkg/credentials"
)

func TestNewCertValidator(t *testing.T) {
	validator := NewCertValidator()
	if validator == nil {
		t.Fatal("NewCertValidator returned nil")
	}
}

func TestNewSkipCertValidator(t *testing.T) {
	validator := NewSkipCertValidator()
	if validator == nil {
		t.Fatal("NewSkipCertValidator returned nil")
	}
}

func TestValidateCertTime(t *testing.T) {
	tests := []struct {
		name      string
		notBefore uint32
		notAfter  uint32
		checkTime time.Time
		expectErr error
	}{
		{
			name:      "valid_cert",
			notBefore: credentials.TimeToMatterEpoch(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)),
			notAfter:  credentials.TimeToMatterEpoch(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)),
			checkTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			expectErr: nil,
		},
		{
			name:      "not_yet_valid",
			notBefore: credentials.TimeToMatterEpoch(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)),
			notAfter:  credentials.TimeToMatterEpoch(time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)),
			checkTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			expectErr: ErrCertificateNotYetValid,
		},
		{
			name:      "expired",
			notBefore: credentials.TimeToMatterEpoch(time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)),
			notAfter:  credentials.TimeToMatterEpoch(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)),
			checkTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			expectErr: ErrCertificateExpired,
		},
		{
			name:      "no_expiration",
			notBefore: credentials.TimeToMatterEpoch(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)),
			notAfter:  0, // No expiration
			checkTime: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
			expectErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := &credentials.Certificate{
				NotBefore: tc.notBefore,
				NotAfter:  tc.notAfter,
			}

			err := validateCertTime(cert, tc.checkTime)
			if tc.expectErr != nil {
				if err != tc.expectErr {
					t.Errorf("validateCertTime() = %v, want %v", err, tc.expectErr)
				}
			} else if err != nil {
				t.Errorf("validateCertTime() unexpected error: %v", err)
			}
		})
	}
}

func TestParseP256PublicKey(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		expectErr bool
	}{
		{
			name:      "valid_key",
			data:      make([]byte, 65), // Will set prefix below
			expectErr: false,
		},
		{
			name:      "wrong_length",
			data:      make([]byte, 64),
			expectErr: true,
		},
		{
			name:      "wrong_prefix",
			data:      make([]byte, 65),
			expectErr: true,
		},
	}

	// Set up valid key
	tests[0].data[0] = 0x04 // Uncompressed prefix

	// Wrong prefix test
	tests[2].data[0] = 0x02 // Compressed prefix

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := parseP256PublicKey(tc.data)
			if tc.expectErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if key == nil {
					t.Error("expected non-nil key")
				}
			}
		})
	}
}

func TestCertificateErrors(t *testing.T) {
	// Test that error messages are meaningful
	errors := []error{
		ErrCertificateParseFailed,
		ErrCertificateTypeMismatch,
		ErrCertificateExpired,
		ErrCertificateNotYetValid,
		ErrCertificateChainBroken,
		ErrSignatureVerifyFailed,
		ErrPublicKeyMismatch,
		ErrMissingNodeID,
		ErrMissingFabricID,
		ErrFabricIDMismatch,
	}

	for _, err := range errors {
		if err.Error() == "" {
			t.Errorf("error %v has empty message", err)
		}
	}
}

func TestSkipCertValidator_Basic(t *testing.T) {
	validator := NewSkipCertValidator()

	// Create a minimal NOC-like certificate
	noc := &credentials.Certificate{
		SerialNum:  []byte{1},
		SigAlgo:    credentials.SignatureAlgoECDSASHA256,
		NotBefore:  0,
		NotAfter:   0,
		PubKeyAlgo: credentials.PublicKeyAlgoEC,
		ECCurveID:  credentials.EllipticCurvePrime256v1,
		ECPubKey:   make([]byte, 65),
		Subject: credentials.DistinguishedName{
			credentials.NewDNUint64(credentials.TagDNMatterNodeID, 12345),
			credentials.NewDNUint64(credentials.TagDNMatterFabricID, 67890),
		},
	}
	noc.ECPubKey[0] = 0x04 // Uncompressed prefix

	nocBytes, err := noc.EncodeTLV()
	if err != nil {
		t.Fatalf("failed to encode NOC: %v", err)
	}

	var rootPubKey [65]byte
	rootPubKey[0] = 0x04

	info, err := validator(nocBytes, nil, rootPubKey)
	if err != nil {
		t.Fatalf("validator failed: %v", err)
	}

	if info.NodeID != 12345 {
		t.Errorf("NodeID = %d, want 12345", info.NodeID)
	}

	if info.FabricID != 67890 {
		t.Errorf("FabricID = %d, want 67890", info.FabricID)
	}
}

func TestSkipCertValidator_DefaultsForMissing(t *testing.T) {
	validator := NewSkipCertValidator()

	// Create a certificate without NodeID/FabricID
	cert := &credentials.Certificate{
		SerialNum:  []byte{1},
		SigAlgo:    credentials.SignatureAlgoECDSASHA256,
		NotBefore:  0,
		NotAfter:   0,
		PubKeyAlgo: credentials.PublicKeyAlgoEC,
		ECCurveID:  credentials.EllipticCurvePrime256v1,
		ECPubKey:   make([]byte, 65),
		Subject:    credentials.DistinguishedName{},
	}
	cert.ECPubKey[0] = 0x04

	certBytes, err := cert.EncodeTLV()
	if err != nil {
		t.Fatalf("failed to encode cert: %v", err)
	}

	var rootPubKey [65]byte
	rootPubKey[0] = 0x04

	info, err := validator(certBytes, nil, rootPubKey)
	if err != nil {
		t.Fatalf("validator failed: %v", err)
	}

	// Skip validator should provide defaults
	if info.NodeID == 0 {
		t.Error("skip validator should provide default NodeID")
	}

	if info.FabricID == 0 {
		t.Error("skip validator should provide default FabricID")
	}
}

// hexDecode decodes a hex string to bytes, panicking on error (for test data).
func hexDecode(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}
