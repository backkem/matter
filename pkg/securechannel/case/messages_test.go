package casesession

import (
	"bytes"
	"testing"

	"github.com/backkem/matter/pkg/crypto"
)

func TestSigma1_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  *Sigma1
	}{
		{
			name: "basic without resumption",
			msg: &Sigma1{
				InitiatorRandom:    [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
				InitiatorSessionID: 0x1234,
				DestinationID:      [32]byte{0xAA, 0xBB, 0xCC},
				InitiatorEphPubKey: func() [65]byte {
					var key [65]byte
					key[0] = 0x04 // uncompressed marker
					for i := 1; i < 65; i++ {
						key[i] = byte(i)
					}
					return key
				}(),
			},
		},
		{
			name: "with MRP params",
			msg: &Sigma1{
				InitiatorRandom:    [32]byte{0xFF},
				InitiatorSessionID: 0xABCD,
				DestinationID:      [32]byte{0x11, 0x22},
				InitiatorEphPubKey: [65]byte{0x04},
				MRPParams: &MRPParameters{
					IdleRetransTimeout:   5000,
					ActiveRetransTimeout: 300,
					ActiveThreshold:      4000,
				},
			},
		},
		{
			name: "with resumption",
			msg: &Sigma1{
				InitiatorRandom:    [32]byte{0xDE, 0xAD, 0xBE, 0xEF},
				InitiatorSessionID: 0x5678,
				DestinationID:      [32]byte{0x33},
				InitiatorEphPubKey: [65]byte{0x04},
				ResumptionID:       &[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				InitiatorResumeMIC: &[16]byte{0xAA, 0xBB, 0xCC, 0xDD},
			},
		},
		{
			name: "with resumption and MRP",
			msg: &Sigma1{
				InitiatorRandom:    [32]byte{0x12},
				InitiatorSessionID: 0x9999,
				DestinationID:      [32]byte{0x44},
				InitiatorEphPubKey: [65]byte{0x04},
				MRPParams: &MRPParameters{
					IdleRetransTimeout: 1000,
				},
				ResumptionID:       &[16]byte{0xEE},
				InitiatorResumeMIC: &[16]byte{0xFF},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := tc.msg.Encode()
			if err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			decoded, err := DecodeSigma1(encoded)
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			// Compare fields
			if decoded.InitiatorRandom != tc.msg.InitiatorRandom {
				t.Errorf("InitiatorRandom mismatch")
			}
			if decoded.InitiatorSessionID != tc.msg.InitiatorSessionID {
				t.Errorf("InitiatorSessionID mismatch: got %d, want %d", decoded.InitiatorSessionID, tc.msg.InitiatorSessionID)
			}
			if decoded.DestinationID != tc.msg.DestinationID {
				t.Errorf("DestinationID mismatch")
			}
			if decoded.InitiatorEphPubKey != tc.msg.InitiatorEphPubKey {
				t.Errorf("InitiatorEphPubKey mismatch")
			}

			// Compare MRP params
			if (tc.msg.MRPParams == nil) != (decoded.MRPParams == nil) {
				t.Errorf("MRPParams presence mismatch")
			} else if tc.msg.MRPParams != nil {
				if decoded.MRPParams.IdleRetransTimeout != tc.msg.MRPParams.IdleRetransTimeout {
					t.Errorf("IdleRetransTimeout mismatch")
				}
				if decoded.MRPParams.ActiveRetransTimeout != tc.msg.MRPParams.ActiveRetransTimeout {
					t.Errorf("ActiveRetransTimeout mismatch")
				}
				if decoded.MRPParams.ActiveThreshold != tc.msg.MRPParams.ActiveThreshold {
					t.Errorf("ActiveThreshold mismatch")
				}
			}

			// Compare resumption fields
			if (tc.msg.ResumptionID == nil) != (decoded.ResumptionID == nil) {
				t.Errorf("ResumptionID presence mismatch")
			} else if tc.msg.ResumptionID != nil && *decoded.ResumptionID != *tc.msg.ResumptionID {
				t.Errorf("ResumptionID mismatch")
			}

			if (tc.msg.InitiatorResumeMIC == nil) != (decoded.InitiatorResumeMIC == nil) {
				t.Errorf("InitiatorResumeMIC presence mismatch")
			} else if tc.msg.InitiatorResumeMIC != nil && *decoded.InitiatorResumeMIC != *tc.msg.InitiatorResumeMIC {
				t.Errorf("InitiatorResumeMIC mismatch")
			}

			// Test HasResumption
			if decoded.HasResumption() != tc.msg.HasResumption() {
				t.Errorf("HasResumption mismatch: got %v, want %v", decoded.HasResumption(), tc.msg.HasResumption())
			}
		})
	}
}

func TestSigma1_DecodeErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty",
			data: []byte{},
		},
		{
			name: "not a struct",
			data: []byte{0x00}, // Null element
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeSigma1(tc.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestSigma2_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  *Sigma2
	}{
		{
			name: "basic",
			msg: &Sigma2{
				ResponderRandom:    [32]byte{0x01, 0x02, 0x03},
				ResponderSessionID: 0xBEEF,
				ResponderEphPubKey: [65]byte{0x04, 0xAA, 0xBB},
				Encrypted2:         []byte{0x11, 0x22, 0x33, 0x44, 0x55},
			},
		},
		{
			name: "with MRP params",
			msg: &Sigma2{
				ResponderRandom:    [32]byte{0xFF},
				ResponderSessionID: 0x1111,
				ResponderEphPubKey: [65]byte{0x04},
				Encrypted2:         []byte{0xDE, 0xAD},
				MRPParams: &MRPParameters{
					ActiveRetransTimeout: 500,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := tc.msg.Encode()
			if err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			decoded, err := DecodeSigma2(encoded)
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if decoded.ResponderRandom != tc.msg.ResponderRandom {
				t.Errorf("ResponderRandom mismatch")
			}
			if decoded.ResponderSessionID != tc.msg.ResponderSessionID {
				t.Errorf("ResponderSessionID mismatch")
			}
			if decoded.ResponderEphPubKey != tc.msg.ResponderEphPubKey {
				t.Errorf("ResponderEphPubKey mismatch")
			}
			if !bytes.Equal(decoded.Encrypted2, tc.msg.Encrypted2) {
				t.Errorf("Encrypted2 mismatch")
			}
		})
	}
}

func TestSigma3_Roundtrip(t *testing.T) {
	msg := &Sigma3{
		Encrypted3: []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
	}

	encoded, err := msg.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := DecodeSigma3(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if !bytes.Equal(decoded.Encrypted3, msg.Encrypted3) {
		t.Errorf("Encrypted3 mismatch")
	}
}

func TestSigma2Resume_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  *Sigma2Resume
	}{
		{
			name: "basic",
			msg: &Sigma2Resume{
				ResumptionID:       [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				Resume2MIC:         [16]byte{0xAA, 0xBB, 0xCC, 0xDD},
				ResponderSessionID: 0xCAFE,
			},
		},
		{
			name: "with MRP",
			msg: &Sigma2Resume{
				ResumptionID:       [16]byte{0xFF},
				Resume2MIC:         [16]byte{0xEE},
				ResponderSessionID: 0x5555,
				MRPParams: &MRPParameters{
					IdleRetransTimeout: 2000,
					ActiveThreshold:    500,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := tc.msg.Encode()
			if err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			decoded, err := DecodeSigma2Resume(encoded)
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if decoded.ResumptionID != tc.msg.ResumptionID {
				t.Errorf("ResumptionID mismatch")
			}
			if decoded.Resume2MIC != tc.msg.Resume2MIC {
				t.Errorf("Resume2MIC mismatch")
			}
			if decoded.ResponderSessionID != tc.msg.ResponderSessionID {
				t.Errorf("ResponderSessionID mismatch")
			}
		})
	}
}

func TestTBEData2_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  *TBEData2
	}{
		{
			name: "without ICAC",
			msg: &TBEData2{
				ResponderNOC: []byte{0x15, 0x01, 0x02, 0x03}, // Sample TLV
				Signature:    [64]byte{0xAA, 0xBB},
				ResumptionID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			},
		},
		{
			name: "with ICAC",
			msg: &TBEData2{
				ResponderNOC:  []byte{0x15, 0x01, 0x02, 0x03},
				ResponderICAC: []byte{0x15, 0x04, 0x05, 0x06},
				Signature:     [64]byte{0xCC, 0xDD},
				ResumptionID:  [16]byte{0xFF},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := tc.msg.Encode()
			if err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			decoded, err := DecodeTBEData2(encoded)
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !bytes.Equal(decoded.ResponderNOC, tc.msg.ResponderNOC) {
				t.Errorf("ResponderNOC mismatch")
			}
			if !bytes.Equal(decoded.ResponderICAC, tc.msg.ResponderICAC) {
				t.Errorf("ResponderICAC mismatch")
			}
			if decoded.Signature != tc.msg.Signature {
				t.Errorf("Signature mismatch")
			}
			if decoded.ResumptionID != tc.msg.ResumptionID {
				t.Errorf("ResumptionID mismatch")
			}
		})
	}
}

func TestTBEData3_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  *TBEData3
	}{
		{
			name: "without ICAC",
			msg: &TBEData3{
				InitiatorNOC: []byte{0x15, 0x01, 0x02, 0x03},
				Signature:    [64]byte{0xAA, 0xBB},
			},
		},
		{
			name: "with ICAC",
			msg: &TBEData3{
				InitiatorNOC:  []byte{0x15, 0x01, 0x02, 0x03},
				InitiatorICAC: []byte{0x15, 0x04, 0x05, 0x06},
				Signature:     [64]byte{0xCC, 0xDD},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := tc.msg.Encode()
			if err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			decoded, err := DecodeTBEData3(encoded)
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !bytes.Equal(decoded.InitiatorNOC, tc.msg.InitiatorNOC) {
				t.Errorf("InitiatorNOC mismatch")
			}
			if !bytes.Equal(decoded.InitiatorICAC, tc.msg.InitiatorICAC) {
				t.Errorf("InitiatorICAC mismatch")
			}
			if decoded.Signature != tc.msg.Signature {
				t.Errorf("Signature mismatch")
			}
		})
	}
}

func TestTBSData2_Encode(t *testing.T) {
	tbs := &TBSData2{
		ResponderNOC:  []byte{0x15, 0x01, 0x02},
		ResponderICAC: []byte{0x15, 0x03, 0x04},
		ResponderEphPubKey: func() [65]byte {
			var key [65]byte
			key[0] = 0x04
			key[1] = 0xAA
			return key
		}(),
		InitiatorEphPubKey: func() [65]byte {
			var key [65]byte
			key[0] = 0x04
			key[1] = 0xBB
			return key
		}(),
	}

	encoded, err := tbs.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	// Verify it's valid TLV (no decode function for TBS, but we can check structure)
	if len(encoded) == 0 {
		t.Error("encoded data is empty")
	}
}

func TestTBSData3_Encode(t *testing.T) {
	tbs := &TBSData3{
		InitiatorNOC:  []byte{0x15, 0x01, 0x02},
		InitiatorICAC: []byte{0x15, 0x03, 0x04},
		InitiatorEphPubKey: func() [65]byte {
			var key [65]byte
			key[0] = 0x04
			key[1] = 0xCC
			return key
		}(),
		ResponderEphPubKey: func() [65]byte {
			var key [65]byte
			key[0] = 0x04
			key[1] = 0xDD
			return key
		}(),
	}

	encoded, err := tbs.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	if len(encoded) == 0 {
		t.Error("encoded data is empty")
	}
}

func TestMRPParameters_Roundtrip(t *testing.T) {
	// Test MRP params through Sigma1 roundtrip
	tests := []struct {
		name   string
		params *MRPParameters
	}{
		{
			name:   "nil",
			params: nil,
		},
		{
			name: "idle only",
			params: &MRPParameters{
				IdleRetransTimeout: 5000,
			},
		},
		{
			name: "active only",
			params: &MRPParameters{
				ActiveRetransTimeout: 300,
			},
		},
		{
			name: "threshold only",
			params: &MRPParameters{
				ActiveThreshold: 4000,
			},
		},
		{
			name: "all fields",
			params: &MRPParameters{
				IdleRetransTimeout:   5000,
				ActiveRetransTimeout: 300,
				ActiveThreshold:      4000,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := &Sigma1{
				InitiatorRandom:    [32]byte{0x01},
				InitiatorSessionID: 100,
				DestinationID:      [32]byte{0x02},
				InitiatorEphPubKey: [crypto.P256PublicKeySizeBytes]byte{0x04},
				MRPParams:          tc.params,
			}

			encoded, err := msg.Encode()
			if err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			decoded, err := DecodeSigma1(encoded)
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if (tc.params == nil) != (decoded.MRPParams == nil) {
				t.Fatalf("MRPParams presence mismatch")
			}

			if tc.params != nil {
				if decoded.MRPParams.IdleRetransTimeout != tc.params.IdleRetransTimeout {
					t.Errorf("IdleRetransTimeout: got %d, want %d", decoded.MRPParams.IdleRetransTimeout, tc.params.IdleRetransTimeout)
				}
				if decoded.MRPParams.ActiveRetransTimeout != tc.params.ActiveRetransTimeout {
					t.Errorf("ActiveRetransTimeout: got %d, want %d", decoded.MRPParams.ActiveRetransTimeout, tc.params.ActiveRetransTimeout)
				}
				if decoded.MRPParams.ActiveThreshold != tc.params.ActiveThreshold {
					t.Errorf("ActiveThreshold: got %d, want %d", decoded.MRPParams.ActiveThreshold, tc.params.ActiveThreshold)
				}
			}
		})
	}
}
