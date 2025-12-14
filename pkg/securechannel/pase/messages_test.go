package pase

import (
	"bytes"
	"testing"
)

func TestPBKDFParamRequestRoundtrip(t *testing.T) {
	var random [RandomSize]byte
	for i := range random {
		random[i] = byte(i)
	}

	original := &PBKDFParamRequest{
		InitiatorRandom:    random,
		InitiatorSessionID: 1234,
		PasscodeID:         0,
		HasPBKDFParameters: false,
	}

	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := DecodePBKDFParamRequest(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.InitiatorRandom != original.InitiatorRandom {
		t.Error("InitiatorRandom mismatch")
	}
	if decoded.InitiatorSessionID != original.InitiatorSessionID {
		t.Errorf("InitiatorSessionID = %d, want %d", decoded.InitiatorSessionID, original.InitiatorSessionID)
	}
	if decoded.PasscodeID != original.PasscodeID {
		t.Errorf("PasscodeID = %d, want %d", decoded.PasscodeID, original.PasscodeID)
	}
	if decoded.HasPBKDFParameters != original.HasPBKDFParameters {
		t.Errorf("HasPBKDFParameters = %v, want %v", decoded.HasPBKDFParameters, original.HasPBKDFParameters)
	}
}

func TestPBKDFParamRequestWithMRP(t *testing.T) {
	var random [RandomSize]byte
	for i := range random {
		random[i] = byte(i)
	}

	original := &PBKDFParamRequest{
		InitiatorRandom:    random,
		InitiatorSessionID: 5678,
		PasscodeID:         0,
		HasPBKDFParameters: true,
		MRPParams: &MRPParameters{
			IdleRetransTimeout:   1000,
			ActiveRetransTimeout: 2000,
			ActiveThreshold:      4000,
		},
	}

	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := DecodePBKDFParamRequest(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.MRPParams == nil {
		t.Fatal("MRPParams is nil")
	}
	if decoded.MRPParams.IdleRetransTimeout != 1000 {
		t.Errorf("IdleRetransTimeout = %d, want 1000", decoded.MRPParams.IdleRetransTimeout)
	}
	if decoded.MRPParams.ActiveRetransTimeout != 2000 {
		t.Errorf("ActiveRetransTimeout = %d, want 2000", decoded.MRPParams.ActiveRetransTimeout)
	}
	if decoded.MRPParams.ActiveThreshold != 4000 {
		t.Errorf("ActiveThreshold = %d, want 4000", decoded.MRPParams.ActiveThreshold)
	}
}

func TestPBKDFParamResponseRoundtrip(t *testing.T) {
	var initRandom, respRandom [RandomSize]byte
	for i := range initRandom {
		initRandom[i] = byte(i)
		respRandom[i] = byte(255 - i)
	}

	salt := []byte("SPAKE2P Key Salt")

	original := &PBKDFParamResponse{
		InitiatorRandom:    initRandom,
		ResponderRandom:    respRandom,
		ResponderSessionID: 9999,
		PBKDFParams: &PBKDFParameters{
			Iterations: 1000,
			Salt:       salt,
		},
	}

	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := DecodePBKDFParamResponse(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.InitiatorRandom != original.InitiatorRandom {
		t.Error("InitiatorRandom mismatch")
	}
	if decoded.ResponderRandom != original.ResponderRandom {
		t.Error("ResponderRandom mismatch")
	}
	if decoded.ResponderSessionID != original.ResponderSessionID {
		t.Errorf("ResponderSessionID = %d, want %d", decoded.ResponderSessionID, original.ResponderSessionID)
	}
	if decoded.PBKDFParams == nil {
		t.Fatal("PBKDFParams is nil")
	}
	if decoded.PBKDFParams.Iterations != 1000 {
		t.Errorf("Iterations = %d, want 1000", decoded.PBKDFParams.Iterations)
	}
	if !bytes.Equal(decoded.PBKDFParams.Salt, salt) {
		t.Error("Salt mismatch")
	}
}

func TestPBKDFParamResponseWithoutParams(t *testing.T) {
	var initRandom, respRandom [RandomSize]byte

	original := &PBKDFParamResponse{
		InitiatorRandom:    initRandom,
		ResponderRandom:    respRandom,
		ResponderSessionID: 1111,
		PBKDFParams:        nil, // Initiator already has params
	}

	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := DecodePBKDFParamResponse(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.PBKDFParams != nil {
		t.Error("Expected PBKDFParams to be nil")
	}
}

func TestPBKDFParamResponseWithMRP(t *testing.T) {
	var initRandom, respRandom [RandomSize]byte
	for i := range initRandom {
		initRandom[i] = byte(i)
		respRandom[i] = byte(255 - i)
	}

	original := &PBKDFParamResponse{
		InitiatorRandom:    initRandom,
		ResponderRandom:    respRandom,
		ResponderSessionID: 9999,
		PBKDFParams: &PBKDFParameters{
			Iterations: 1000,
			Salt:       []byte("test salt here!"),
		},
		MRPParams: &MRPParameters{
			IdleRetransTimeout:   3000,
			ActiveRetransTimeout: 5000,
			ActiveThreshold:      6000,
		},
	}

	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := DecodePBKDFParamResponse(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.MRPParams == nil {
		t.Fatal("MRPParams is nil")
	}
	if decoded.MRPParams.IdleRetransTimeout != 3000 {
		t.Errorf("IdleRetransTimeout = %d, want 3000", decoded.MRPParams.IdleRetransTimeout)
	}
	if decoded.MRPParams.ActiveRetransTimeout != 5000 {
		t.Errorf("ActiveRetransTimeout = %d, want 5000", decoded.MRPParams.ActiveRetransTimeout)
	}
	if decoded.MRPParams.ActiveThreshold != 6000 {
		t.Errorf("ActiveThreshold = %d, want 6000", decoded.MRPParams.ActiveThreshold)
	}
}

func TestPake1Roundtrip(t *testing.T) {
	// 65-byte uncompressed P-256 point
	pa := make([]byte, 65)
	pa[0] = 0x04
	for i := 1; i < 65; i++ {
		pa[i] = byte(i)
	}

	original := &Pake1{PA: pa}

	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := DecodePake1(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if !bytes.Equal(decoded.PA, original.PA) {
		t.Error("PA mismatch")
	}
}

func TestPake2Roundtrip(t *testing.T) {
	pb := make([]byte, 65)
	pb[0] = 0x04
	for i := 1; i < 65; i++ {
		pb[i] = byte(i)
	}

	cb := make([]byte, 32)
	for i := range cb {
		cb[i] = byte(255 - i)
	}

	original := &Pake2{PB: pb, CB: cb}

	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := DecodePake2(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if !bytes.Equal(decoded.PB, original.PB) {
		t.Error("PB mismatch")
	}
	if !bytes.Equal(decoded.CB, original.CB) {
		t.Error("CB mismatch")
	}
}

func TestPake3Roundtrip(t *testing.T) {
	ca := make([]byte, 32)
	for i := range ca {
		ca[i] = byte(i * 2)
	}

	original := &Pake3{CA: ca}

	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := DecodePake3(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if !bytes.Equal(decoded.CA, original.CA) {
		t.Error("CA mismatch")
	}
}

func TestDecodeInvalidMessages(t *testing.T) {
	t.Run("empty_data", func(t *testing.T) {
		_, err := DecodePBKDFParamRequest([]byte{})
		if err == nil {
			t.Error("Expected error for empty data")
		}
	})

	t.Run("truncated_pake1", func(t *testing.T) {
		_, err := DecodePake1([]byte{0x15, 0x30, 0x01}) // Truncated
		if err == nil {
			t.Error("Expected error for truncated data")
		}
	})

	t.Run("missing_pake2_cb", func(t *testing.T) {
		// Encode Pake2 with only PB, missing CB
		pake1 := &Pake1{PA: make([]byte, 65)}
		encoded, _ := pake1.Encode()

		_, err := DecodePake2(encoded)
		if err == nil {
			t.Error("Expected error for missing CB")
		}
	})
}
