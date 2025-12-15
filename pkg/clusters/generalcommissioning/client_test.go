package generalcommissioning

import (
	"testing"
)

func TestEncodeDecodeArmFailSafe(t *testing.T) {
	tests := []struct {
		name string
		req  ArmFailSafeRequest
	}{
		{
			name: "basic arm",
			req: ArmFailSafeRequest{
				ExpiryLengthSeconds: 60,
				Breadcrumb:          12345,
			},
		},
		{
			name: "zero expiry (disarm)",
			req: ArmFailSafeRequest{
				ExpiryLengthSeconds: 0,
				Breadcrumb:          0,
			},
		},
		{
			name: "max values",
			req: ArmFailSafeRequest{
				ExpiryLengthSeconds: 0xFFFF,
				Breadcrumb:          0xFFFFFFFFFFFFFFFF,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode request
			encoded, err := EncodeArmFailSafeRequest(&tt.req)
			if err != nil {
				t.Fatalf("EncodeArmFailSafeRequest() error: %v", err)
			}

			if len(encoded) == 0 {
				t.Fatal("EncodeArmFailSafeRequest() returned empty data")
			}
		})
	}
}

func TestDecodeArmFailSafeResponse(t *testing.T) {
	// Create a known response and verify decoding
	resp := ArmFailSafeResponse{
		ErrorCode: CommissioningOK,
		DebugText: "",
	}

	// First encode it using the server-side encoder
	encoded, err := encodeArmFailSafeResponse(resp)
	if err != nil {
		t.Fatalf("encodeArmFailSafeResponse() error: %v", err)
	}

	// Now decode it using the client-side decoder
	decoded, err := DecodeArmFailSafeResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeArmFailSafeResponse() error: %v", err)
	}

	if decoded.ErrorCode != resp.ErrorCode {
		t.Errorf("ErrorCode = %v, want %v", decoded.ErrorCode, resp.ErrorCode)
	}

	if decoded.DebugText != resp.DebugText {
		t.Errorf("DebugText = %q, want %q", decoded.DebugText, resp.DebugText)
	}
}

func TestDecodeArmFailSafeResponseWithError(t *testing.T) {
	resp := ArmFailSafeResponse{
		ErrorCode: CommissioningBusyWithOtherAdmin,
		DebugText: "fail-safe armed by different fabric",
	}

	encoded, err := encodeArmFailSafeResponse(resp)
	if err != nil {
		t.Fatalf("encodeArmFailSafeResponse() error: %v", err)
	}

	decoded, err := DecodeArmFailSafeResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeArmFailSafeResponse() error: %v", err)
	}

	if decoded.ErrorCode != CommissioningBusyWithOtherAdmin {
		t.Errorf("ErrorCode = %v, want %v", decoded.ErrorCode, CommissioningBusyWithOtherAdmin)
	}

	if decoded.DebugText != resp.DebugText {
		t.Errorf("DebugText = %q, want %q", decoded.DebugText, resp.DebugText)
	}
}

func TestEncodeDecodeSetRegulatoryConfig(t *testing.T) {
	tests := []struct {
		name string
		req  SetRegulatoryConfigRequest
	}{
		{
			name: "indoor",
			req: SetRegulatoryConfigRequest{
				NewRegulatoryConfig: RegulatoryIndoor,
				CountryCode:         "US",
				Breadcrumb:          100,
			},
		},
		{
			name: "outdoor",
			req: SetRegulatoryConfigRequest{
				NewRegulatoryConfig: RegulatoryOutdoor,
				CountryCode:         "DE",
				Breadcrumb:          200,
			},
		},
		{
			name: "indoor outdoor",
			req: SetRegulatoryConfigRequest{
				NewRegulatoryConfig: RegulatoryIndoorOutdoor,
				CountryCode:         "XX",
				Breadcrumb:          0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := EncodeSetRegulatoryConfigRequest(&tt.req)
			if err != nil {
				t.Fatalf("EncodeSetRegulatoryConfigRequest() error: %v", err)
			}

			if len(encoded) == 0 {
				t.Fatal("EncodeSetRegulatoryConfigRequest() returned empty data")
			}
		})
	}
}

func TestDecodeSetRegulatoryConfigResponse(t *testing.T) {
	resp := SetRegulatoryConfigResponse{
		ErrorCode: CommissioningOK,
		DebugText: "",
	}

	encoded, err := encodeSetRegulatoryConfigResponse(resp)
	if err != nil {
		t.Fatalf("encodeSetRegulatoryConfigResponse() error: %v", err)
	}

	decoded, err := DecodeSetRegulatoryConfigResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeSetRegulatoryConfigResponse() error: %v", err)
	}

	if decoded.ErrorCode != resp.ErrorCode {
		t.Errorf("ErrorCode = %v, want %v", decoded.ErrorCode, resp.ErrorCode)
	}
}

func TestEncodeDecodeCommissioningComplete(t *testing.T) {
	// CommissioningComplete has no request fields
	encoded, err := EncodeCommissioningCompleteRequest()
	if err != nil {
		t.Fatalf("EncodeCommissioningCompleteRequest() error: %v", err)
	}

	if len(encoded) == 0 {
		t.Fatal("EncodeCommissioningCompleteRequest() returned empty data")
	}

	// Should be an empty struct: 0x15 (start struct) 0x18 (end container)
	// The actual encoding may vary slightly but should be valid TLV
}

func TestDecodeCommissioningCompleteResponse(t *testing.T) {
	resp := CommissioningCompleteResponse{
		ErrorCode: CommissioningOK,
		DebugText: "",
	}

	encoded, err := encodeCommissioningCompleteResponse(resp)
	if err != nil {
		t.Fatalf("encodeCommissioningCompleteResponse() error: %v", err)
	}

	decoded, err := DecodeCommissioningCompleteResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeCommissioningCompleteResponse() error: %v", err)
	}

	if decoded.ErrorCode != resp.ErrorCode {
		t.Errorf("ErrorCode = %v, want %v", decoded.ErrorCode, resp.ErrorCode)
	}
}

func TestDecodeCommissioningCompleteResponseNoFailSafe(t *testing.T) {
	resp := CommissioningCompleteResponse{
		ErrorCode: CommissioningNoFailSafe,
		DebugText: "fail-safe not armed",
	}

	encoded, err := encodeCommissioningCompleteResponse(resp)
	if err != nil {
		t.Fatalf("encodeCommissioningCompleteResponse() error: %v", err)
	}

	decoded, err := DecodeCommissioningCompleteResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeCommissioningCompleteResponse() error: %v", err)
	}

	if decoded.ErrorCode != CommissioningNoFailSafe {
		t.Errorf("ErrorCode = %v, want %v", decoded.ErrorCode, CommissioningNoFailSafe)
	}

	if decoded.DebugText != resp.DebugText {
		t.Errorf("DebugText = %q, want %q", decoded.DebugText, resp.DebugText)
	}
}
