package securechannel

import (
	"bytes"
	"testing"
)

func TestStatusReportRoundtrip(t *testing.T) {
	tests := []struct {
		name   string
		report *StatusReport
	}{
		{
			name:   "success",
			report: Success(),
		},
		{
			name:   "invalid_param",
			report: InvalidParam(),
		},
		{
			name:   "busy",
			report: Busy(5000),
		},
		{
			name:   "close_session",
			report: CloseSession(),
		},
		{
			name: "custom",
			report: &StatusReport{
				GeneralCode:  GeneralCodeFailure,
				ProtocolID:   0x00010002, // VendorID=1, ProtocolID=2
				ProtocolCode: 0x1234,
				ProtocolData: []byte{0xAB, 0xCD},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := tc.report.Encode()
			decoded, err := DecodeStatusReport(encoded)
			if err != nil {
				t.Fatalf("DecodeStatusReport failed: %v", err)
			}

			if decoded.GeneralCode != tc.report.GeneralCode {
				t.Errorf("GeneralCode = %v, want %v", decoded.GeneralCode, tc.report.GeneralCode)
			}
			if decoded.ProtocolID != tc.report.ProtocolID {
				t.Errorf("ProtocolID = 0x%08X, want 0x%08X", decoded.ProtocolID, tc.report.ProtocolID)
			}
			if decoded.ProtocolCode != tc.report.ProtocolCode {
				t.Errorf("ProtocolCode = 0x%04X, want 0x%04X", decoded.ProtocolCode, tc.report.ProtocolCode)
			}
			if !bytes.Equal(decoded.ProtocolData, tc.report.ProtocolData) {
				t.Errorf("ProtocolData mismatch")
			}
		})
	}
}

func TestStatusReportHelpers(t *testing.T) {
	t.Run("success_is_success", func(t *testing.T) {
		s := Success()
		if !s.IsSuccess() {
			t.Error("Success().IsSuccess() = false")
		}
		if !s.IsSecureChannel() {
			t.Error("Success().IsSecureChannel() = false")
		}
	})

	t.Run("busy_is_busy", func(t *testing.T) {
		s := Busy(3000)
		if !s.IsBusy() {
			t.Error("Busy().IsBusy() = false")
		}
		if s.BusyWaitTime() != 3000 {
			t.Errorf("BusyWaitTime() = %d, want 3000", s.BusyWaitTime())
		}
	})

	t.Run("invalid_param_code", func(t *testing.T) {
		s := InvalidParam()
		if s.SecureChannelCode() != ProtocolCodeInvalidParam {
			t.Errorf("SecureChannelCode() = %v, want InvalidParam", s.SecureChannelCode())
		}
	})
}

func TestDecodeStatusReportTooShort(t *testing.T) {
	_, err := DecodeStatusReport([]byte{0x00, 0x00, 0x00})
	if err != ErrStatusReportTooShort {
		t.Errorf("Expected ErrStatusReportTooShort, got %v", err)
	}
}

func TestStatusReportString(t *testing.T) {
	s := Success()
	str := s.String()
	if str == "" {
		t.Error("String() returned empty string")
	}
	// Should contain "SUCCESS"
	if len(str) < 10 {
		t.Errorf("String() too short: %s", str)
	}
}

func TestGeneralCodeString(t *testing.T) {
	tests := []struct {
		code GeneralCode
		want string
	}{
		{GeneralCodeSuccess, "SUCCESS"},
		{GeneralCodeFailure, "FAILURE"},
		{GeneralCodeBusy, "BUSY"},
		{GeneralCode(999), "UNKNOWN"},
	}

	for _, tc := range tests {
		if got := tc.code.String(); got != tc.want {
			t.Errorf("GeneralCode(%d).String() = %q, want %q", tc.code, got, tc.want)
		}
	}
}

func TestProtocolCodeString(t *testing.T) {
	tests := []struct {
		code ProtocolCode
		want string
	}{
		{ProtocolCodeSuccess, "SESSION_ESTABLISHED"},
		{ProtocolCodeInvalidParam, "INVALID_PARAMETER"},
		{ProtocolCodeBusy, "BUSY"},
		{ProtocolCode(999), "UNKNOWN"},
	}

	for _, tc := range tests {
		if got := tc.code.String(); got != tc.want {
			t.Errorf("ProtocolCode(%d).String() = %q, want %q", tc.code, got, tc.want)
		}
	}
}

func TestOpcodeString(t *testing.T) {
	tests := []struct {
		opcode Opcode
		want   string
	}{
		{OpcodePBKDFParamRequest, "PBKDFParamRequest"},
		{OpcodePBKDFParamResponse, "PBKDFParamResponse"},
		{OpcodePASEPake1, "PASE_Pake1"},
		{OpcodePASEPake2, "PASE_Pake2"},
		{OpcodePASEPake3, "PASE_Pake3"},
		{OpcodeStatusReport, "StatusReport"},
		{Opcode(0xFF), "Unknown"},
	}

	for _, tc := range tests {
		if got := tc.opcode.String(); got != tc.want {
			t.Errorf("Opcode(%d).String() = %q, want %q", tc.opcode, got, tc.want)
		}
	}
}
