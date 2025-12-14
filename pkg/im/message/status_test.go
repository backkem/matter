package message

import "testing"

func TestStatus_String(t *testing.T) {
	tests := []struct {
		status Status
		want   string
	}{
		{StatusSuccess, "Success"},
		{StatusFailure, "Failure"},
		{StatusInvalidSubscription, "InvalidSubscription"},
		{StatusUnsupportedAccess, "UnsupportedAccess"},
		{StatusUnsupportedEndpoint, "UnsupportedEndpoint"},
		{StatusInvalidAction, "InvalidAction"},
		{StatusUnsupportedCommand, "UnsupportedCommand"},
		{StatusInvalidCommand, "InvalidCommand"},
		{StatusUnsupportedAttribute, "UnsupportedAttribute"},
		{StatusConstraintError, "ConstraintError"},
		{StatusUnsupportedWrite, "UnsupportedWrite"},
		{StatusResourceExhausted, "ResourceExhausted"},
		{StatusNotFound, "NotFound"},
		{StatusUnreportableAttribute, "UnreportableAttribute"},
		{StatusInvalidDataType, "InvalidDataType"},
		{StatusUnsupportedRead, "UnsupportedRead"},
		{StatusDataVersionMismatch, "DataVersionMismatch"},
		{StatusTimeout, "Timeout"},
		{StatusBusy, "Busy"},
		{StatusAccessRestricted, "AccessRestricted"},
		{StatusUnsupportedCluster, "UnsupportedCluster"},
		{StatusNoUpstreamSubscription, "NoUpstreamSubscription"},
		{StatusNeedsTimedInteraction, "NeedsTimedInteraction"},
		{StatusUnsupportedEvent, "UnsupportedEvent"},
		{StatusPathsExhausted, "PathsExhausted"},
		{StatusTimedRequestMismatch, "TimedRequestMismatch"},
		{StatusFailsafeRequired, "FailsafeRequired"},
		{StatusInvalidInState, "InvalidInState"},
		{StatusNoCommandResponse, "NoCommandResponse"},
		{Status(0xFF), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.status.String(); got != tt.want {
				t.Errorf("Status.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStatus_IsSuccess(t *testing.T) {
	if !StatusSuccess.IsSuccess() {
		t.Error("StatusSuccess.IsSuccess() should be true")
	}
	if StatusFailure.IsSuccess() {
		t.Error("StatusFailure.IsSuccess() should be false")
	}
}

func TestStatus_IsFailure(t *testing.T) {
	if StatusSuccess.IsFailure() {
		t.Error("StatusSuccess.IsFailure() should be false")
	}
	if !StatusFailure.IsFailure() {
		t.Error("StatusFailure.IsFailure() should be true")
	}
}

func TestOpcode_String(t *testing.T) {
	tests := []struct {
		opcode Opcode
		want   string
	}{
		{OpcodeStatusResponse, "StatusResponse"},
		{OpcodeReadRequest, "ReadRequest"},
		{OpcodeSubscribeRequest, "SubscribeRequest"},
		{OpcodeSubscribeResponse, "SubscribeResponse"},
		{OpcodeReportData, "ReportData"},
		{OpcodeWriteRequest, "WriteRequest"},
		{OpcodeWriteResponse, "WriteResponse"},
		{OpcodeInvokeRequest, "InvokeRequest"},
		{OpcodeInvokeResponse, "InvokeResponse"},
		{OpcodeTimedRequest, "TimedRequest"},
		{Opcode(0xFF), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.opcode.String(); got != tt.want {
				t.Errorf("Opcode.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
