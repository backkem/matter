// Package securechannel implements the Matter Secure Channel Protocol.
//
// This package provides constants and types for secure channel operations
// including PASE (Passcode-Authenticated Session Establishment) and
// CASE (Certificate Authenticated Session Establishment).
//
// See Matter Specification Section 4.11.
package securechannel

// ProtocolID is the Secure Channel protocol identifier.
const ProtocolID uint16 = 0x0000

// Opcode represents a Secure Channel protocol message type.
type Opcode uint8

// Secure Channel Protocol Opcodes (Table 18).
const (
	// Message Counter Synchronization
	OpcodeMsgCounterSyncReq  Opcode = 0x00
	OpcodeMsgCounterSyncResp Opcode = 0x01

	// Reliable Messaging Protocol
	OpcodeStandaloneAck Opcode = 0x10

	// PASE (Password-based session establishment)
	OpcodePBKDFParamRequest  Opcode = 0x20
	OpcodePBKDFParamResponse Opcode = 0x21
	OpcodePASEPake1          Opcode = 0x22
	OpcodePASEPake2          Opcode = 0x23
	OpcodePASEPake3          Opcode = 0x24

	// CASE (Certificate-based session establishment)
	OpcodeCASESigma1       Opcode = 0x30
	OpcodeCASESigma2       Opcode = 0x31
	OpcodeCASESigma3       Opcode = 0x32
	OpcodeCASESigma2Resume Opcode = 0x33

	// Status and ICD
	OpcodeStatusReport Opcode = 0x40
	OpcodeICDCheckIn   Opcode = 0x50
)

// String returns the opcode name.
func (o Opcode) String() string {
	switch o {
	case OpcodeMsgCounterSyncReq:
		return "MsgCounterSyncReq"
	case OpcodeMsgCounterSyncResp:
		return "MsgCounterSyncResp"
	case OpcodeStandaloneAck:
		return "StandaloneAck"
	case OpcodePBKDFParamRequest:
		return "PBKDFParamRequest"
	case OpcodePBKDFParamResponse:
		return "PBKDFParamResponse"
	case OpcodePASEPake1:
		return "PASE_Pake1"
	case OpcodePASEPake2:
		return "PASE_Pake2"
	case OpcodePASEPake3:
		return "PASE_Pake3"
	case OpcodeCASESigma1:
		return "CASE_Sigma1"
	case OpcodeCASESigma2:
		return "CASE_Sigma2"
	case OpcodeCASESigma3:
		return "CASE_Sigma3"
	case OpcodeCASESigma2Resume:
		return "CASE_Sigma2Resume"
	case OpcodeStatusReport:
		return "StatusReport"
	case OpcodeICDCheckIn:
		return "ICD_CheckIn"
	default:
		return "Unknown"
	}
}

// GeneralCode represents protocol-agnostic status codes (Appendix D.3.1).
type GeneralCode uint16

const (
	GeneralCodeSuccess           GeneralCode = 0
	GeneralCodeFailure           GeneralCode = 1
	GeneralCodeBadPrecondition   GeneralCode = 2
	GeneralCodeOutOfRange        GeneralCode = 3
	GeneralCodeBadRequest        GeneralCode = 4
	GeneralCodeUnsupported       GeneralCode = 5
	GeneralCodeUnexpected        GeneralCode = 6
	GeneralCodeResourceExhausted GeneralCode = 7
	GeneralCodeBusy              GeneralCode = 8
	GeneralCodeTimeout           GeneralCode = 9
	GeneralCodeContinue          GeneralCode = 10
	GeneralCodeAborted           GeneralCode = 11
	GeneralCodeInvalidArgument   GeneralCode = 12
	GeneralCodeNotFound          GeneralCode = 13
	GeneralCodeAlreadyExists     GeneralCode = 14
	GeneralCodePermissionDenied  GeneralCode = 15
	GeneralCodeDataLoss          GeneralCode = 16
)

// String returns the general code name.
func (g GeneralCode) String() string {
	switch g {
	case GeneralCodeSuccess:
		return "SUCCESS"
	case GeneralCodeFailure:
		return "FAILURE"
	case GeneralCodeBadPrecondition:
		return "BAD_PRECONDITION"
	case GeneralCodeOutOfRange:
		return "OUT_OF_RANGE"
	case GeneralCodeBadRequest:
		return "BAD_REQUEST"
	case GeneralCodeUnsupported:
		return "UNSUPPORTED"
	case GeneralCodeUnexpected:
		return "UNEXPECTED"
	case GeneralCodeResourceExhausted:
		return "RESOURCE_EXHAUSTED"
	case GeneralCodeBusy:
		return "BUSY"
	case GeneralCodeTimeout:
		return "TIMEOUT"
	case GeneralCodeContinue:
		return "CONTINUE"
	case GeneralCodeAborted:
		return "ABORTED"
	case GeneralCodeInvalidArgument:
		return "INVALID_ARGUMENT"
	case GeneralCodeNotFound:
		return "NOT_FOUND"
	case GeneralCodeAlreadyExists:
		return "ALREADY_EXISTS"
	case GeneralCodePermissionDenied:
		return "PERMISSION_DENIED"
	case GeneralCodeDataLoss:
		return "DATA_LOSS"
	default:
		return "UNKNOWN"
	}
}

// ProtocolCode represents Secure Channel specific status codes (Table 19).
type ProtocolCode uint16

const (
	ProtocolCodeSuccess         ProtocolCode = 0x0000
	ProtocolCodeNoSharedRoot    ProtocolCode = 0x0001
	ProtocolCodeInvalidParam    ProtocolCode = 0x0002
	ProtocolCodeCloseSession    ProtocolCode = 0x0003
	ProtocolCodeBusy            ProtocolCode = 0x0004
	ProtocolCodeSessionNotFound ProtocolCode = 0x0005
	ProtocolCodeGeneralFailure  ProtocolCode = 0xFFFF
)

// String returns the protocol code name.
func (p ProtocolCode) String() string {
	switch p {
	case ProtocolCodeSuccess:
		return "SESSION_ESTABLISHED"
	case ProtocolCodeNoSharedRoot:
		return "NO_SHARED_TRUST_ROOTS"
	case ProtocolCodeInvalidParam:
		return "INVALID_PARAMETER"
	case ProtocolCodeCloseSession:
		return "CLOSE_SESSION"
	case ProtocolCodeBusy:
		return "BUSY"
	case ProtocolCodeSessionNotFound:
		return "SESSION_NOT_FOUND"
	case ProtocolCodeGeneralFailure:
		return "GENERAL_FAILURE"
	default:
		return "UNKNOWN"
	}
}
