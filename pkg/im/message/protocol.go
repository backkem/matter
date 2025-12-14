package message

// ProtocolID is the Interaction Model protocol identifier.
// Spec: Section 10.2
const ProtocolID uint16 = 0x0001

// Opcode represents an Interaction Model message opcode.
// Spec: Section 10.2.1, Table 10-1
type Opcode uint8

const (
	OpcodeStatusResponse    Opcode = 0x01
	OpcodeReadRequest       Opcode = 0x02
	OpcodeSubscribeRequest  Opcode = 0x03
	OpcodeSubscribeResponse Opcode = 0x04
	OpcodeReportData        Opcode = 0x05
	OpcodeWriteRequest      Opcode = 0x06
	OpcodeWriteResponse     Opcode = 0x07
	OpcodeInvokeRequest     Opcode = 0x08
	OpcodeInvokeResponse    Opcode = 0x09
	OpcodeTimedRequest      Opcode = 0x0a
)

// String returns the name of the opcode.
func (o Opcode) String() string {
	switch o {
	case OpcodeStatusResponse:
		return "StatusResponse"
	case OpcodeReadRequest:
		return "ReadRequest"
	case OpcodeSubscribeRequest:
		return "SubscribeRequest"
	case OpcodeSubscribeResponse:
		return "SubscribeResponse"
	case OpcodeReportData:
		return "ReportData"
	case OpcodeWriteRequest:
		return "WriteRequest"
	case OpcodeWriteResponse:
		return "WriteResponse"
	case OpcodeInvokeRequest:
		return "InvokeRequest"
	case OpcodeInvokeResponse:
		return "InvokeResponse"
	case OpcodeTimedRequest:
		return "TimedRequest"
	default:
		return "Unknown"
	}
}
