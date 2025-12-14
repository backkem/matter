package message

// Status represents an Interaction Model status code.
// Spec: Section 8.10, Table 8-36
type Status uint8

const (
	StatusSuccess               Status = 0x00
	StatusFailure               Status = 0x01
	StatusInvalidSubscription   Status = 0x7d
	StatusUnsupportedAccess     Status = 0x7e
	StatusUnsupportedEndpoint   Status = 0x7f
	StatusInvalidAction         Status = 0x80
	StatusUnsupportedCommand    Status = 0x81
	StatusInvalidCommand        Status = 0x85
	StatusUnsupportedAttribute  Status = 0x86
	StatusConstraintError       Status = 0x87
	StatusUnsupportedWrite      Status = 0x88
	StatusResourceExhausted     Status = 0x89
	StatusNotFound              Status = 0x8b
	StatusUnreportableAttribute Status = 0x8c
	StatusInvalidDataType       Status = 0x8d
	StatusUnsupportedRead       Status = 0x8f
	StatusDataVersionMismatch   Status = 0x92
	StatusTimeout               Status = 0x94
	StatusBusy                  Status = 0x9c
	StatusAccessRestricted      Status = 0x9d
	StatusUnsupportedCluster    Status = 0xc3
	StatusNoUpstreamSubscription Status = 0xc5
	StatusNeedsTimedInteraction Status = 0xc6
	StatusUnsupportedEvent      Status = 0xc7
	StatusPathsExhausted        Status = 0xc8
	StatusTimedRequestMismatch  Status = 0xc9
	StatusFailsafeRequired      Status = 0xca
	StatusInvalidInState        Status = 0xcb
	StatusNoCommandResponse     Status = 0xcc
	StatusDynamicConstraintError Status = 0xcf
	StatusAlreadyExists         Status = 0xd0
	StatusInvalidTransportType  Status = 0xd1
)

// String returns the name of the status code.
func (s Status) String() string {
	switch s {
	case StatusSuccess:
		return "Success"
	case StatusFailure:
		return "Failure"
	case StatusInvalidSubscription:
		return "InvalidSubscription"
	case StatusUnsupportedAccess:
		return "UnsupportedAccess"
	case StatusUnsupportedEndpoint:
		return "UnsupportedEndpoint"
	case StatusInvalidAction:
		return "InvalidAction"
	case StatusUnsupportedCommand:
		return "UnsupportedCommand"
	case StatusInvalidCommand:
		return "InvalidCommand"
	case StatusUnsupportedAttribute:
		return "UnsupportedAttribute"
	case StatusConstraintError:
		return "ConstraintError"
	case StatusUnsupportedWrite:
		return "UnsupportedWrite"
	case StatusResourceExhausted:
		return "ResourceExhausted"
	case StatusNotFound:
		return "NotFound"
	case StatusUnreportableAttribute:
		return "UnreportableAttribute"
	case StatusInvalidDataType:
		return "InvalidDataType"
	case StatusUnsupportedRead:
		return "UnsupportedRead"
	case StatusDataVersionMismatch:
		return "DataVersionMismatch"
	case StatusTimeout:
		return "Timeout"
	case StatusBusy:
		return "Busy"
	case StatusAccessRestricted:
		return "AccessRestricted"
	case StatusUnsupportedCluster:
		return "UnsupportedCluster"
	case StatusNoUpstreamSubscription:
		return "NoUpstreamSubscription"
	case StatusNeedsTimedInteraction:
		return "NeedsTimedInteraction"
	case StatusUnsupportedEvent:
		return "UnsupportedEvent"
	case StatusPathsExhausted:
		return "PathsExhausted"
	case StatusTimedRequestMismatch:
		return "TimedRequestMismatch"
	case StatusFailsafeRequired:
		return "FailsafeRequired"
	case StatusInvalidInState:
		return "InvalidInState"
	case StatusNoCommandResponse:
		return "NoCommandResponse"
	case StatusDynamicConstraintError:
		return "DynamicConstraintError"
	case StatusAlreadyExists:
		return "AlreadyExists"
	case StatusInvalidTransportType:
		return "InvalidTransportType"
	default:
		return "Unknown"
	}
}

// IsSuccess returns true if the status indicates success.
func (s Status) IsSuccess() bool {
	return s == StatusSuccess
}

// IsFailure returns true if the status indicates failure.
func (s Status) IsFailure() bool {
	return s != StatusSuccess
}
