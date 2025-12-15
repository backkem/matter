package commissioning

// CommissionerState represents the commissioner state machine.
// The commissioner progresses through these states during the commissioning flow.
type CommissionerState int

const (
	// CommissionerStateIdle is the initial state before commissioning starts.
	CommissionerStateIdle CommissionerState = iota

	// CommissionerStateDiscovering indicates the commissioner is searching
	// for commissionable devices via DNS-SD.
	CommissionerStateDiscovering

	// CommissionerStateConnecting indicates the commissioner is establishing
	// a transport connection to the device.
	CommissionerStateConnecting

	// CommissionerStatePASE indicates the commissioner is performing the
	// PASE handshake to establish a secure channel.
	CommissionerStatePASE

	// CommissionerStateArmingFailSafe indicates the commissioner is arming
	// the fail-safe timer on the device.
	CommissionerStateArmingFailSafe

	// CommissionerStateDeviceAttestation indicates the commissioner is
	// performing device attestation verification.
	CommissionerStateDeviceAttestation

	// CommissionerStateCSRRequest indicates the commissioner is requesting
	// a Certificate Signing Request from the device.
	CommissionerStateCSRRequest

	// CommissionerStateAddNOC indicates the commissioner is adding the
	// Node Operational Certificate to the device.
	CommissionerStateAddNOC

	// CommissionerStateNetworkConfig indicates the commissioner is
	// configuring the operational network (Wi-Fi/Thread) on the device.
	CommissionerStateNetworkConfig

	// CommissionerStateOperationalDiscovery indicates the commissioner is
	// discovering the device on the operational network via DNS-SD.
	CommissionerStateOperationalDiscovery

	// CommissionerStateCASE indicates the commissioner is establishing
	// a CASE session with the commissioned device.
	CommissionerStateCASE

	// CommissionerStateComplete indicates commissioning completed successfully.
	CommissionerStateComplete

	// CommissionerStateFailed indicates commissioning failed.
	CommissionerStateFailed
)

// String returns a human-readable representation of the commissioner state.
func (s CommissionerState) String() string {
	switch s {
	case CommissionerStateIdle:
		return "Idle"
	case CommissionerStateDiscovering:
		return "Discovering"
	case CommissionerStateConnecting:
		return "Connecting"
	case CommissionerStatePASE:
		return "PASE"
	case CommissionerStateArmingFailSafe:
		return "ArmingFailSafe"
	case CommissionerStateDeviceAttestation:
		return "DeviceAttestation"
	case CommissionerStateCSRRequest:
		return "CSRRequest"
	case CommissionerStateAddNOC:
		return "AddNOC"
	case CommissionerStateNetworkConfig:
		return "NetworkConfig"
	case CommissionerStateOperationalDiscovery:
		return "OperationalDiscovery"
	case CommissionerStateCASE:
		return "CASE"
	case CommissionerStateComplete:
		return "Complete"
	case CommissionerStateFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// IsTerminal returns true if this is a terminal state (Complete or Failed).
func (s CommissionerState) IsTerminal() bool {
	return s == CommissionerStateComplete || s == CommissionerStateFailed
}

// DeviceCommissioningState represents the device's commissioning state.
type DeviceCommissioningState int

const (
	// DeviceStateUncommissioned indicates the device has never been commissioned.
	DeviceStateUncommissioned DeviceCommissioningState = iota

	// DeviceStateAdvertising indicates the device is advertising for commissioning
	// via DNS-SD (_matterc._udp).
	DeviceStateAdvertising

	// DeviceStatePASEPending indicates a PASE session request has been received
	// and is being processed.
	DeviceStatePASEPending

	// DeviceStatePASEEstablished indicates a PASE session has been established
	// and the device is awaiting commissioning commands.
	DeviceStatePASEEstablished

	// DeviceStateCommissioning indicates the device is actively being commissioned
	// (fail-safe armed, receiving credentials).
	DeviceStateCommissioning

	// DeviceStateCommissioned indicates the device has been successfully
	// commissioned to at least one fabric.
	DeviceStateCommissioned
)

// String returns a human-readable representation of the device state.
func (s DeviceCommissioningState) String() string {
	switch s {
	case DeviceStateUncommissioned:
		return "Uncommissioned"
	case DeviceStateAdvertising:
		return "Advertising"
	case DeviceStatePASEPending:
		return "PASEPending"
	case DeviceStatePASEEstablished:
		return "PASEEstablished"
	case DeviceStateCommissioning:
		return "Commissioning"
	case DeviceStateCommissioned:
		return "Commissioned"
	default:
		return "Unknown"
	}
}

// IsCommissionable returns true if the device can accept commissioning.
func (s DeviceCommissioningState) IsCommissionable() bool {
	return s == DeviceStateAdvertising || s == DeviceStatePASEPending
}
