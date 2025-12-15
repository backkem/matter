package commissioning

import "testing"

func TestCommissionerStateString(t *testing.T) {
	tests := []struct {
		state CommissionerState
		want  string
	}{
		{CommissionerStateIdle, "Idle"},
		{CommissionerStateDiscovering, "Discovering"},
		{CommissionerStateConnecting, "Connecting"},
		{CommissionerStatePASE, "PASE"},
		{CommissionerStateArmingFailSafe, "ArmingFailSafe"},
		{CommissionerStateDeviceAttestation, "DeviceAttestation"},
		{CommissionerStateCSRRequest, "CSRRequest"},
		{CommissionerStateAddNOC, "AddNOC"},
		{CommissionerStateNetworkConfig, "NetworkConfig"},
		{CommissionerStateOperationalDiscovery, "OperationalDiscovery"},
		{CommissionerStateCASE, "CASE"},
		{CommissionerStateComplete, "Complete"},
		{CommissionerStateFailed, "Failed"},
		{CommissionerState(100), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("CommissionerState(%d).String() = %q, want %q", tt.state, got, tt.want)
			}
		})
	}
}

func TestCommissionerStateIsTerminal(t *testing.T) {
	tests := []struct {
		state      CommissionerState
		isTerminal bool
	}{
		{CommissionerStateIdle, false},
		{CommissionerStateDiscovering, false},
		{CommissionerStatePASE, false},
		{CommissionerStateComplete, true},
		{CommissionerStateFailed, true},
	}

	for _, tt := range tests {
		t.Run(tt.state.String(), func(t *testing.T) {
			if got := tt.state.IsTerminal(); got != tt.isTerminal {
				t.Errorf("CommissionerState(%s).IsTerminal() = %v, want %v", tt.state, got, tt.isTerminal)
			}
		})
	}
}

func TestDeviceCommissioningStateString(t *testing.T) {
	tests := []struct {
		state DeviceCommissioningState
		want  string
	}{
		{DeviceStateUncommissioned, "Uncommissioned"},
		{DeviceStateAdvertising, "Advertising"},
		{DeviceStatePASEPending, "PASEPending"},
		{DeviceStatePASEEstablished, "PASEEstablished"},
		{DeviceStateCommissioning, "Commissioning"},
		{DeviceStateCommissioned, "Commissioned"},
		{DeviceCommissioningState(100), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("DeviceCommissioningState(%d).String() = %q, want %q", tt.state, got, tt.want)
			}
		})
	}
}

func TestDeviceCommissioningStateIsCommissionable(t *testing.T) {
	tests := []struct {
		state           DeviceCommissioningState
		isCommissionable bool
	}{
		{DeviceStateUncommissioned, false},
		{DeviceStateAdvertising, true},
		{DeviceStatePASEPending, true},
		{DeviceStatePASEEstablished, false},
		{DeviceStateCommissioning, false},
		{DeviceStateCommissioned, false},
	}

	for _, tt := range tests {
		t.Run(tt.state.String(), func(t *testing.T) {
			if got := tt.state.IsCommissionable(); got != tt.isCommissionable {
				t.Errorf("DeviceCommissioningState(%s).IsCommissionable() = %v, want %v", tt.state, got, tt.isCommissionable)
			}
		})
	}
}
