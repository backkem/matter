package discovery

import "testing"

func TestServiceType_String(t *testing.T) {
	tests := []struct {
		s    ServiceType
		want string
	}{
		{ServiceTypeUnknown, "Unknown"},
		{ServiceTypeCommissionable, "Commissionable"},
		{ServiceTypeOperational, "Operational"},
		{ServiceTypeCommissioner, "Commissioner"},
		{ServiceType(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("ServiceType(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestServiceType_IsValid(t *testing.T) {
	tests := []struct {
		s    ServiceType
		want bool
	}{
		{ServiceTypeUnknown, false},
		{ServiceTypeCommissionable, true},
		{ServiceTypeOperational, true},
		{ServiceTypeCommissioner, true},
		{ServiceType(99), false},
	}

	for _, tt := range tests {
		if got := tt.s.IsValid(); got != tt.want {
			t.Errorf("ServiceType(%d).IsValid() = %v, want %v", tt.s, got, tt.want)
		}
	}
}

func TestServiceType_ServiceString(t *testing.T) {
	tests := []struct {
		s    ServiceType
		want string
	}{
		{ServiceTypeCommissionable, "_matterc._udp"},
		{ServiceTypeOperational, "_matter._tcp"},
		{ServiceTypeCommissioner, "_matterd._udp"},
		{ServiceTypeUnknown, ""},
		{ServiceType(99), ""},
	}

	for _, tt := range tests {
		if got := tt.s.ServiceString(); got != tt.want {
			t.Errorf("ServiceType(%d).ServiceString() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestCommissioningMode_String(t *testing.T) {
	tests := []struct {
		c    CommissioningMode
		want string
	}{
		{CommissioningModeDisabled, "Disabled"},
		{CommissioningModeBasic, "Basic"},
		{CommissioningModeEnhanced, "Enhanced"},
		{CommissioningMode(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.c.String(); got != tt.want {
			t.Errorf("CommissioningMode(%d).String() = %q, want %q", tt.c, got, tt.want)
		}
	}
}

func TestCommissioningMode_IsValid(t *testing.T) {
	tests := []struct {
		c    CommissioningMode
		want bool
	}{
		{CommissioningModeDisabled, true},
		{CommissioningModeBasic, true},
		{CommissioningModeEnhanced, true},
		{CommissioningMode(-1), false},
		{CommissioningMode(99), false},
	}

	for _, tt := range tests {
		if got := tt.c.IsValid(); got != tt.want {
			t.Errorf("CommissioningMode(%d).IsValid() = %v, want %v", tt.c, got, tt.want)
		}
	}
}

func TestICDMode_String(t *testing.T) {
	tests := []struct {
		i    ICDMode
		want string
	}{
		{ICDModeSIT, "SIT"},
		{ICDModeLIT, "LIT"},
		{ICDMode(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.i.String(); got != tt.want {
			t.Errorf("ICDMode(%d).String() = %q, want %q", tt.i, got, tt.want)
		}
	}
}

func TestICDMode_IsValid(t *testing.T) {
	tests := []struct {
		i    ICDMode
		want bool
	}{
		{ICDModeSIT, true},
		{ICDModeLIT, true},
		{ICDMode(-1), false},
		{ICDMode(99), false},
	}

	for _, tt := range tests {
		if got := tt.i.IsValid(); got != tt.want {
			t.Errorf("ICDMode(%d).IsValid() = %v, want %v", tt.i, got, tt.want)
		}
	}
}
