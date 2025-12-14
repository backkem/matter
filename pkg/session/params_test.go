package session

import (
	"testing"
	"time"
)

func TestDefaultParams(t *testing.T) {
	params := DefaultParams()

	if params.IdleInterval != DefaultIdleInterval {
		t.Errorf("IdleInterval = %v, want %v", params.IdleInterval, DefaultIdleInterval)
	}
	if params.ActiveInterval != DefaultActiveInterval {
		t.Errorf("ActiveInterval = %v, want %v", params.ActiveInterval, DefaultActiveInterval)
	}
	if params.ActiveThreshold != DefaultActiveThreshold {
		t.Errorf("ActiveThreshold = %v, want %v", params.ActiveThreshold, DefaultActiveThreshold)
	}
}

func TestParams_Validate(t *testing.T) {
	tests := []struct {
		name   string
		params Params
		want   bool
	}{
		{
			name:   "default params are valid",
			params: DefaultParams(),
			want:   true,
		},
		{
			name: "zero idle interval is invalid",
			params: Params{
				IdleInterval:    0,
				ActiveInterval:  DefaultActiveInterval,
				ActiveThreshold: DefaultActiveThreshold,
			},
			want: false,
		},
		{
			name: "zero active interval is invalid",
			params: Params{
				IdleInterval:    DefaultIdleInterval,
				ActiveInterval:  0,
				ActiveThreshold: DefaultActiveThreshold,
			},
			want: false,
		},
		{
			name: "zero active threshold is invalid",
			params: Params{
				IdleInterval:    DefaultIdleInterval,
				ActiveInterval:  DefaultActiveInterval,
				ActiveThreshold: 0,
			},
			want: false,
		},
		{
			name: "idle interval exceeds max",
			params: Params{
				IdleInterval:    MaxIdleInterval + time.Second,
				ActiveInterval:  DefaultActiveInterval,
				ActiveThreshold: DefaultActiveThreshold,
			},
			want: false,
		},
		{
			name: "active interval exceeds max",
			params: Params{
				IdleInterval:    DefaultIdleInterval,
				ActiveInterval:  MaxActiveInterval + time.Second,
				ActiveThreshold: DefaultActiveThreshold,
			},
			want: false,
		},
		{
			name: "active threshold exceeds max",
			params: Params{
				IdleInterval:    DefaultIdleInterval,
				ActiveInterval:  DefaultActiveInterval,
				ActiveThreshold: MaxActiveThreshold + time.Second,
			},
			want: false,
		},
		{
			name: "custom valid params",
			params: Params{
				IdleInterval:    1 * time.Second,
				ActiveInterval:  500 * time.Millisecond,
				ActiveThreshold: 10 * time.Second,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.params.Validate()
			if got != tt.want {
				t.Errorf("Validate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParams_WithDefaults(t *testing.T) {
	// Zero params should get defaults
	zero := Params{}
	filled := zero.WithDefaults()

	if filled.IdleInterval != DefaultIdleInterval {
		t.Errorf("IdleInterval = %v, want %v", filled.IdleInterval, DefaultIdleInterval)
	}
	if filled.ActiveInterval != DefaultActiveInterval {
		t.Errorf("ActiveInterval = %v, want %v", filled.ActiveInterval, DefaultActiveInterval)
	}
	if filled.ActiveThreshold != DefaultActiveThreshold {
		t.Errorf("ActiveThreshold = %v, want %v", filled.ActiveThreshold, DefaultActiveThreshold)
	}

	// Non-zero params should be preserved
	custom := Params{
		IdleInterval:    1 * time.Second,
		ActiveInterval:  2 * time.Second,
		ActiveThreshold: 3 * time.Second,
	}
	preserved := custom.WithDefaults()

	if preserved.IdleInterval != custom.IdleInterval {
		t.Errorf("IdleInterval = %v, want %v", preserved.IdleInterval, custom.IdleInterval)
	}
	if preserved.ActiveInterval != custom.ActiveInterval {
		t.Errorf("ActiveInterval = %v, want %v", preserved.ActiveInterval, custom.ActiveInterval)
	}
	if preserved.ActiveThreshold != custom.ActiveThreshold {
		t.Errorf("ActiveThreshold = %v, want %v", preserved.ActiveThreshold, custom.ActiveThreshold)
	}
}
