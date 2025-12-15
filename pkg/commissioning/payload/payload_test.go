package payload

import "testing"

func TestDiscriminator(t *testing.T) {
	t.Run("long discriminator", func(t *testing.T) {
		d := NewLongDiscriminator(0x80) // 128
		if d.IsShort() {
			t.Error("expected long discriminator")
		}
		if d.Long() != 0x80 {
			t.Errorf("Long() = %d, want %d", d.Long(), 0x80)
		}
		// Short value is MSBs: 0x80 >> 8 = 0
		if d.Short() != 0 {
			t.Errorf("Short() = %d, want %d", d.Short(), 0)
		}
	})

	t.Run("long discriminator MSBs", func(t *testing.T) {
		d := NewLongDiscriminator(0xA1F) // 2591
		if d.Short() != 0xA { // 0xA1F >> 8 = 0xA
			t.Errorf("Short() = %d, want %d", d.Short(), 0xA)
		}
	})

	t.Run("short discriminator", func(t *testing.T) {
		d := NewShortDiscriminator(0xA)
		if !d.IsShort() {
			t.Error("expected short discriminator")
		}
		if d.Short() != 0xA {
			t.Errorf("Short() = %d, want %d", d.Short(), 0xA)
		}
	})

	t.Run("matching", func(t *testing.T) {
		short := NewShortDiscriminator(0xA)
		long := NewLongDiscriminator(0xA1F) // MSBs = 0xA

		if !short.Matches(0xA1F) {
			t.Error("short should match long 0xA1F")
		}
		if !short.Matches(0xA00) {
			t.Error("short should match long 0xA00")
		}
		if short.Matches(0xB00) {
			t.Error("short should not match long 0xB00")
		}

		if !long.Matches(0xA1F) {
			t.Error("long should match same value")
		}
		if long.Matches(0xA1E) {
			t.Error("long should not match different value")
		}
	})

	t.Run("string", func(t *testing.T) {
		if s := NewLongDiscriminator(128).String(); s != "long:128" {
			t.Errorf("String() = %q", s)
		}
		if s := NewShortDiscriminator(10).String(); s != "short:10" {
			t.Errorf("String() = %q", s)
		}
	})
}

func TestDiscoveryCapabilities(t *testing.T) {
	t.Run("has", func(t *testing.T) {
		caps := DiscoveryCapabilityBLE | DiscoveryCapabilityOnNetwork
		if !caps.Has(DiscoveryCapabilityBLE) {
			t.Error("should have BLE")
		}
		if !caps.Has(DiscoveryCapabilityOnNetwork) {
			t.Error("should have OnNetwork")
		}
		if caps.Has(DiscoveryCapabilitySoftAP) {
			t.Error("should not have SoftAP")
		}
	})

	t.Run("string", func(t *testing.T) {
		tests := []struct {
			caps DiscoveryCapabilities
			want string
		}{
			{0, "none"},
			{DiscoveryCapabilityBLE, "BLE"},
			{DiscoveryCapabilityBLE | DiscoveryCapabilityOnNetwork, "BLE|OnNetwork"},
			{DiscoveryCapabilitySoftAP | DiscoveryCapabilityBLE | DiscoveryCapabilityOnNetwork |
				DiscoveryCapabilityWiFiPAF | DiscoveryCapabilityNFC, "SoftAP|BLE|OnNetwork|WiFiPAF|NFC"},
		}
		for _, tt := range tests {
			if got := tt.caps.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		}
	})
}

func TestCommissioningFlow(t *testing.T) {
	tests := []struct {
		flow CommissioningFlow
		want string
	}{
		{CommissioningFlowStandard, "Standard"},
		{CommissioningFlowUserIntent, "UserIntent"},
		{CommissioningFlowCustom, "Custom"},
		{CommissioningFlow(99), "Unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.flow.String(); got != tt.want {
			t.Errorf("String() = %q, want %q", got, tt.want)
		}
	}
}

func TestValidatePasscode(t *testing.T) {
	tests := []struct {
		name     string
		passcode uint32
		wantErr  bool
	}{
		// Valid passcodes
		{name: "min valid", passcode: 1, wantErr: false},
		{name: "max valid", passcode: 99999998, wantErr: false},
		{name: "2048", passcode: 2048, wantErr: false},
		{name: "12345679", passcode: 12345679, wantErr: false},

		// Invalid: out of range
		{name: "zero", passcode: 0, wantErr: true},
		{name: "too large", passcode: 99999999, wantErr: true},

		// Invalid: forbidden values
		{name: "11111111", passcode: 11111111, wantErr: true},
		{name: "22222222", passcode: 22222222, wantErr: true},
		{name: "33333333", passcode: 33333333, wantErr: true},
		{name: "44444444", passcode: 44444444, wantErr: true},
		{name: "55555555", passcode: 55555555, wantErr: true},
		{name: "66666666", passcode: 66666666, wantErr: true},
		{name: "77777777", passcode: 77777777, wantErr: true},
		{name: "88888888", passcode: 88888888, wantErr: true},
		{name: "99999999", passcode: 99999999, wantErr: true},
		{name: "12345678", passcode: 12345678, wantErr: true},
		{name: "87654321", passcode: 87654321, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasscode(tt.passcode)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePasscode(%d) error = %v, wantErr %v", tt.passcode, err, tt.wantErr)
			}
		})
	}
}

func TestSetupPayloadValidate(t *testing.T) {
	validPayload := func() *SetupPayload {
		return &SetupPayload{
			Version:                  0,
			VendorID:                 12,
			ProductID:                1,
			CommissioningFlow:        CommissioningFlowStandard,
			DiscoveryCapabilities:    DiscoveryCapabilitySoftAP,
			HasDiscoveryCapabilities: true,
			Discriminator:            NewLongDiscriminator(128),
			Passcode:                 2048,
		}
	}

	t.Run("valid payload", func(t *testing.T) {
		p := validPayload()
		if err := p.Validate(ValidationModeProduce); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid version", func(t *testing.T) {
		p := validPayload()
		p.Version = 1
		if err := p.Validate(ValidationModeProduce); err != ErrInvalidVersion {
			t.Errorf("expected ErrInvalidVersion, got %v", err)
		}
	})

	t.Run("invalid passcode", func(t *testing.T) {
		p := validPayload()
		p.Passcode = 0
		if err := p.Validate(ValidationModeProduce); err != ErrInvalidPasscode {
			t.Errorf("expected ErrInvalidPasscode, got %v", err)
		}
	})

	t.Run("invalid commissioning flow (produce)", func(t *testing.T) {
		p := validPayload()
		p.CommissioningFlow = 99
		if err := p.Validate(ValidationModeProduce); err != ErrInvalidCommissioningFlow {
			t.Errorf("expected ErrInvalidCommissioningFlow, got %v", err)
		}
	})

	t.Run("unknown commissioning flow (consume)", func(t *testing.T) {
		p := validPayload()
		p.CommissioningFlow = 99
		// Should be OK in consume mode
		if err := p.Validate(ValidationModeConsume); err != nil {
			t.Errorf("unexpected error in consume mode: %v", err)
		}
	})

	t.Run("unknown discovery capabilities (produce)", func(t *testing.T) {
		p := validPayload()
		p.DiscoveryCapabilities = 0xFF // Unknown bits set
		if err := p.Validate(ValidationModeProduce); err != ErrInvalidDiscoveryCapabilities {
			t.Errorf("expected ErrInvalidDiscoveryCapabilities, got %v", err)
		}
	})

	t.Run("unknown discovery capabilities (consume)", func(t *testing.T) {
		p := validPayload()
		p.DiscoveryCapabilities = 0xFF // Unknown bits set
		// Should be OK in consume mode
		if err := p.Validate(ValidationModeConsume); err != nil {
			t.Errorf("unexpected error in consume mode: %v", err)
		}
	})
}

func TestIsValidQRCodePayload(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		p := &SetupPayload{
			Version:                  0,
			DiscoveryCapabilities:    DiscoveryCapabilityBLE,
			HasDiscoveryCapabilities: true,
			Discriminator:            NewLongDiscriminator(128),
			Passcode:                 2048,
		}
		if !p.IsValidQRCodePayload(ValidationModeProduce) {
			t.Error("expected valid QR code payload")
		}
	})

	t.Run("missing discovery capabilities", func(t *testing.T) {
		p := &SetupPayload{
			Version:       0,
			Discriminator: NewLongDiscriminator(128),
			Passcode:      2048,
		}
		if p.IsValidQRCodePayload(ValidationModeProduce) {
			t.Error("expected invalid: missing discovery capabilities")
		}
	})

	t.Run("short discriminator", func(t *testing.T) {
		p := &SetupPayload{
			Version:                  0,
			DiscoveryCapabilities:    DiscoveryCapabilityBLE,
			HasDiscoveryCapabilities: true,
			Discriminator:            NewShortDiscriminator(10),
			Passcode:                 2048,
		}
		if p.IsValidQRCodePayload(ValidationModeProduce) {
			t.Error("expected invalid: short discriminator")
		}
	})
}

func TestSetupPayloadHelpers(t *testing.T) {
	p := &SetupPayload{
		DiscoveryCapabilities:    DiscoveryCapabilityBLE | DiscoveryCapabilityOnNetwork,
		HasDiscoveryCapabilities: true,
	}

	if !p.SupportsBLE() {
		t.Error("should support BLE")
	}
	if !p.SupportsOnNetworkDiscovery() {
		t.Error("should support on-network discovery")
	}

	// Without discovery capabilities
	p2 := &SetupPayload{}
	if p2.SupportsBLE() {
		t.Error("should not support BLE without capabilities")
	}
}
