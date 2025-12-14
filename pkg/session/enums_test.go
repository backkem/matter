package session

import "testing"

func TestSessionType_String(t *testing.T) {
	tests := []struct {
		st   SessionType
		want string
	}{
		{SessionTypeUnknown, "Unknown"},
		{SessionTypePASE, "PASE"},
		{SessionTypeCASE, "CASE"},
		{SessionType(99), "Unknown"},
	}

	for _, tt := range tests {
		got := tt.st.String()
		if got != tt.want {
			t.Errorf("SessionType(%d).String() = %q, want %q", tt.st, got, tt.want)
		}
	}
}

func TestSessionType_IsValid(t *testing.T) {
	tests := []struct {
		st   SessionType
		want bool
	}{
		{SessionTypeUnknown, false},
		{SessionTypePASE, true},
		{SessionTypeCASE, true},
		{SessionType(99), false},
	}

	for _, tt := range tests {
		got := tt.st.IsValid()
		if got != tt.want {
			t.Errorf("SessionType(%d).IsValid() = %v, want %v", tt.st, got, tt.want)
		}
	}
}

func TestSessionRole_String(t *testing.T) {
	tests := []struct {
		sr   SessionRole
		want string
	}{
		{SessionRoleUnknown, "Unknown"},
		{SessionRoleInitiator, "Initiator"},
		{SessionRoleResponder, "Responder"},
		{SessionRole(99), "Unknown"},
	}

	for _, tt := range tests {
		got := tt.sr.String()
		if got != tt.want {
			t.Errorf("SessionRole(%d).String() = %q, want %q", tt.sr, got, tt.want)
		}
	}
}

func TestSessionRole_IsValid(t *testing.T) {
	tests := []struct {
		sr   SessionRole
		want bool
	}{
		{SessionRoleUnknown, false},
		{SessionRoleInitiator, true},
		{SessionRoleResponder, true},
		{SessionRole(99), false},
	}

	for _, tt := range tests {
		got := tt.sr.IsValid()
		if got != tt.want {
			t.Errorf("SessionRole(%d).IsValid() = %v, want %v", tt.sr, got, tt.want)
		}
	}
}
