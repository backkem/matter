package acl

import "testing"

func TestPrivilege_String(t *testing.T) {
	tests := []struct {
		p    Privilege
		want string
	}{
		{PrivilegeView, "View"},
		{PrivilegeProxyView, "ProxyView"},
		{PrivilegeOperate, "Operate"},
		{PrivilegeManage, "Manage"},
		{PrivilegeAdminister, "Administer"},
		{Privilege(0), "Unknown"},
		{Privilege(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.p.String(); got != tt.want {
			t.Errorf("Privilege(%d).String() = %q, want %q", tt.p, got, tt.want)
		}
	}
}

func TestPrivilege_IsValid(t *testing.T) {
	tests := []struct {
		p    Privilege
		want bool
	}{
		{Privilege(0), false},
		{PrivilegeView, true},
		{PrivilegeProxyView, true},
		{PrivilegeOperate, true},
		{PrivilegeManage, true},
		{PrivilegeAdminister, true},
		{Privilege(6), false},
		{Privilege(99), false},
	}

	for _, tt := range tests {
		if got := tt.p.IsValid(); got != tt.want {
			t.Errorf("Privilege(%d).IsValid() = %v, want %v", tt.p, got, tt.want)
		}
	}
}

func TestPrivilege_Grants(t *testing.T) {
	// Test privilege hierarchy from C++ CheckRequestPrivilegeAgainstEntryPrivilege
	tests := []struct {
		entry     Privilege
		requested Privilege
		want      bool
	}{
		// View grants only View
		{PrivilegeView, PrivilegeView, true},
		{PrivilegeView, PrivilegeProxyView, false},
		{PrivilegeView, PrivilegeOperate, false},
		{PrivilegeView, PrivilegeManage, false},
		{PrivilegeView, PrivilegeAdminister, false},

		// ProxyView grants ProxyView and View
		{PrivilegeProxyView, PrivilegeView, true},
		{PrivilegeProxyView, PrivilegeProxyView, true},
		{PrivilegeProxyView, PrivilegeOperate, false},
		{PrivilegeProxyView, PrivilegeManage, false},
		{PrivilegeProxyView, PrivilegeAdminister, false},

		// Operate grants Operate and View
		{PrivilegeOperate, PrivilegeView, true},
		{PrivilegeOperate, PrivilegeProxyView, false},
		{PrivilegeOperate, PrivilegeOperate, true},
		{PrivilegeOperate, PrivilegeManage, false},
		{PrivilegeOperate, PrivilegeAdminister, false},

		// Manage grants Manage, Operate, and View
		{PrivilegeManage, PrivilegeView, true},
		{PrivilegeManage, PrivilegeProxyView, false},
		{PrivilegeManage, PrivilegeOperate, true},
		{PrivilegeManage, PrivilegeManage, true},
		{PrivilegeManage, PrivilegeAdminister, false},

		// Administer grants all
		{PrivilegeAdminister, PrivilegeView, true},
		{PrivilegeAdminister, PrivilegeProxyView, true},
		{PrivilegeAdminister, PrivilegeOperate, true},
		{PrivilegeAdminister, PrivilegeManage, true},
		{PrivilegeAdminister, PrivilegeAdminister, true},

		// Invalid privilege grants nothing
		{Privilege(0), PrivilegeView, false},
		{Privilege(99), PrivilegeView, false},
	}

	for _, tt := range tests {
		got := tt.entry.Grants(tt.requested)
		if got != tt.want {
			t.Errorf("%s.Grants(%s) = %v, want %v", tt.entry, tt.requested, got, tt.want)
		}
	}
}

func TestAuthMode_String(t *testing.T) {
	tests := []struct {
		m    AuthMode
		want string
	}{
		{AuthModeUnknown, "Unknown"},
		{AuthModePASE, "PASE"},
		{AuthModeCASE, "CASE"},
		{AuthModeGroup, "Group"},
		{AuthMode(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.m.String(); got != tt.want {
			t.Errorf("AuthMode(%d).String() = %q, want %q", tt.m, got, tt.want)
		}
	}
}

func TestAuthMode_IsValid(t *testing.T) {
	tests := []struct {
		m    AuthMode
		want bool
	}{
		{AuthModeUnknown, false},
		{AuthModePASE, true},
		{AuthModeCASE, true},
		{AuthModeGroup, true},
		{AuthMode(4), false},
		{AuthMode(99), false},
	}

	for _, tt := range tests {
		if got := tt.m.IsValid(); got != tt.want {
			t.Errorf("AuthMode(%d).IsValid() = %v, want %v", tt.m, got, tt.want)
		}
	}
}

func TestRequestType_String(t *testing.T) {
	tests := []struct {
		r    RequestType
		want string
	}{
		{RequestTypeUnknown, "Unknown"},
		{RequestTypeAttributeRead, "AttributeRead"},
		{RequestTypeAttributeWrite, "AttributeWrite"},
		{RequestTypeCommandInvoke, "CommandInvoke"},
		{RequestTypeEventRead, "EventRead"},
		{RequestType(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.r.String(); got != tt.want {
			t.Errorf("RequestType(%d).String() = %q, want %q", tt.r, got, tt.want)
		}
	}
}

func TestRequestType_IsValid(t *testing.T) {
	tests := []struct {
		r    RequestType
		want bool
	}{
		{RequestTypeUnknown, false},
		{RequestTypeAttributeRead, true},
		{RequestTypeAttributeWrite, true},
		{RequestTypeCommandInvoke, true},
		{RequestTypeEventRead, true},
		{RequestType(5), false},
	}

	for _, tt := range tests {
		if got := tt.r.IsValid(); got != tt.want {
			t.Errorf("RequestType(%d).IsValid() = %v, want %v", tt.r, got, tt.want)
		}
	}
}

func TestResult_String(t *testing.T) {
	tests := []struct {
		r    Result
		want string
	}{
		{ResultDenied, "Denied"},
		{ResultAllowed, "Allowed"},
		{ResultRestricted, "Restricted"},
		{Result(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.r.String(); got != tt.want {
			t.Errorf("Result(%d).String() = %q, want %q", tt.r, got, tt.want)
		}
	}
}
