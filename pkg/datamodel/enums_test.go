package datamodel

import "testing"

func TestPrivilege_String(t *testing.T) {
	tests := []struct {
		p    Privilege
		want string
	}{
		{PrivilegeUnknown, "Unknown"},
		{PrivilegeView, "View"},
		{PrivilegeProxyView, "ProxyView"},
		{PrivilegeOperate, "Operate"},
		{PrivilegeManage, "Manage"},
		{PrivilegeAdminister, "Administer"},
		{Privilege(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.p.String(); got != tt.want {
				t.Errorf("Privilege.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrivilege_IsValid(t *testing.T) {
	tests := []struct {
		p    Privilege
		want bool
	}{
		{PrivilegeUnknown, false},
		{PrivilegeView, true},
		{PrivilegeProxyView, true},
		{PrivilegeOperate, true},
		{PrivilegeManage, true},
		{PrivilegeAdminister, true},
		{Privilege(99), false},
	}

	for _, tt := range tests {
		t.Run(tt.p.String(), func(t *testing.T) {
			if got := tt.p.IsValid(); got != tt.want {
				t.Errorf("Privilege.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAttributeQuality_String(t *testing.T) {
	tests := []struct {
		q    AttributeQuality
		want string
	}{
		{0, "None"},
		{AttrQualityChangesOmitted, "C"},
		{AttrQualityFixed, "F"},
		{AttrQualityNullable, "X"},
		{AttrQualityList, "[List]"},
		{AttrQualityFabricScoped, "[FabricScoped]"},
		{AttrQualityChangesOmitted | AttrQualityFixed, "CF"},
		{AttrQualityNullable | AttrQualityList, "X[List]"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.q.String(); got != tt.want {
				t.Errorf("AttributeQuality.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommandQuality_String(t *testing.T) {
	tests := []struct {
		q    CommandQuality
		want string
	}{
		{0, "None"},
		{CmdQualityFabricScoped, "F"},
		{CmdQualityTimed, "T"},
		{CmdQualityLargeMessage, "L"},
		{CmdQualityFabricScoped | CmdQualityTimed, "FT"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.q.String(); got != tt.want {
				t.Errorf("CommandQuality.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEventPriority_String(t *testing.T) {
	tests := []struct {
		p    EventPriority
		want string
	}{
		{EventPriorityDebug, "Debug"},
		{EventPriorityInfo, "Info"},
		{EventPriorityCritical, "Critical"},
		{EventPriority(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.p.String(); got != tt.want {
				t.Errorf("EventPriority.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEventPriority_IsValid(t *testing.T) {
	tests := []struct {
		p    EventPriority
		want bool
	}{
		{EventPriorityDebug, true},
		{EventPriorityInfo, true},
		{EventPriorityCritical, true},
		{EventPriority(-1), false},
		{EventPriority(99), false},
	}

	for _, tt := range tests {
		t.Run(tt.p.String(), func(t *testing.T) {
			if got := tt.p.IsValid(); got != tt.want {
				t.Errorf("EventPriority.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClusterClassification_String(t *testing.T) {
	tests := []struct {
		c    ClusterClassification
		want string
	}{
		{ClusterClassUnknown, "Unknown"},
		{ClusterClassUtility, "Utility"},
		{ClusterClassApplication, "Application"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.c.String(); got != tt.want {
				t.Errorf("ClusterClassification.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEndpointComposition_String(t *testing.T) {
	tests := []struct {
		c    EndpointComposition
		want string
	}{
		{CompositionUnknown, "Unknown"},
		{CompositionTree, "Tree"},
		{CompositionFullFamily, "FullFamily"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.c.String(); got != tt.want {
				t.Errorf("EndpointComposition.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthMode_String(t *testing.T) {
	tests := []struct {
		m    AuthMode
		want string
	}{
		{AuthModeUnknown, "Unknown"},
		{AuthModeCASE, "CASE"},
		{AuthModePASE, "PASE"},
		{AuthModeGroup, "Group"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.m.String(); got != tt.want {
				t.Errorf("AuthMode.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthMode_IsValid(t *testing.T) {
	tests := []struct {
		m    AuthMode
		want bool
	}{
		{AuthModeUnknown, false},
		{AuthModeCASE, true},
		{AuthModePASE, true},
		{AuthModeGroup, true},
		{AuthMode(99), false},
	}

	for _, tt := range tests {
		t.Run(tt.m.String(), func(t *testing.T) {
			if got := tt.m.IsValid(); got != tt.want {
				t.Errorf("AuthMode.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAtomicRequestType_String(t *testing.T) {
	tests := []struct {
		r    AtomicRequestType
		want string
	}{
		{AtomicBeginWrite, "BeginWrite"},
		{AtomicCommitWrite, "CommitWrite"},
		{AtomicRollbackWrite, "RollbackWrite"},
		{AtomicRequestType(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.r.String(); got != tt.want {
				t.Errorf("AtomicRequestType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
