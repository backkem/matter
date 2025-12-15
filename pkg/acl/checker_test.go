package acl

import (
	"testing"

	"github.com/backkem/matter/pkg/fabric"
)

func TestChecker_NewChecker(t *testing.T) {
	// With nil resolver
	c := NewChecker(nil)
	if c == nil {
		t.Fatal("NewChecker(nil) returned nil")
	}

	// With custom resolver
	c = NewChecker(NullDeviceTypeResolver{})
	if c == nil {
		t.Fatal("NewChecker(resolver) returned nil")
	}
}

func TestChecker_SetGetEntries(t *testing.T) {
	c := NewChecker(nil)

	entries := []Entry{
		{FabricIndex: 1, Privilege: PrivilegeAdminister, AuthMode: AuthModeCASE},
		{FabricIndex: 2, Privilege: PrivilegeView, AuthMode: AuthModeGroup},
	}

	c.SetEntries(entries)

	got := c.GetEntries()
	if len(got) != len(entries) {
		t.Errorf("GetEntries() returned %d entries, want %d", len(got), len(entries))
	}

	// Verify entries are copied (modification shouldn't affect checker)
	entries[0].Privilege = PrivilegeView
	got = c.GetEntries()
	if got[0].Privilege != PrivilegeAdminister {
		t.Error("Entries should be copied, not referenced")
	}
}

func TestChecker_AddEntry(t *testing.T) {
	c := NewChecker(nil)

	// Valid entry
	validEntry := Entry{
		FabricIndex: 1,
		Privilege:   PrivilegeView,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{0x0123_4567_89AB_CDEF},
		Targets:     []Target{NewTargetCluster(0x0006)},
	}

	if err := c.AddEntry(validEntry); err != nil {
		t.Errorf("AddEntry(valid) = %v, want nil", err)
	}

	if len(c.GetEntries()) != 1 {
		t.Error("Entry should have been added")
	}

	// Invalid entry (bad fabric index)
	invalidEntry := Entry{
		FabricIndex: 0, // Invalid
		Privilege:   PrivilegeView,
		AuthMode:    AuthModeCASE,
	}

	if err := c.AddEntry(invalidEntry); err == nil {
		t.Error("AddEntry(invalid) should return error")
	}

	// Entry count should still be 1
	if len(c.GetEntries()) != 1 {
		t.Error("Invalid entry should not have been added")
	}
}

func TestChecker_PASECommissioning(t *testing.T) {
	c := NewChecker(nil)

	// PASE during commissioning gets implicit Administer
	subject := SubjectDescriptor{
		FabricIndex:     0, // No fabric during PASE
		AuthMode:        AuthModePASE,
		Subject:         NodeIDFromPAKEKeyID(0x0000),
		IsCommissioning: true,
	}

	path := NewRequestPath(0x001F, 0, RequestTypeAttributeWrite) // Access Control cluster

	// Should be allowed even with empty ACL
	result := c.Check(subject, path, PrivilegeAdminister)
	if result != ResultAllowed {
		t.Errorf("PASE commissioning should get implicit Administer, got %v", result)
	}
}

func TestChecker_PASENotCommissioning(t *testing.T) {
	c := NewChecker(nil)

	// PASE but NOT commissioning - no implicit privilege
	subject := SubjectDescriptor{
		FabricIndex:     1,
		AuthMode:        AuthModePASE,
		Subject:         NodeIDFromPAKEKeyID(0x0000),
		IsCommissioning: false,
	}

	path := NewRequestPath(0x001F, 0, RequestTypeAttributeRead)

	// Should be denied with empty ACL
	result := c.Check(subject, path, PrivilegeView)
	if result != ResultDenied {
		t.Errorf("PASE not commissioning should be denied, got %v", result)
	}
}

func TestChecker_BasicCASE(t *testing.T) {
	c := NewChecker(nil)

	// Add an entry granting View to a specific node
	c.AddEntry(Entry{
		FabricIndex: 1,
		Privilege:   PrivilegeView,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{0x1111_1111_1111_1111},
		Targets:     []Target{NewTargetCluster(0x0006)},
	})

	// Matching subject should be allowed
	subject := SubjectDescriptor{
		FabricIndex: 1,
		AuthMode:    AuthModeCASE,
		Subject:     0x1111_1111_1111_1111,
	}

	// Matching path should be allowed
	result := c.Check(subject, NewRequestPath(0x0006, 1, RequestTypeAttributeRead), PrivilegeView)
	if result != ResultAllowed {
		t.Errorf("Matching subject/target should be allowed, got %v", result)
	}

	// Wrong subject should be denied
	subject.Subject = 0x2222_2222_2222_2222
	result = c.Check(subject, NewRequestPath(0x0006, 1, RequestTypeAttributeRead), PrivilegeView)
	if result != ResultDenied {
		t.Errorf("Wrong subject should be denied, got %v", result)
	}

	// Wrong fabric should be denied
	subject.Subject = 0x1111_1111_1111_1111
	subject.FabricIndex = 2
	result = c.Check(subject, NewRequestPath(0x0006, 1, RequestTypeAttributeRead), PrivilegeView)
	if result != ResultDenied {
		t.Errorf("Wrong fabric should be denied, got %v", result)
	}

	// Wrong auth mode should be denied
	subject.FabricIndex = 1
	subject.AuthMode = AuthModeGroup
	result = c.Check(subject, NewRequestPath(0x0006, 1, RequestTypeAttributeRead), PrivilegeView)
	if result != ResultDenied {
		t.Errorf("Wrong auth mode should be denied, got %v", result)
	}
}

func TestChecker_PrivilegeHierarchy(t *testing.T) {
	c := NewChecker(nil)

	// Add Administer entry
	c.AddEntry(Entry{
		FabricIndex: 1,
		Privilege:   PrivilegeAdminister,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{0x1111_1111_1111_1111},
	})

	subject := SubjectDescriptor{
		FabricIndex: 1,
		AuthMode:    AuthModeCASE,
		Subject:     0x1111_1111_1111_1111,
	}
	path := NewRequestPath(0x001F, 0, RequestTypeAttributeRead)

	// Administer grants all privileges
	for _, priv := range []Privilege{PrivilegeView, PrivilegeProxyView, PrivilegeOperate, PrivilegeManage, PrivilegeAdminister} {
		result := c.Check(subject, path, priv)
		if result != ResultAllowed {
			t.Errorf("Administer entry should grant %s, got %v", priv, result)
		}
	}
}

func TestChecker_WildcardSubjects(t *testing.T) {
	c := NewChecker(nil)

	// Add entry with empty subjects (wildcard)
	c.AddEntry(Entry{
		FabricIndex: 1,
		Privilege:   PrivilegeView,
		AuthMode:    AuthModeCASE,
		Subjects:    nil, // Wildcard
		Targets:     []Target{NewTargetCluster(0x0006)},
	})

	// Any CASE subject on fabric 1 should match
	for _, nodeID := range []uint64{0x1111_1111_1111_1111, 0x2222_2222_2222_2222, 0xFFFF_FFEF_FFFF_FFFF} {
		subject := SubjectDescriptor{
			FabricIndex: 1,
			AuthMode:    AuthModeCASE,
			Subject:     nodeID,
		}

		result := c.Check(subject, NewRequestPath(0x0006, 1, RequestTypeAttributeRead), PrivilegeView)
		if result != ResultAllowed {
			t.Errorf("Wildcard subjects should match any CASE subject, got %v for 0x%016X", result, nodeID)
		}
	}
}

func TestChecker_WildcardTargets(t *testing.T) {
	c := NewChecker(nil)

	// Add entry with empty targets (wildcard)
	c.AddEntry(Entry{
		FabricIndex: 1,
		Privilege:   PrivilegeView,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{0x1111_1111_1111_1111},
		Targets:     nil, // Wildcard
	})

	subject := SubjectDescriptor{
		FabricIndex: 1,
		AuthMode:    AuthModeCASE,
		Subject:     0x1111_1111_1111_1111,
	}

	// Any cluster/endpoint should match
	for _, cluster := range []uint32{0x0006, 0x0008, 0x001F, 0x0300} {
		for _, endpoint := range []uint16{0, 1, 2, 100} {
			path := NewRequestPath(cluster, endpoint, RequestTypeAttributeRead)
			result := c.Check(subject, path, PrivilegeView)
			if result != ResultAllowed {
				t.Errorf("Wildcard targets should match any path, got %v for cluster=0x%04X endpoint=%d",
					result, cluster, endpoint)
			}
		}
	}
}

func TestChecker_CATMatching(t *testing.T) {
	c := NewChecker(nil)

	// Add entry with CAT subject (identifier 0xABCD, version 2)
	catSubject := NewCASEAuthTag(0xABCD, 0x0002).NodeID()
	c.AddEntry(Entry{
		FabricIndex: 1,
		Privilege:   PrivilegeOperate,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{catSubject},
		Targets:     []Target{NewTargetCluster(0x0006)},
	})

	path := NewRequestPath(0x0006, 1, RequestTypeAttributeRead)

	// Subject with same CAT (version 2) should match
	t.Run("Exact CAT match", func(t *testing.T) {
		subject := SubjectDescriptor{
			FabricIndex: 1,
			AuthMode:    AuthModeCASE,
			Subject:     0x0123_4567_89AB_CDEF, // Different primary NodeID
			CATs:        CATValues{NewCASEAuthTag(0xABCD, 0x0002), 0, 0},
		}
		result := c.Check(subject, path, PrivilegeOperate)
		if result != ResultAllowed {
			t.Errorf("Same CAT version should match, got %v", result)
		}
	})

	// Subject with higher CAT version (8) should match (8 >= 2)
	t.Run("Higher CAT version matches", func(t *testing.T) {
		subject := SubjectDescriptor{
			FabricIndex: 1,
			AuthMode:    AuthModeCASE,
			Subject:     0x0123_4567_89AB_CDEF,
			CATs:        CATValues{NewCASEAuthTag(0xABCD, 0x0008), 0, 0},
		}
		result := c.Check(subject, path, PrivilegeOperate)
		if result != ResultAllowed {
			t.Errorf("Higher CAT version should match, got %v", result)
		}
	})

	// Subject with lower CAT version (1) should NOT match (1 < 2)
	t.Run("Lower CAT version denied", func(t *testing.T) {
		subject := SubjectDescriptor{
			FabricIndex: 1,
			AuthMode:    AuthModeCASE,
			Subject:     0x0123_4567_89AB_CDEF,
			CATs:        CATValues{NewCASEAuthTag(0xABCD, 0x0001), 0, 0},
		}
		result := c.Check(subject, path, PrivilegeOperate)
		if result != ResultDenied {
			t.Errorf("Lower CAT version should be denied, got %v", result)
		}
	})

	// Subject with different CAT identifier should NOT match
	t.Run("Different CAT identifier denied", func(t *testing.T) {
		subject := SubjectDescriptor{
			FabricIndex: 1,
			AuthMode:    AuthModeCASE,
			Subject:     0x0123_4567_89AB_CDEF,
			CATs:        CATValues{NewCASEAuthTag(0x1234, 0x0008), 0, 0}, // Different identifier
		}
		result := c.Check(subject, path, PrivilegeOperate)
		if result != ResultDenied {
			t.Errorf("Different CAT identifier should be denied, got %v", result)
		}
	})
}

func TestChecker_GroupAuth(t *testing.T) {
	c := NewChecker(nil)

	group2 := NodeIDFromGroupID(0x0002)

	// Add entry for group 2
	c.AddEntry(Entry{
		FabricIndex: 1,
		Privilege:   PrivilegeOperate,
		AuthMode:    AuthModeGroup,
		Subjects:    []uint64{group2},
		Targets:     []Target{NewTargetCluster(0x0006)},
	})

	// Group 2 subject should match
	subject := SubjectDescriptor{
		FabricIndex: 1,
		AuthMode:    AuthModeGroup,
		Subject:     group2,
	}

	result := c.Check(subject, NewRequestPath(0x0006, 1, RequestTypeAttributeRead), PrivilegeOperate)
	if result != ResultAllowed {
		t.Errorf("Group 2 should be allowed, got %v", result)
	}

	// Different group should be denied
	subject.Subject = NodeIDFromGroupID(0x0004)
	result = c.Check(subject, NewRequestPath(0x0006, 1, RequestTypeAttributeRead), PrivilegeOperate)
	if result != ResultDenied {
		t.Errorf("Group 4 should be denied, got %v", result)
	}

	// CASE auth mode should be denied even with same NodeID value
	subject.Subject = group2
	subject.AuthMode = AuthModeCASE
	result = c.Check(subject, NewRequestPath(0x0006, 1, RequestTypeAttributeRead), PrivilegeOperate)
	if result != ResultDenied {
		t.Errorf("CASE auth mode should not match Group entry, got %v", result)
	}
}

func TestChecker_MultipleTargets(t *testing.T) {
	c := NewChecker(nil)

	// Entry with multiple targets
	c.AddEntry(Entry{
		FabricIndex: 1,
		Privilege:   PrivilegeOperate,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{0x1111_1111_1111_1111},
		Targets: []Target{
			NewTargetClusterEndpoint(0x0008, 1), // LevelControl on endpoint 1
			NewTargetCluster(0x0006),            // OnOff on any endpoint
			NewTargetEndpoint(2),                // Any cluster on endpoint 2
		},
	})

	subject := SubjectDescriptor{
		FabricIndex: 1,
		AuthMode:    AuthModeCASE,
		Subject:     0x1111_1111_1111_1111,
	}

	tests := []struct {
		cluster  uint32
		endpoint uint16
		want     Result
	}{
		{0x0008, 1, ResultAllowed},  // Target 1: LevelControl@1
		{0x0008, 2, ResultAllowed},  // Target 3: endpoint 2 matches
		{0x0008, 3, ResultDenied},   // LevelControl@3 doesn't match
		{0x0006, 1, ResultAllowed},  // Target 2: OnOff on any endpoint
		{0x0006, 5, ResultAllowed},  // Target 2: OnOff on any endpoint
		{0x0300, 2, ResultAllowed},  // Target 3: any cluster on endpoint 2
		{0x0300, 3, ResultDenied},   // ColorControl@3 doesn't match
	}

	for _, tt := range tests {
		path := NewRequestPath(tt.cluster, tt.endpoint, RequestTypeAttributeRead)
		result := c.Check(subject, path, PrivilegeOperate)
		if result != tt.want {
			t.Errorf("Check(cluster=0x%04X, endpoint=%d) = %v, want %v",
				tt.cluster, tt.endpoint, result, tt.want)
		}
	}
}

// mockDeviceTypeResolver for testing device type matching
type mockDeviceTypeResolver struct {
	mapping map[uint16][]uint32 // endpoint -> device types
}

func (m *mockDeviceTypeResolver) IsDeviceTypeOnEndpoint(deviceType uint32, endpoint uint16) bool {
	types, ok := m.mapping[endpoint]
	if !ok {
		return false
	}
	for _, dt := range types {
		if dt == deviceType {
			return true
		}
	}
	return false
}

func TestChecker_DeviceTypeTarget(t *testing.T) {
	resolver := &mockDeviceTypeResolver{
		mapping: map[uint16][]uint32{
			1: {0x0100}, // Endpoint 1 is On/Off Light (0x0100)
			2: {0x010C}, // Endpoint 2 is Color Temperature Light
		},
	}

	c := NewChecker(resolver)

	// Entry targeting device type 0x0100 (On/Off Light)
	c.AddEntry(Entry{
		FabricIndex: 1,
		Privilege:   PrivilegeOperate,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{0x1111_1111_1111_1111},
		Targets:     []Target{NewTargetDeviceType(0x0100)},
	})

	subject := SubjectDescriptor{
		FabricIndex: 1,
		AuthMode:    AuthModeCASE,
		Subject:     0x1111_1111_1111_1111,
	}

	// Endpoint 1 (has device type 0x0100) should match
	result := c.Check(subject, NewRequestPath(0x0006, 1, RequestTypeAttributeRead), PrivilegeOperate)
	if result != ResultAllowed {
		t.Errorf("Endpoint with matching device type should be allowed, got %v", result)
	}

	// Endpoint 2 (different device type) should be denied
	result = c.Check(subject, NewRequestPath(0x0006, 2, RequestTypeAttributeRead), PrivilegeOperate)
	if result != ResultDenied {
		t.Errorf("Endpoint without matching device type should be denied, got %v", result)
	}

	// Endpoint 3 (no device types) should be denied
	result = c.Check(subject, NewRequestPath(0x0006, 3, RequestTypeAttributeRead), PrivilegeOperate)
	if result != ResultDenied {
		t.Errorf("Unknown endpoint should be denied, got %v", result)
	}
}

func TestChecker_ClusterDeviceTypeTarget(t *testing.T) {
	resolver := &mockDeviceTypeResolver{
		mapping: map[uint16][]uint32{
			1: {0x0100}, // Endpoint 1 is On/Off Light
			2: {0x0100}, // Endpoint 2 is also On/Off Light
			3: {0x010C}, // Endpoint 3 is Color Temperature Light
		},
	}

	c := NewChecker(resolver)

	// Entry targeting OnOff cluster on device type 0x0100
	c.AddEntry(Entry{
		FabricIndex: 1,
		Privilege:   PrivilegeOperate,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{0x1111_1111_1111_1111},
		Targets:     []Target{NewTargetClusterDeviceType(0x0006, 0x0100)},
	})

	subject := SubjectDescriptor{
		FabricIndex: 1,
		AuthMode:    AuthModeCASE,
		Subject:     0x1111_1111_1111_1111,
	}

	tests := []struct {
		cluster  uint32
		endpoint uint16
		want     Result
	}{
		{0x0006, 1, ResultAllowed}, // OnOff on device type 0x0100
		{0x0006, 2, ResultAllowed}, // OnOff on device type 0x0100
		{0x0006, 3, ResultDenied},  // OnOff but wrong device type
		{0x0008, 1, ResultDenied},  // Wrong cluster, right device type
	}

	for _, tt := range tests {
		path := NewRequestPath(tt.cluster, tt.endpoint, RequestTypeAttributeRead)
		result := c.Check(subject, path, PrivilegeOperate)
		if result != tt.want {
			t.Errorf("Check(cluster=0x%04X, endpoint=%d) = %v, want %v",
				tt.cluster, tt.endpoint, result, tt.want)
		}
	}
}

func TestChecker_FabricIsolation(t *testing.T) {
	c := NewChecker(nil)

	// Entries for different fabrics
	c.AddEntry(Entry{
		FabricIndex: 1,
		Privilege:   PrivilegeAdminister,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{0x1111_1111_1111_1111},
	})
	c.AddEntry(Entry{
		FabricIndex: 2,
		Privilege:   PrivilegeAdminister,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{0x2222_2222_2222_2222},
	})

	path := NewRequestPath(0x001F, 0, RequestTypeAttributeWrite)

	// Fabric 1 subject accessing fabric 1
	subject := SubjectDescriptor{
		FabricIndex: 1,
		AuthMode:    AuthModeCASE,
		Subject:     0x1111_1111_1111_1111,
	}
	result := c.Check(subject, path, PrivilegeAdminister)
	if result != ResultAllowed {
		t.Errorf("Fabric 1 subject on fabric 1 should be allowed, got %v", result)
	}

	// Fabric 1 subject trying to access fabric 2 entry
	subject.FabricIndex = 2
	result = c.Check(subject, path, PrivilegeAdminister)
	if result != ResultDenied {
		t.Errorf("Fabric 1 subject on fabric 2 should be denied, got %v", result)
	}

	// Fabric 2 subject accessing fabric 2
	subject.Subject = 0x2222_2222_2222_2222
	result = c.Check(subject, path, PrivilegeAdminister)
	if result != ResultAllowed {
		t.Errorf("Fabric 2 subject on fabric 2 should be allowed, got %v", result)
	}
}

func BenchmarkChecker_Check(b *testing.B) {
	c := NewChecker(nil)

	// Add some entries
	for i := fabric.FabricIndex(1); i <= 10; i++ {
		for j := 0; j < 5; j++ {
			c.AddEntry(Entry{
				FabricIndex: i,
				Privilege:   PrivilegeOperate,
				AuthMode:    AuthModeCASE,
				Subjects:    []uint64{uint64(i)*1000 + uint64(j)},
				Targets:     []Target{NewTargetCluster(uint32(j))},
			})
		}
	}

	subject := SubjectDescriptor{
		FabricIndex: 5,
		AuthMode:    AuthModeCASE,
		Subject:     5003,
	}
	path := NewRequestPath(3, 1, RequestTypeAttributeRead)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Check(subject, path, PrivilegeOperate)
	}
}
