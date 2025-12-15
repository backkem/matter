package acl

import "testing"

// Test vectors ported from C++ connectedhomeip/src/access/tests/TestAccessControl.cpp
// These test the access control algorithm against the reference implementation.

// Cluster IDs used in test vectors
const (
	kOnOffCluster         uint32 = 0x0000_0006
	kLevelControlCluster  uint32 = 0x0000_0008
	kAccessControlCluster uint32 = 0x0000_001F
	kColorControlCluster  uint32 = 0x0000_0300
)

// Node IDs used in test vectors
const (
	kOperationalNodeId0 uint64 = 0x0123_4567_89AB_CDEF
	kOperationalNodeId1 uint64 = 0x1234_5678_1234_5678
	kOperationalNodeId2 uint64 = 0x1122_3344_5566_7788
	kOperationalNodeId3 uint64 = 0x1111_1111_1111_1111
	kOperationalNodeId4 uint64 = 0x2222_2222_2222_2222
	kOperationalNodeId5 uint64 = 0x3333_3333_3333_3333
)

// CASE Auth Tags used in test vectors
var (
	kCASEAuthTag0 = NewCASEAuthTag(0x0001, 0x0001) // 0x0001_0001
	kCASEAuthTag1 = NewCASEAuthTag(0x0002, 0x0001) // 0x0002_0001
	kCASEAuthTag2 = NewCASEAuthTag(0xABCD, 0x0002) // 0xABCD_0002
	kCASEAuthTag3 = NewCASEAuthTag(0xABCD, 0x0008) // 0xABCD_0008
	kCASEAuthTag4 = NewCASEAuthTag(0xABCD, 0xABCD) // 0xABCD_ABCD
)

// Group NodeIDs
var (
	kGroup2 = NodeIDFromGroupID(0x0002)
	kGroup4 = NodeIDFromGroupID(0x0004)
)

// PAKE NodeIDs
var (
	kPaseVerifier0 = NodeIDFromPAKEKeyID(0x0000)
	kPaseVerifier1 = NodeIDFromPAKEKeyID(0x0001)
	kPaseVerifier3 = NodeIDFromPAKEKeyID(0x0003)
)

// entryData1 is the ACL entry set used for most tests
// Ported from C++ entryData1[]
var entryData1 = []Entry{
	// Entry 0: Fabric 1, Administer to specific node
	{
		FabricIndex: 1,
		Privilege:   PrivilegeAdminister,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{kOperationalNodeId3},
	},
	// Entry 1: Fabric 1, View to anyone (wildcard subjects)
	{
		FabricIndex: 1,
		Privilege:   PrivilegeView,
		AuthMode:    AuthModeCASE,
	},
	// Entry 2: Fabric 2, Administer to specific node
	{
		FabricIndex: 2,
		Privilege:   PrivilegeAdminister,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{kOperationalNodeId4},
	},
	// Entry 3: Fabric 1, Operate on OnOff cluster (any endpoint)
	{
		FabricIndex: 1,
		Privilege:   PrivilegeOperate,
		AuthMode:    AuthModeCASE,
		Targets:     []Target{NewTargetCluster(kOnOffCluster)},
	},
	// Entry 4: Fabric 2, Manage on OnOff@endpoint2 to specific node
	{
		FabricIndex: 2,
		Privilege:   PrivilegeManage,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{kOperationalNodeId5},
		Targets:     []Target{NewTargetClusterEndpoint(kOnOffCluster, 2)},
	},
	// Entry 5: Fabric 2, ProxyView for Group2 on multiple targets
	{
		FabricIndex: 2,
		Privilege:   PrivilegeProxyView,
		AuthMode:    AuthModeGroup,
		Subjects:    []uint64{kGroup2},
		Targets: []Target{
			NewTargetClusterEndpoint(kLevelControlCluster, 1),
			NewTargetCluster(kOnOffCluster),
			NewTargetEndpoint(2),
		},
	},
	// Entry 6: Fabric 1, Administer to CAT0
	{
		FabricIndex: 1,
		Privilege:   PrivilegeAdminister,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{kCASEAuthTag0.NodeID()},
	},
	// Entry 7: Fabric 2, Manage on OnOff to CAT3 or CAT1
	{
		FabricIndex: 2,
		Privilege:   PrivilegeManage,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{kCASEAuthTag3.NodeID(), kCASEAuthTag1.NodeID()},
		Targets:     []Target{NewTargetCluster(kOnOffCluster)},
	},
	// Entry 8: Fabric 2, Operate on LevelControl to CAT4 or CAT1
	{
		FabricIndex: 2,
		Privilege:   PrivilegeOperate,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{kCASEAuthTag4.NodeID(), kCASEAuthTag1.NodeID()},
		Targets:     []Target{NewTargetCluster(kLevelControlCluster)},
	},
}

// CheckData represents a single test vector
type CheckData struct {
	Name      string
	Subject   SubjectDescriptor
	Path      RequestPath
	Privilege Privilege
	Want      Result
}

// checkData1 contains test vectors from C++ checkData1[]
var checkData1 = []CheckData{
	// === Checks for implicit PASE ===
	{"PASE implicit admin f=0", SubjectDescriptor{FabricIndex: 0, AuthMode: AuthModePASE, Subject: kPaseVerifier0, IsCommissioning: true},
		NewRequestPath(1, 2, RequestTypeAttributeRead), PrivilegeAdminister, ResultAllowed},
	{"PASE implicit admin f=1", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModePASE, Subject: kPaseVerifier0, IsCommissioning: true},
		NewRequestPath(3, 4, RequestTypeAttributeRead), PrivilegeAdminister, ResultAllowed},
	{"PASE implicit admin f=2", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModePASE, Subject: kPaseVerifier0, IsCommissioning: true},
		NewRequestPath(5, 6, RequestTypeAttributeRead), PrivilegeAdminister, ResultAllowed},
	{"PASE implicit admin f=2 v1", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModePASE, Subject: kPaseVerifier1, IsCommissioning: true},
		NewRequestPath(5, 6, RequestTypeAttributeRead), PrivilegeAdminister, ResultAllowed},
	{"PASE implicit admin f=3", SubjectDescriptor{FabricIndex: 3, AuthMode: AuthModePASE, Subject: kPaseVerifier3, IsCommissioning: true},
		NewRequestPath(7, 8, RequestTypeAttributeRead), PrivilegeAdminister, ResultAllowed},

	// === Checks for entry 0: Fabric 1, Administer to kOperationalNodeId3 ===
	{"Entry0: admin on ACL cluster", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeCASE, Subject: kOperationalNodeId3},
		NewRequestPath(kAccessControlCluster, 0, RequestTypeAttributeRead), PrivilegeAdminister, ResultAllowed},
	{"Entry0: manage any", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeCASE, Subject: kOperationalNodeId3},
		NewRequestPath(1, 2, RequestTypeAttributeRead), PrivilegeManage, ResultAllowed},
	{"Entry0: operate any", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeCASE, Subject: kOperationalNodeId3},
		NewRequestPath(3, 4, RequestTypeAttributeRead), PrivilegeOperate, ResultAllowed},
	{"Entry0: view any", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeCASE, Subject: kOperationalNodeId3},
		NewRequestPath(5, 6, RequestTypeAttributeRead), PrivilegeView, ResultAllowed},
	{"Entry0: proxy view any", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeCASE, Subject: kOperationalNodeId3},
		NewRequestPath(7, 8, RequestTypeAttributeRead), PrivilegeProxyView, ResultAllowed},
	{"Entry0: wrong fabric", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, Subject: kOperationalNodeId3},
		NewRequestPath(1, 2, RequestTypeAttributeRead), PrivilegeAdminister, ResultDenied},
	{"Entry0: wrong auth mode", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeGroup, Subject: kOperationalNodeId3},
		NewRequestPath(1, 2, RequestTypeAttributeRead), PrivilegeAdminister, ResultDenied},
	{"Entry0: wrong subject", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeCASE, Subject: kOperationalNodeId4},
		NewRequestPath(1, 2, RequestTypeAttributeRead), PrivilegeAdminister, ResultDenied},

	// === Checks for entry 1: Fabric 1, View wildcard ===
	{"Entry1: view allowed", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeCASE, Subject: kOperationalNodeId1},
		NewRequestPath(11, 13, RequestTypeAttributeRead), PrivilegeView, ResultAllowed},
	{"Entry1: operate not granted", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeCASE, Subject: kOperationalNodeId1},
		NewRequestPath(11, 13, RequestTypeAttributeRead), PrivilegeOperate, ResultDenied},
	{"Entry1: wrong fabric", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, Subject: kOperationalNodeId1},
		NewRequestPath(11, 13, RequestTypeAttributeRead), PrivilegeView, ResultDenied},
	{"Entry1: wrong auth mode", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeGroup, Subject: kOperationalNodeId1},
		NewRequestPath(11, 13, RequestTypeAttributeRead), PrivilegeView, ResultDenied},

	// === Checks for entry 2: Fabric 2, Administer to kOperationalNodeId4 ===
	{"Entry2: admin ACL", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, Subject: kOperationalNodeId4},
		NewRequestPath(kAccessControlCluster, 0, RequestTypeAttributeRead), PrivilegeAdminister, ResultAllowed},
	{"Entry2: manage any", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, Subject: kOperationalNodeId4},
		NewRequestPath(1, 2, RequestTypeAttributeRead), PrivilegeManage, ResultAllowed},
	{"Entry2: operate any", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, Subject: kOperationalNodeId4},
		NewRequestPath(3, 4, RequestTypeAttributeRead), PrivilegeOperate, ResultAllowed},
	{"Entry2: view any", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, Subject: kOperationalNodeId4},
		NewRequestPath(5, 6, RequestTypeAttributeRead), PrivilegeView, ResultAllowed},
	{"Entry2: proxy view any", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, Subject: kOperationalNodeId4},
		NewRequestPath(7, 8, RequestTypeAttributeRead), PrivilegeProxyView, ResultAllowed},
	{"Entry2: wrong fabric", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeCASE, Subject: kOperationalNodeId4},
		NewRequestPath(1, 2, RequestTypeAttributeRead), PrivilegeAdminister, ResultDenied},
	{"Entry2: wrong auth mode", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeGroup, Subject: kOperationalNodeId4},
		NewRequestPath(1, 2, RequestTypeAttributeRead), PrivilegeAdminister, ResultDenied},
	{"Entry2: wrong subject", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, Subject: kOperationalNodeId3},
		NewRequestPath(1, 2, RequestTypeAttributeRead), PrivilegeAdminister, ResultDenied},

	// === Checks for entry 3: Fabric 1, Operate on OnOff ===
	{"Entry3: operate OnOff ep11", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeCASE, Subject: kOperationalNodeId1},
		NewRequestPath(kOnOffCluster, 11, RequestTypeAttributeRead), PrivilegeOperate, ResultAllowed},
	{"Entry3: operate OnOff ep13", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeCASE, Subject: kOperationalNodeId2},
		NewRequestPath(kOnOffCluster, 13, RequestTypeAttributeRead), PrivilegeOperate, ResultAllowed},
	{"Entry3: wrong fabric", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, Subject: kOperationalNodeId1},
		NewRequestPath(kOnOffCluster, 11, RequestTypeAttributeRead), PrivilegeOperate, ResultDenied},
	{"Entry3: wrong cluster", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeCASE, Subject: kOperationalNodeId1},
		NewRequestPath(123, 11, RequestTypeAttributeRead), PrivilegeOperate, ResultDenied},
	{"Entry3: manage not granted", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeCASE, Subject: kOperationalNodeId1},
		NewRequestPath(kOnOffCluster, 11, RequestTypeAttributeRead), PrivilegeManage, ResultDenied},

	// === Checks for entry 4: Fabric 2, Manage on OnOff@ep2 to kOperationalNodeId5 ===
	{"Entry4: manage OnOff@2", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, Subject: kOperationalNodeId5},
		NewRequestPath(kOnOffCluster, 2, RequestTypeAttributeRead), PrivilegeManage, ResultAllowed},
	{"Entry4: wrong fabric", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeCASE, Subject: kOperationalNodeId5},
		NewRequestPath(kOnOffCluster, 2, RequestTypeAttributeRead), PrivilegeManage, ResultDenied},
	{"Entry4: wrong auth mode", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeGroup, Subject: kOperationalNodeId5},
		NewRequestPath(kOnOffCluster, 2, RequestTypeAttributeRead), PrivilegeManage, ResultDenied},
	{"Entry4: wrong subject", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, Subject: kOperationalNodeId3},
		NewRequestPath(kOnOffCluster, 2, RequestTypeAttributeRead), PrivilegeManage, ResultDenied},
	{"Entry4: wrong cluster", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, Subject: kOperationalNodeId5},
		NewRequestPath(kLevelControlCluster, 2, RequestTypeAttributeRead), PrivilegeManage, ResultDenied},
	{"Entry4: wrong endpoint", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, Subject: kOperationalNodeId5},
		NewRequestPath(kOnOffCluster, 1, RequestTypeAttributeRead), PrivilegeManage, ResultDenied},
	{"Entry4: admin not granted", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, Subject: kOperationalNodeId5},
		NewRequestPath(kOnOffCluster, 2, RequestTypeAttributeRead), PrivilegeAdminister, ResultDenied},

	// === Checks for entry 5: Fabric 2, ProxyView Group2 on multiple targets ===
	{"Entry5: proxyview Level@1", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeGroup, Subject: kGroup2},
		NewRequestPath(kLevelControlCluster, 1, RequestTypeAttributeRead), PrivilegeProxyView, ResultAllowed},
	{"Entry5: proxyview OnOff@3", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeGroup, Subject: kGroup2},
		NewRequestPath(kOnOffCluster, 3, RequestTypeAttributeRead), PrivilegeProxyView, ResultAllowed},
	{"Entry5: proxyview Color@2", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeGroup, Subject: kGroup2},
		NewRequestPath(kColorControlCluster, 2, RequestTypeAttributeRead), PrivilegeProxyView, ResultAllowed},
	{"Entry5: wrong fabric", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeGroup, Subject: kGroup2},
		NewRequestPath(kLevelControlCluster, 1, RequestTypeAttributeRead), PrivilegeProxyView, ResultDenied},
	{"Entry5: wrong auth mode", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, Subject: kGroup2},
		NewRequestPath(kLevelControlCluster, 1, RequestTypeAttributeRead), PrivilegeProxyView, ResultDenied},
	{"Entry5: wrong group", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeGroup, Subject: kGroup4},
		NewRequestPath(kLevelControlCluster, 1, RequestTypeAttributeRead), PrivilegeProxyView, ResultDenied},
	{"Entry5: wrong target Color@1", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeGroup, Subject: kGroup2},
		NewRequestPath(kColorControlCluster, 1, RequestTypeAttributeRead), PrivilegeProxyView, ResultDenied},
	{"Entry5: wrong target Level@3", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeGroup, Subject: kGroup2},
		NewRequestPath(kLevelControlCluster, 3, RequestTypeAttributeRead), PrivilegeProxyView, ResultDenied},
	{"Entry5: operate not granted", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeGroup, Subject: kGroup2},
		NewRequestPath(kLevelControlCluster, 1, RequestTypeAttributeRead), PrivilegeOperate, ResultDenied},

	// === Checks for entry 6: Fabric 1, Administer to CAT0 ===
	{"Entry6: wrong fabric", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, CATs: CATValues{kCASEAuthTag0, 0, 0}},
		NewRequestPath(kLevelControlCluster, 1, RequestTypeAttributeRead), PrivilegeOperate, ResultDenied},
	{"Entry6: CAT0 matches", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeCASE, CATs: CATValues{kCASEAuthTag0, 0, 0}},
		NewRequestPath(kLevelControlCluster, 1, RequestTypeAttributeRead), PrivilegeOperate, ResultAllowed},
	{"Entry6: CAT1 doesn't match", SubjectDescriptor{FabricIndex: 1, AuthMode: AuthModeCASE, CATs: CATValues{kCASEAuthTag1, 0, 0}},
		NewRequestPath(kLevelControlCluster, 1, RequestTypeAttributeRead), PrivilegeOperate, ResultDenied},

	// === Checks for entry 7: Fabric 2, Manage on OnOff to CAT3 or CAT1 ===
	{"Entry7: CAT0 doesn't match", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, CATs: CATValues{kCASEAuthTag0, 0, 0}},
		NewRequestPath(kOnOffCluster, 1, RequestTypeAttributeRead), PrivilegeOperate, ResultDenied},
	{"Entry7: CAT0+CAT2 doesn't match", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, CATs: CATValues{kCASEAuthTag0, kCASEAuthTag2, 0}},
		NewRequestPath(kOnOffCluster, 1, RequestTypeAttributeRead), PrivilegeOperate, ResultDenied},
	// CAT3 has identifier 0xABCD version 8, entry requires 0xABCD version 8 - exact match
	{"Entry7: CAT0+CAT3 matches via CAT3", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, CATs: CATValues{kCASEAuthTag0, kCASEAuthTag3, 0}},
		NewRequestPath(kOnOffCluster, 1, RequestTypeAttributeRead), PrivilegeOperate, ResultAllowed},
	// CAT4 has identifier 0xABCD version 0xABCD, entry requires 0xABCD version 8 - 0xABCD >= 8, matches
	{"Entry7: CAT0+CAT4 matches via CAT4 Manage", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, CATs: CATValues{kCASEAuthTag0, kCASEAuthTag4, 0}},
		NewRequestPath(kOnOffCluster, 1, RequestTypeAttributeRead), PrivilegeManage, ResultAllowed},

	// === Checks for entry 8: Fabric 2, Operate on LevelControl to CAT4 or CAT1 ===
	// Entry 8 requires CAT4 (0xABCD:0xABCD) or CAT1 (0x0002:0x0001)
	{"Entry8: CAT0+CAT3 doesn't match LevelControl", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, CATs: CATValues{kCASEAuthTag0, kCASEAuthTag3, 0}},
		NewRequestPath(kLevelControlCluster, 1, RequestTypeAttributeRead), PrivilegeOperate, ResultDenied},
	// CAT4 matches entry 8's first subject (same identifier 0xABCD, our version >= entry version)
	{"Entry8: CAT0+CAT4 matches LevelControl", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, CATs: CATValues{kCASEAuthTag0, kCASEAuthTag4, 0}},
		NewRequestPath(kLevelControlCluster, 2, RequestTypeAttributeRead), PrivilegeOperate, ResultAllowed},
	// CAT1 matches entry 8's second subject
	{"Entry8: CAT1 matches LevelControl", SubjectDescriptor{FabricIndex: 2, AuthMode: AuthModeCASE, CATs: CATValues{kCASEAuthTag1, 0, 0}},
		NewRequestPath(kLevelControlCluster, 2, RequestTypeAttributeRead), PrivilegeOperate, ResultAllowed},
}

func TestSpecVectors(t *testing.T) {
	c := NewChecker(nil)
	c.SetEntries(entryData1)

	for _, tc := range checkData1 {
		t.Run(tc.Name, func(t *testing.T) {
			got := c.Check(tc.Subject, tc.Path, tc.Privilege)
			if got != tc.Want {
				t.Errorf("Check() = %v, want %v", got, tc.Want)
				t.Logf("Subject: fabric=%d auth=%s subject=0x%016X cats=%v commissioning=%v",
					tc.Subject.FabricIndex, tc.Subject.AuthMode, tc.Subject.Subject, tc.Subject.CATs, tc.Subject.IsCommissioning)
				t.Logf("Path: cluster=0x%08X endpoint=%d", tc.Path.Cluster, tc.Path.Endpoint)
				t.Logf("Privilege: %s", tc.Privilege)
			}
		})
	}
}

// TestEntryData1LoadValidation ensures all entries in entryData1 are valid
func TestEntryData1LoadValidation(t *testing.T) {
	for i, entry := range entryData1 {
		if err := ValidateEntry(&entry); err != nil {
			t.Errorf("entryData1[%d] validation failed: %v", i, err)
		}
	}
}

// TestFabricCounts verifies the entry distribution
func TestFabricCounts(t *testing.T) {
	fabric1Count := 0
	fabric2Count := 0

	for _, entry := range entryData1 {
		switch entry.FabricIndex {
		case 1:
			fabric1Count++
		case 2:
			fabric2Count++
		}
	}

	// From C++: kNumFabric1EntriesInEntryData1 = 4, kNumFabric2EntriesInEntryData1 = 5
	if fabric1Count != 4 {
		t.Errorf("Fabric 1 entry count = %d, want 4", fabric1Count)
	}
	if fabric2Count != 5 {
		t.Errorf("Fabric 2 entry count = %d, want 5", fabric2Count)
	}
}

func BenchmarkSpecVectors(b *testing.B) {
	c := NewChecker(nil)
	c.SetEntries(entryData1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tc := range checkData1 {
			c.Check(tc.Subject, tc.Path, tc.Privilege)
		}
	}
}
