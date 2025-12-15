package acl

import "testing"

func TestCASEAuthTag_GetIdentifier(t *testing.T) {
	tests := []struct {
		cat  CASEAuthTag
		want uint16
	}{
		{0x0001_0001, 0x0001},
		{0x0002_0001, 0x0002},
		{0xABCD_0002, 0xABCD},
		{0xFFFF_FFFF, 0xFFFF},
		{0x0000_0001, 0x0000},
	}

	for _, tt := range tests {
		if got := tt.cat.GetIdentifier(); got != tt.want {
			t.Errorf("CASEAuthTag(0x%08X).GetIdentifier() = 0x%04X, want 0x%04X", tt.cat, got, tt.want)
		}
	}
}

func TestCASEAuthTag_GetVersion(t *testing.T) {
	tests := []struct {
		cat  CASEAuthTag
		want uint16
	}{
		{0x0001_0001, 0x0001},
		{0x0002_0001, 0x0001},
		{0xABCD_0002, 0x0002},
		{0xABCD_ABCD, 0xABCD},
		{0xFFFF_0000, 0x0000},
	}

	for _, tt := range tests {
		if got := tt.cat.GetVersion(); got != tt.want {
			t.Errorf("CASEAuthTag(0x%08X).GetVersion() = 0x%04X, want 0x%04X", tt.cat, got, tt.want)
		}
	}
}

func TestCASEAuthTag_IsValid(t *testing.T) {
	tests := []struct {
		cat  CASEAuthTag
		want bool
	}{
		{0x0001_0001, true},  // Version 1
		{0xABCD_0002, true},  // Version 2
		{0xFFFF_FFFF, true},  // Max version
		{0x0001_0000, false}, // Version 0
		{0xFFFF_0000, false}, // Version 0
		{CATUndefined, false},
	}

	for _, tt := range tests {
		if got := tt.cat.IsValid(); got != tt.want {
			t.Errorf("CASEAuthTag(0x%08X).IsValid() = %v, want %v", tt.cat, got, tt.want)
		}
	}
}

func TestCASEAuthTag_NodeID(t *testing.T) {
	tests := []struct {
		cat  CASEAuthTag
		want uint64
	}{
		{0x0001_0001, 0xFFFF_FFFD_0001_0001},
		{0xABCD_0002, 0xFFFF_FFFD_ABCD_0002},
		{0xFFFF_FFFF, 0xFFFF_FFFD_FFFF_FFFF},
		{0x0000_0000, 0xFFFF_FFFD_0000_0000},
	}

	for _, tt := range tests {
		if got := tt.cat.NodeID(); got != tt.want {
			t.Errorf("CASEAuthTag(0x%08X).NodeID() = 0x%016X, want 0x%016X", tt.cat, got, tt.want)
		}
	}
}

func TestNewCASEAuthTag(t *testing.T) {
	tests := []struct {
		identifier uint16
		version    uint16
		want       CASEAuthTag
	}{
		{0x0001, 0x0001, 0x0001_0001},
		{0xABCD, 0x0002, 0xABCD_0002},
		{0xFFFF, 0xFFFF, 0xFFFF_FFFF},
	}

	for _, tt := range tests {
		got := NewCASEAuthTag(tt.identifier, tt.version)
		if got != tt.want {
			t.Errorf("NewCASEAuthTag(0x%04X, 0x%04X) = 0x%08X, want 0x%08X",
				tt.identifier, tt.version, got, tt.want)
		}
	}
}

func TestIsCATNodeID(t *testing.T) {
	tests := []struct {
		nodeID uint64
		want   bool
	}{
		// Valid CAT NodeIDs
		{0xFFFF_FFFD_0000_0001, true},
		{0xFFFF_FFFD_0001_0001, true},
		{0xFFFF_FFFD_ABCD_0002, true},
		{0xFFFF_FFFD_FFFF_FFFF, true},
		{0xFFFF_FFFD_0000_0000, true}, // Min CAT

		// Not CAT NodeIDs
		{0x0000_0000_0000_0001, false}, // Operational
		{0xFFFF_FFEF_FFFF_FFFF, false}, // Max operational
		{0xFFFF_FFFC_0000_0000, false}, // Reserved
		{0xFFFF_FFFE_0000_0000, false}, // Temporary local
		{0xFFFF_FFFF_0000_0001, false}, // Group
	}

	for _, tt := range tests {
		if got := IsCATNodeID(tt.nodeID); got != tt.want {
			t.Errorf("IsCATNodeID(0x%016X) = %v, want %v", tt.nodeID, got, tt.want)
		}
	}
}

func TestCATFromNodeID(t *testing.T) {
	tests := []struct {
		nodeID uint64
		want   CASEAuthTag
	}{
		{0xFFFF_FFFD_0001_0001, 0x0001_0001},
		{0xFFFF_FFFD_ABCD_0002, 0xABCD_0002},
		{0xFFFF_FFFD_FFFF_FFFF, 0xFFFF_FFFF},
		// Non-CAT NodeIDs return CATUndefined
		{0x0000_0000_0000_0001, CATUndefined},
		{0xFFFF_FFFF_0000_0001, CATUndefined},
	}

	for _, tt := range tests {
		if got := CATFromNodeID(tt.nodeID); got != tt.want {
			t.Errorf("CATFromNodeID(0x%016X) = 0x%08X, want 0x%08X", tt.nodeID, got, tt.want)
		}
	}
}

func TestCATValues_GetNumTagsPresent(t *testing.T) {
	tests := []struct {
		cats CATValues
		want int
	}{
		{CATValues{}, 0},
		{CATValues{0x0001_0001, 0, 0}, 1},
		{CATValues{0x0001_0001, 0x0002_0001, 0}, 2},
		{CATValues{0x0001_0001, 0x0002_0001, 0x0003_0001}, 3},
	}

	for _, tt := range tests {
		if got := tt.cats.GetNumTagsPresent(); got != tt.want {
			t.Errorf("CATValues%v.GetNumTagsPresent() = %d, want %d", tt.cats, got, tt.want)
		}
	}
}

func TestCATValues_AreValid(t *testing.T) {
	tests := []struct {
		name string
		cats CATValues
		want bool
	}{
		{"empty", CATValues{}, true},
		{"one valid", CATValues{0x0001_0001, 0, 0}, true},
		{"three valid", CATValues{0x0001_0001, 0x0002_0002, 0x0003_0003}, true},
		{"version 0", CATValues{0x0001_0000, 0, 0}, false},
		{"duplicate identifier", CATValues{0x0001_0001, 0x0001_0002, 0}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cats.AreValid(); got != tt.want {
				t.Errorf("CATValues.AreValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCATValues_CheckSubjectAgainstCATs(t *testing.T) {
	// Test vectors from C++ TestAccessControl.cpp
	// CATs defined in test file:
	// kCASEAuthTag0 = 0x0001_0001
	// kCASEAuthTag1 = 0x0002_0001
	// kCASEAuthTag2 = 0xABCD_0002
	// kCASEAuthTag3 = 0xABCD_0008
	// kCASEAuthTag4 = 0xABCD_ABCD

	kCASEAuthTag0 := CASEAuthTag(0x0001_0001)
	kCASEAuthTag1 := CASEAuthTag(0x0002_0001)
	kCASEAuthTag2 := CASEAuthTag(0xABCD_0002)
	kCASEAuthTag3 := CASEAuthTag(0xABCD_0008)
	kCASEAuthTag4 := CASEAuthTag(0xABCD_ABCD)

	tests := []struct {
		name    string
		cats    CATValues
		subject uint64
		want    bool
	}{
		// Basic matching - same identifier and version
		{
			"exact match",
			CATValues{kCASEAuthTag0, 0, 0},
			kCASEAuthTag0.NodeID(),
			true,
		},
		{
			"different identifier",
			CATValues{kCASEAuthTag0, 0, 0},
			kCASEAuthTag1.NodeID(),
			false,
		},

		// Version matching (holder version >= entry version)
		// Entry has version 2, subject has version 8 -> match (8 >= 2)
		{
			"subject version higher than entry",
			CATValues{kCASEAuthTag2, 0, 0}, // 0xABCD_0002
			kCASEAuthTag3.NodeID(),         // 0xABCD_0008
			false,                          // Subject's 8 vs our 2 - we need >= subject
		},
		// Holder (us) has version 8, entry (subject) has version 2 -> match (8 >= 2)
		{
			"holder version higher than subject",
			CATValues{kCASEAuthTag3, 0, 0}, // 0xABCD_0008
			kCASEAuthTag2.NodeID(),         // 0xABCD_0002
			true,                           // Our 8 >= subject's 2
		},
		// Holder has version 0xABCD, subject has version 2 -> match
		{
			"holder has max-ish version",
			CATValues{kCASEAuthTag4, 0, 0}, // 0xABCD_ABCD
			kCASEAuthTag2.NodeID(),         // 0xABCD_0002
			true,                           // Our 0xABCD >= 2
		},

		// Non-CAT subject
		{
			"non-CAT subject",
			CATValues{kCASEAuthTag0, 0, 0},
			0x0123_4567_89AB_CDEF, // Operational NodeID
			false,
		},

		// Empty CATs
		{
			"empty CATs",
			CATValues{},
			kCASEAuthTag0.NodeID(),
			false,
		},

		// Subject with version 0 (invalid)
		{
			"subject version 0",
			CATValues{0xABCD_0001, 0, 0},
			NewCASEAuthTag(0xABCD, 0).NodeID(), // Version 0
			false,
		},

		// Multiple CATs, one matches
		{
			"multiple CATs one match",
			CATValues{kCASEAuthTag0, kCASEAuthTag3, 0},
			kCASEAuthTag2.NodeID(), // Same identifier as kCASEAuthTag3, lower version
			true,                   // kCASEAuthTag3 (version 8) >= kCASEAuthTag2 (version 2)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cats.CheckSubjectAgainstCATs(tt.subject)
			if got != tt.want {
				t.Errorf("CATValues%v.CheckSubjectAgainstCATs(0x%016X) = %v, want %v",
					tt.cats, tt.subject, got, tt.want)
			}
		})
	}
}

func TestCATValues_Contains(t *testing.T) {
	cats := CATValues{0x0001_0001, 0x0002_0002, 0}

	if !cats.Contains(0x0001_0001) {
		t.Error("Contains should return true for present CAT")
	}
	if cats.Contains(0x0003_0003) {
		t.Error("Contains should return false for absent CAT")
	}
	if cats.Contains(CATUndefined) {
		t.Error("Contains should return false for CATUndefined")
	}
}

func TestCATValues_ContainsIdentifier(t *testing.T) {
	cats := CATValues{0x0001_0001, 0x0002_0002, 0}

	if !cats.ContainsIdentifier(0x0001) {
		t.Error("ContainsIdentifier should return true for present identifier")
	}
	if !cats.ContainsIdentifier(0x0002) {
		t.Error("ContainsIdentifier should return true for present identifier")
	}
	if cats.ContainsIdentifier(0x0003) {
		t.Error("ContainsIdentifier should return false for absent identifier")
	}
}

func TestCATValues_Equal(t *testing.T) {
	tests := []struct {
		name string
		a    CATValues
		b    CATValues
		want bool
	}{
		{
			"both empty",
			CATValues{},
			CATValues{},
			true,
		},
		{
			"same order",
			CATValues{0x0001_0001, 0x0002_0002, 0},
			CATValues{0x0001_0001, 0x0002_0002, 0},
			true,
		},
		{
			"different order",
			CATValues{0x0001_0001, 0x0002_0002, 0},
			CATValues{0x0002_0002, 0x0001_0001, 0},
			true,
		},
		{
			"different count",
			CATValues{0x0001_0001, 0, 0},
			CATValues{0x0001_0001, 0x0002_0002, 0},
			false,
		},
		{
			"different values",
			CATValues{0x0001_0001, 0, 0},
			CATValues{0x0001_0002, 0, 0},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.Equal(tt.b); got != tt.want {
				t.Errorf("CATValues.Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}
