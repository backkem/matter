package datamodel

import "testing"

func TestIsGlobalAttribute(t *testing.T) {
	tests := []struct {
		id   AttributeID
		want bool
	}{
		{GlobalAttrClusterRevision, true},
		{GlobalAttrFeatureMap, true},
		{GlobalAttrAttributeList, true},
		{GlobalAttrEventList, true},
		{GlobalAttrAcceptedCommandList, true},
		{GlobalAttrGeneratedCommandList, true},
		{0, false},
		{100, false},
		{0xFFF7, false},
		{0xFFFE, false},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			if got := IsGlobalAttribute(tt.id); got != tt.want {
				t.Errorf("IsGlobalAttribute(0x%04X) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}

func TestIsGlobalCommand(t *testing.T) {
	tests := []struct {
		id   CommandID
		want bool
	}{
		{GlobalCmdAtomicRequest, true},
		{GlobalCmdAtomicResponse, true},
		{0, false},
		{100, false},
		{0xFF, false},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			if got := IsGlobalCommand(tt.id); got != tt.want {
				t.Errorf("IsGlobalCommand(0x%02X) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}

func TestGlobalAttributeEntries(t *testing.T) {
	entries := GlobalAttributeEntries()

	if len(entries) != 5 {
		t.Fatalf("len(GlobalAttributeEntries()) = %v, want 5", len(entries))
	}

	// Verify all global attributes are present
	expectedIDs := []AttributeID{
		GlobalAttrClusterRevision,
		GlobalAttrFeatureMap,
		GlobalAttrAttributeList,
		GlobalAttrAcceptedCommandList,
		GlobalAttrGeneratedCommandList,
	}

	for _, expectedID := range expectedIDs {
		found := false
		for _, entry := range entries {
			if entry.ID == expectedID {
				found = true

				// All global attributes should be readable with View privilege
				if !entry.IsReadable() {
					t.Errorf("Global attribute 0x%04X should be readable", expectedID)
				}
				if *entry.ReadPrivilege != PrivilegeView {
					t.Errorf("Global attribute 0x%04X ReadPrivilege = %v, want View", expectedID, *entry.ReadPrivilege)
				}

				// All global attributes should have Fixed quality
				if !entry.HasQuality(AttrQualityFixed) {
					t.Errorf("Global attribute 0x%04X should have Fixed quality", expectedID)
				}

				// Global attributes should not be writable
				if entry.IsWritable() {
					t.Errorf("Global attribute 0x%04X should not be writable", expectedID)
				}

				break
			}
		}
		if !found {
			t.Errorf("Global attribute 0x%04X not found in GlobalAttributeEntries()", expectedID)
		}
	}

	// Verify list attributes have List quality
	for _, entry := range entries {
		switch entry.ID {
		case GlobalAttrAttributeList, GlobalAttrAcceptedCommandList, GlobalAttrGeneratedCommandList:
			if !entry.IsList() {
				t.Errorf("Global attribute 0x%04X should have List quality", entry.ID)
			}
		}
	}
}

func TestGlobalConstants(t *testing.T) {
	// Verify endpoint constants
	if EndpointRoot != 0 {
		t.Errorf("EndpointRoot = %v, want 0", EndpointRoot)
	}

	// Verify some well-known cluster IDs
	tests := []struct {
		name string
		got  ClusterID
		want ClusterID
	}{
		{"Descriptor", ClusterDescriptor, 0x001D},
		{"BasicInformation", ClusterBasicInformation, 0x0028},
		{"OnOff", ClusterOnOff, 0x0006},
		{"LevelControl", ClusterLevelControl, 0x0008},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = 0x%04X, want 0x%04X", tt.name, tt.got, tt.want)
			}
		})
	}

	// Verify some device type IDs
	dtTests := []struct {
		name string
		got  DeviceTypeID
		want DeviceTypeID
	}{
		{"RootNode", DeviceTypeRootNode, 0x0016},
		{"OnOffLight", DeviceTypeOnOffLight, 0x0100},
	}

	for _, tt := range dtTests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = 0x%04X, want 0x%04X", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestMergeAttributeLists(t *testing.T) {
	clusterAttrs := []AttributeEntry{
		NewReadOnlyAttribute(0, 0, PrivilegeView),
		NewReadOnlyAttribute(1, 0, PrivilegeView),
	}

	merged := MergeAttributeLists(clusterAttrs)

	// Should have cluster attrs + 5 global attrs
	expectedLen := len(clusterAttrs) + 5
	if len(merged) != expectedLen {
		t.Errorf("len(merged) = %v, want %v", len(merged), expectedLen)
	}

	// Cluster attributes should come first
	if merged[0].ID != 0 {
		t.Errorf("merged[0].ID = %v, want 0", merged[0].ID)
	}
	if merged[1].ID != 1 {
		t.Errorf("merged[1].ID = %v, want 1", merged[1].ID)
	}
}

func TestFindAttribute(t *testing.T) {
	list := []AttributeEntry{
		{ID: 0},
		{ID: 10},
		{ID: 20},
	}

	// Find existing
	found := FindAttribute(list, 10)
	if found == nil {
		t.Fatal("FindAttribute(10) = nil, want non-nil")
	}
	if found.ID != 10 {
		t.Errorf("FindAttribute(10).ID = %v, want 10", found.ID)
	}

	// Find non-existent
	if FindAttribute(list, 99) != nil {
		t.Error("FindAttribute(99) = non-nil, want nil")
	}
}

func TestFindCommand(t *testing.T) {
	list := []CommandEntry{
		{ID: 0},
		{ID: 10},
		{ID: 20},
	}

	// Find existing
	found := FindCommand(list, 10)
	if found == nil {
		t.Fatal("FindCommand(10) = nil, want non-nil")
	}
	if found.ID != 10 {
		t.Errorf("FindCommand(10).ID = %v, want 10", found.ID)
	}

	// Find non-existent
	if FindCommand(list, 99) != nil {
		t.Error("FindCommand(99) = non-nil, want nil")
	}
}
