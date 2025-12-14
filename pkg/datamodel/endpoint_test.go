package datamodel

import (
	"sync"
	"testing"
)

func TestBasicEndpoint_New(t *testing.T) {
	ep := NewEndpoint(5)

	if ep.ID() != 5 {
		t.Errorf("ID() = %v, want 5", ep.ID())
	}

	entry := ep.Entry()
	if entry.ID != 5 {
		t.Errorf("Entry().ID = %v, want 5", entry.ID)
	}
	if entry.ParentID != nil {
		t.Errorf("Entry().ParentID = %v, want nil", entry.ParentID)
	}
	if entry.CompositionPattern != CompositionTree {
		t.Errorf("Entry().CompositionPattern = %v, want Tree", entry.CompositionPattern)
	}
}

func TestBasicEndpoint_NewWithParent(t *testing.T) {
	ep := NewEndpointWithParent(5, 0)

	if ep.ID() != 5 {
		t.Errorf("ID() = %v, want 5", ep.ID())
	}

	entry := ep.Entry()
	if entry.ParentID == nil {
		t.Fatal("Entry().ParentID = nil, want 0")
	}
	if *entry.ParentID != 0 {
		t.Errorf("Entry().ParentID = %v, want 0", *entry.ParentID)
	}
}

func TestBasicEndpoint_SetParent(t *testing.T) {
	ep := NewEndpoint(1)

	ep.SetParent(0)

	entry := ep.Entry()
	if entry.ParentID == nil {
		t.Fatal("ParentID = nil, want 0")
	}
	if *entry.ParentID != 0 {
		t.Errorf("ParentID = %v, want 0", *entry.ParentID)
	}
}

func TestBasicEndpoint_SetCompositionPattern(t *testing.T) {
	ep := NewEndpoint(0)

	ep.SetCompositionPattern(CompositionFullFamily)

	entry := ep.Entry()
	if entry.CompositionPattern != CompositionFullFamily {
		t.Errorf("CompositionPattern = %v, want FullFamily", entry.CompositionPattern)
	}
}

func TestBasicEndpoint_AddCluster(t *testing.T) {
	ep := NewEndpoint(0)

	c1 := &mockCluster{id: ClusterOnOff, endpointID: 0}
	c2 := &mockCluster{id: ClusterLevelControl, endpointID: 0}

	// Add first cluster
	if err := ep.AddCluster(c1); err != nil {
		t.Fatalf("AddCluster(OnOff) failed: %v", err)
	}

	// Add second cluster
	if err := ep.AddCluster(c2); err != nil {
		t.Fatalf("AddCluster(LevelControl) failed: %v", err)
	}

	// Try to add duplicate
	cDup := &mockCluster{id: ClusterOnOff, endpointID: 0}
	if err := ep.AddCluster(cDup); err != ErrClusterExists {
		t.Errorf("AddCluster(duplicate) = %v, want ErrClusterExists", err)
	}

	if ep.ClusterCount() != 2 {
		t.Errorf("ClusterCount() = %v, want 2", ep.ClusterCount())
	}
}

func TestBasicEndpoint_GetCluster(t *testing.T) {
	ep := NewEndpoint(0)

	cluster := &mockCluster{id: ClusterOnOff, endpointID: 0}
	ep.AddCluster(cluster)

	// Get existing cluster
	got := ep.GetCluster(ClusterOnOff)
	if got == nil {
		t.Fatal("GetCluster(OnOff) = nil, want non-nil")
	}
	if got.ID() != ClusterOnOff {
		t.Errorf("GetCluster(OnOff).ID() = %v, want OnOff", got.ID())
	}

	// Get non-existent cluster
	if ep.GetCluster(9999) != nil {
		t.Error("GetCluster(9999) = non-nil, want nil")
	}
}

func TestBasicEndpoint_GetClusters(t *testing.T) {
	ep := NewEndpoint(0)

	// Add clusters in specific order
	ep.AddCluster(&mockCluster{id: ClusterLevelControl, endpointID: 0})
	ep.AddCluster(&mockCluster{id: ClusterOnOff, endpointID: 0})
	ep.AddCluster(&mockCluster{id: ClusterColorControl, endpointID: 0})

	clusters := ep.GetClusters()

	if len(clusters) != 3 {
		t.Fatalf("len(GetClusters()) = %v, want 3", len(clusters))
	}

	// Verify registration order is preserved
	expectedOrder := []ClusterID{ClusterLevelControl, ClusterOnOff, ClusterColorControl}
	for i, c := range clusters {
		if c.ID() != expectedOrder[i] {
			t.Errorf("clusters[%d].ID() = %v, want %v", i, c.ID(), expectedOrder[i])
		}
	}
}

func TestBasicEndpoint_RemoveCluster(t *testing.T) {
	ep := NewEndpoint(0)

	ep.AddCluster(&mockCluster{id: ClusterOnOff, endpointID: 0})
	ep.AddCluster(&mockCluster{id: ClusterLevelControl, endpointID: 0})

	// Remove existing cluster
	if err := ep.RemoveCluster(ClusterOnOff); err != nil {
		t.Fatalf("RemoveCluster(OnOff) failed: %v", err)
	}

	if ep.ClusterCount() != 1 {
		t.Errorf("ClusterCount() = %v, want 1", ep.ClusterCount())
	}

	if ep.GetCluster(ClusterOnOff) != nil {
		t.Error("GetCluster(OnOff) = non-nil after remove")
	}

	// Remove non-existent cluster
	if err := ep.RemoveCluster(9999); err != ErrClusterNotFound {
		t.Errorf("RemoveCluster(9999) = %v, want ErrClusterNotFound", err)
	}
}

func TestBasicEndpoint_HasCluster(t *testing.T) {
	ep := NewEndpoint(0)
	ep.AddCluster(&mockCluster{id: ClusterOnOff, endpointID: 0})

	if !ep.HasCluster(ClusterOnOff) {
		t.Error("HasCluster(OnOff) = false, want true")
	}

	if ep.HasCluster(9999) {
		t.Error("HasCluster(9999) = true, want false")
	}
}

func TestBasicEndpoint_DeviceTypes(t *testing.T) {
	ep := NewEndpoint(1)

	// Initially empty
	if len(ep.GetDeviceTypes()) != 0 {
		t.Errorf("Initial GetDeviceTypes() len = %v, want 0", len(ep.GetDeviceTypes()))
	}

	// Add device types
	ep.AddDeviceType(DeviceTypeEntry{DeviceTypeID: DeviceTypeOnOffLight, Revision: 1})
	ep.AddDeviceType(DeviceTypeEntry{DeviceTypeID: DeviceTypeDimmableLight, Revision: 2})

	dts := ep.GetDeviceTypes()
	if len(dts) != 2 {
		t.Fatalf("GetDeviceTypes() len = %v, want 2", len(dts))
	}

	if dts[0].DeviceTypeID != DeviceTypeOnOffLight {
		t.Errorf("DeviceTypes[0].DeviceTypeID = %v, want OnOffLight", dts[0].DeviceTypeID)
	}
	if dts[1].DeviceTypeID != DeviceTypeDimmableLight {
		t.Errorf("DeviceTypes[1].DeviceTypeID = %v, want DimmableLight", dts[1].DeviceTypeID)
	}

	// Clear device types
	ep.ClearDeviceTypes()
	if len(ep.GetDeviceTypes()) != 0 {
		t.Errorf("After Clear GetDeviceTypes() len = %v, want 0", len(ep.GetDeviceTypes()))
	}
}

func TestBasicEndpoint_GetClusterIDs(t *testing.T) {
	ep := NewEndpoint(0)

	ep.AddCluster(&mockCluster{id: ClusterOnOff, endpointID: 0})
	ep.AddCluster(&mockCluster{id: ClusterLevelControl, endpointID: 0})

	ids := ep.GetClusterIDs()

	if len(ids) != 2 {
		t.Fatalf("len(GetClusterIDs()) = %v, want 2", len(ids))
	}

	if ids[0] != ClusterOnOff {
		t.Errorf("ClusterIDs[0] = %v, want OnOff", ids[0])
	}
	if ids[1] != ClusterLevelControl {
		t.Errorf("ClusterIDs[1] = %v, want LevelControl", ids[1])
	}
}

func TestBasicEndpoint_Concurrent(t *testing.T) {
	ep := NewEndpoint(0)

	// Pre-populate with clusters
	for i := 0; i < 10; i++ {
		ep.AddCluster(&mockCluster{id: ClusterID(i), endpointID: 0})
	}

	var wg sync.WaitGroup
	const goroutines = 10
	const iterations = 100

	// Concurrent reads
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				ep.GetCluster(ClusterID(id % 10))
				ep.GetClusters()
				ep.ClusterCount()
				ep.Entry()
				ep.GetDeviceTypes()
			}
		}(i)
	}

	wg.Wait()
}
