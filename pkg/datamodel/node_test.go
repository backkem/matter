package datamodel

import (
	"context"
	"sync"
	"testing"

	"github.com/backkem/matter/pkg/tlv"
)

func TestBasicNode_AddEndpoint(t *testing.T) {
	node := NewNode()

	ep1 := NewEndpoint(0)
	ep2 := NewEndpoint(1)

	// Add first endpoint
	if err := node.AddEndpoint(ep1); err != nil {
		t.Fatalf("AddEndpoint(0) failed: %v", err)
	}

	// Add second endpoint
	if err := node.AddEndpoint(ep2); err != nil {
		t.Fatalf("AddEndpoint(1) failed: %v", err)
	}

	// Try to add duplicate
	epDup := NewEndpoint(0)
	if err := node.AddEndpoint(epDup); err != ErrEndpointExists {
		t.Errorf("AddEndpoint(duplicate) = %v, want ErrEndpointExists", err)
	}

	if node.EndpointCount() != 2 {
		t.Errorf("EndpointCount() = %v, want 2", node.EndpointCount())
	}
}

func TestBasicNode_GetEndpoint(t *testing.T) {
	node := NewNode()

	ep := NewEndpoint(5)
	node.AddEndpoint(ep)

	// Get existing endpoint
	got := node.GetEndpoint(5)
	if got == nil {
		t.Fatal("GetEndpoint(5) = nil, want non-nil")
	}
	if got.ID() != 5 {
		t.Errorf("GetEndpoint(5).ID() = %v, want 5", got.ID())
	}

	// Get non-existent endpoint
	if node.GetEndpoint(99) != nil {
		t.Error("GetEndpoint(99) = non-nil, want nil")
	}
}

func TestBasicNode_GetEndpoints(t *testing.T) {
	node := NewNode()

	// Add endpoints in specific order
	node.AddEndpoint(NewEndpoint(2))
	node.AddEndpoint(NewEndpoint(0))
	node.AddEndpoint(NewEndpoint(1))

	endpoints := node.GetEndpoints()

	if len(endpoints) != 3 {
		t.Fatalf("len(GetEndpoints()) = %v, want 3", len(endpoints))
	}

	// Verify registration order is preserved
	expectedOrder := []EndpointID{2, 0, 1}
	for i, ep := range endpoints {
		if ep.ID() != expectedOrder[i] {
			t.Errorf("endpoints[%d].ID() = %v, want %v", i, ep.ID(), expectedOrder[i])
		}
	}
}

func TestBasicNode_RemoveEndpoint(t *testing.T) {
	node := NewNode()

	node.AddEndpoint(NewEndpoint(0))
	node.AddEndpoint(NewEndpoint(1))

	// Remove existing endpoint
	if err := node.RemoveEndpoint(0); err != nil {
		t.Fatalf("RemoveEndpoint(0) failed: %v", err)
	}

	if node.EndpointCount() != 1 {
		t.Errorf("EndpointCount() = %v, want 1", node.EndpointCount())
	}

	if node.GetEndpoint(0) != nil {
		t.Error("GetEndpoint(0) = non-nil after remove")
	}

	// Remove non-existent endpoint
	if err := node.RemoveEndpoint(99); err != ErrEndpointNotFound {
		t.Errorf("RemoveEndpoint(99) = %v, want ErrEndpointNotFound", err)
	}
}

func TestBasicNode_HasEndpoint(t *testing.T) {
	node := NewNode()
	node.AddEndpoint(NewEndpoint(0))

	if !node.HasEndpoint(0) {
		t.Error("HasEndpoint(0) = false, want true")
	}

	if node.HasEndpoint(1) {
		t.Error("HasEndpoint(1) = true, want false")
	}
}

func TestBasicNode_GetCluster(t *testing.T) {
	node := NewNode()

	ep := NewEndpoint(0)
	cluster := &mockCluster{id: ClusterOnOff, endpointID: 0}
	ep.AddCluster(cluster)
	node.AddEndpoint(ep)

	// Get existing cluster
	c := node.GetCluster(0, ClusterOnOff)
	if c == nil {
		t.Fatal("GetCluster(0, OnOff) = nil, want non-nil")
	}

	// Get from non-existent endpoint
	if node.GetCluster(99, ClusterOnOff) != nil {
		t.Error("GetCluster(99, OnOff) = non-nil, want nil")
	}

	// Get non-existent cluster
	if node.GetCluster(0, 9999) != nil {
		t.Error("GetCluster(0, 9999) = non-nil, want nil")
	}
}

func TestBasicNode_AttributeChangeListener(t *testing.T) {
	node := NewNode()

	var notifiedPath *ConcreteAttributePath
	listener := &mockAttributeChangeListener{
		onChanged: func(path ConcreteAttributePath) {
			notifiedPath = &path
		},
	}

	node.SetAttributeChangeListener(listener)

	expectedPath := ConcreteAttributePath{
		Endpoint:  1,
		Cluster:   ClusterOnOff,
		Attribute: 0,
	}
	node.NotifyAttributeChanged(expectedPath)

	if notifiedPath == nil {
		t.Fatal("Listener was not called")
	}
	if *notifiedPath != expectedPath {
		t.Errorf("Notified path = %v, want %v", *notifiedPath, expectedPath)
	}
}

func TestBasicNode_Concurrent(t *testing.T) {
	node := NewNode()

	// Pre-populate
	for i := 0; i < 10; i++ {
		node.AddEndpoint(NewEndpoint(EndpointID(i)))
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
				node.GetEndpoint(EndpointID(id % 10))
				node.GetEndpoints()
				node.EndpointCount()
			}
		}(i)
	}

	wg.Wait()
}

// Mock types for testing

type mockCluster struct {
	id         ClusterID
	endpointID EndpointID
}

func (m *mockCluster) ID() ClusterID                       { return m.id }
func (m *mockCluster) EndpointID() EndpointID              { return m.endpointID }
func (m *mockCluster) DataVersion() DataVersion            { return 1 }
func (m *mockCluster) ClusterRevision() uint16             { return 1 }
func (m *mockCluster) FeatureMap() uint32                  { return 0 }
func (m *mockCluster) AttributeList() []AttributeEntry     { return nil }
func (m *mockCluster) AcceptedCommandList() []CommandEntry { return nil }
func (m *mockCluster) GeneratedCommandList() []CommandID   { return nil }

func (m *mockCluster) ReadAttribute(_ context.Context, _ ReadAttributeRequest, _ *tlv.Writer) error {
	return nil
}

func (m *mockCluster) WriteAttribute(_ context.Context, _ WriteAttributeRequest, _ *tlv.Reader) error {
	return nil
}

func (m *mockCluster) InvokeCommand(_ context.Context, _ InvokeRequest, _ *tlv.Reader) ([]byte, error) {
	return nil, nil
}

type mockAttributeChangeListener struct {
	onChanged func(path ConcreteAttributePath)
}

func (m *mockAttributeChangeListener) OnAttributeChanged(path ConcreteAttributePath) {
	if m.onChanged != nil {
		m.onChanged(path)
	}
}
