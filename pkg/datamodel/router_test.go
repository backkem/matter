package datamodel

import (
	"context"
	"testing"

	"github.com/backkem/matter/pkg/tlv"
)

// routerTestCluster implements Cluster for router testing with callbacks.
type routerTestCluster struct {
	id              ClusterID
	endpointID      EndpointID
	dataVersion     DataVersion
	clusterRevision uint16
	featureMap      uint32
	attributes      []AttributeEntry
	commands        []CommandEntry
	generatedCmds   []CommandID

	readFunc   func(ctx context.Context, req ReadAttributeRequest, w *tlv.Writer) error
	writeFunc  func(ctx context.Context, req WriteAttributeRequest, r *tlv.Reader) error
	invokeFunc func(ctx context.Context, req InvokeRequest, r *tlv.Reader) ([]byte, error)
}

func (m *routerTestCluster) ID() ClusterID                        { return m.id }
func (m *routerTestCluster) EndpointID() EndpointID               { return m.endpointID }
func (m *routerTestCluster) DataVersion() DataVersion             { return m.dataVersion }
func (m *routerTestCluster) ClusterRevision() uint16              { return m.clusterRevision }
func (m *routerTestCluster) FeatureMap() uint32                   { return m.featureMap }
func (m *routerTestCluster) AttributeList() []AttributeEntry      { return m.attributes }
func (m *routerTestCluster) AcceptedCommandList() []CommandEntry  { return m.commands }
func (m *routerTestCluster) GeneratedCommandList() []CommandID    { return m.generatedCmds }

func (m *routerTestCluster) ReadAttribute(ctx context.Context, req ReadAttributeRequest, w *tlv.Writer) error {
	if m.readFunc != nil {
		return m.readFunc(ctx, req, w)
	}
	return nil
}

func (m *routerTestCluster) WriteAttribute(ctx context.Context, req WriteAttributeRequest, r *tlv.Reader) error {
	if m.writeFunc != nil {
		return m.writeFunc(ctx, req, r)
	}
	return nil
}

func (m *routerTestCluster) InvokeCommand(ctx context.Context, req InvokeRequest, r *tlv.Reader) ([]byte, error) {
	if m.invokeFunc != nil {
		return m.invokeFunc(ctx, req, r)
	}
	return nil, nil
}

func TestRouter_RegisterCluster(t *testing.T) {
	router := NewRouter()

	cluster := &routerTestCluster{
		id:         0x001D, // Descriptor
		endpointID: 0,
	}

	router.RegisterCluster(0, cluster)

	got, err := router.GetCluster(0, 0x001D)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != cluster {
		t.Error("expected registered cluster")
	}
}

func TestRouter_RegisterMultipleClusters(t *testing.T) {
	router := NewRouter()

	descriptorCluster := &routerTestCluster{id: 0x001D, endpointID: 0}
	basicCluster := &routerTestCluster{id: 0x0028, endpointID: 0}
	onoffCluster := &routerTestCluster{id: 0x0006, endpointID: 1}

	router.RegisterCluster(0, descriptorCluster)
	router.RegisterCluster(0, basicCluster)
	router.RegisterCluster(1, onoffCluster)

	// Check endpoint 0
	got, err := router.GetCluster(0, 0x001D)
	if err != nil || got != descriptorCluster {
		t.Error("expected descriptor cluster on endpoint 0")
	}

	got, err = router.GetCluster(0, 0x0028)
	if err != nil || got != basicCluster {
		t.Error("expected basic cluster on endpoint 0")
	}

	// Check endpoint 1
	got, err = router.GetCluster(1, 0x0006)
	if err != nil || got != onoffCluster {
		t.Error("expected onoff cluster on endpoint 1")
	}
}

func TestRouter_GetCluster_NotFound(t *testing.T) {
	router := NewRouter()

	// No endpoints registered
	_, err := router.GetCluster(0, 0x001D)
	if err != ErrEndpointNotFound {
		t.Errorf("expected ErrEndpointNotFound, got %v", err)
	}

	// Register a cluster on endpoint 0
	router.RegisterCluster(0, &routerTestCluster{id: 0x001D, endpointID: 0})

	// Cluster not on this endpoint
	_, err = router.GetCluster(0, 0x0006)
	if err != ErrClusterNotFound {
		t.Errorf("expected ErrClusterNotFound, got %v", err)
	}

	// Endpoint doesn't exist
	_, err = router.GetCluster(1, 0x001D)
	if err != ErrEndpointNotFound {
		t.Errorf("expected ErrEndpointNotFound, got %v", err)
	}
}

func TestRouter_UnregisterCluster(t *testing.T) {
	router := NewRouter()

	cluster1 := &routerTestCluster{id: 0x001D, endpointID: 0}
	cluster2 := &routerTestCluster{id: 0x0028, endpointID: 0}

	router.RegisterCluster(0, cluster1)
	router.RegisterCluster(0, cluster2)

	// Unregister one cluster
	router.UnregisterCluster(0, 0x001D)

	_, err := router.GetCluster(0, 0x001D)
	if err != ErrClusterNotFound {
		t.Error("expected cluster to be unregistered")
	}

	// Other cluster should still exist
	got, err := router.GetCluster(0, 0x0028)
	if err != nil || got != cluster2 {
		t.Error("expected other cluster to still exist")
	}

	// Unregister last cluster - endpoint should be removed
	router.UnregisterCluster(0, 0x0028)

	_, err = router.GetCluster(0, 0x0028)
	if err != ErrEndpointNotFound {
		t.Error("expected endpoint to be removed when empty")
	}
}

func TestRouter_GetEndpointClusters(t *testing.T) {
	router := NewRouter()

	cluster1 := &routerTestCluster{id: 0x001D, endpointID: 0}
	cluster2 := &routerTestCluster{id: 0x0028, endpointID: 0}

	router.RegisterCluster(0, cluster1)
	router.RegisterCluster(0, cluster2)

	clusters := router.GetEndpointClusters(0)
	if len(clusters) != 2 {
		t.Errorf("expected 2 clusters, got %d", len(clusters))
	}

	// Non-existent endpoint
	clusters = router.GetEndpointClusters(99)
	if clusters != nil {
		t.Error("expected nil for non-existent endpoint")
	}
}

func TestRouter_GetEndpointIDs(t *testing.T) {
	router := NewRouter()

	router.RegisterCluster(0, &routerTestCluster{id: 0x001D, endpointID: 0})
	router.RegisterCluster(1, &routerTestCluster{id: 0x0006, endpointID: 1})
	router.RegisterCluster(2, &routerTestCluster{id: 0x0006, endpointID: 2})

	ids := router.GetEndpointIDs()
	if len(ids) != 3 {
		t.Errorf("expected 3 endpoint IDs, got %d", len(ids))
	}

	// Check all IDs are present
	found := make(map[EndpointID]bool)
	for _, id := range ids {
		found[id] = true
	}
	if !found[0] || !found[1] || !found[2] {
		t.Error("missing endpoint IDs")
	}
}

func TestRouter_ReadAttribute(t *testing.T) {
	router := NewRouter()

	readCalled := false
	cluster := &routerTestCluster{
		id:         0x001D,
		endpointID: 0,
		readFunc: func(ctx context.Context, req ReadAttributeRequest, w *tlv.Writer) error {
			readCalled = true
			if req.Path.Endpoint != 0 {
				t.Errorf("expected endpoint 0, got %d", req.Path.Endpoint)
			}
			if req.Path.Cluster != 0x001D {
				t.Errorf("expected cluster 0x001D, got %d", req.Path.Cluster)
			}
			if req.Path.Attribute != 0x0000 {
				t.Errorf("expected attribute 0, got %d", req.Path.Attribute)
			}
			return nil
		},
	}

	router.RegisterCluster(0, cluster)

	req := ReadAttributeRequest{
		Path: ConcreteAttributePath{
			Endpoint:  0,
			Cluster:   0x001D,
			Attribute: 0x0000,
		},
	}

	err := router.ReadAttribute(context.Background(), req, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !readCalled {
		t.Error("expected read function to be called")
	}
}

func TestRouter_ReadAttribute_ClusterNotFound(t *testing.T) {
	router := NewRouter()

	req := ReadAttributeRequest{
		Path: ConcreteAttributePath{
			Endpoint:  0,
			Cluster:   0x001D,
			Attribute: 0x0000,
		},
	}

	err := router.ReadAttribute(context.Background(), req, nil)
	if err != ErrEndpointNotFound {
		t.Errorf("expected ErrEndpointNotFound, got %v", err)
	}
}

func TestRouter_WriteAttribute(t *testing.T) {
	router := NewRouter()

	writeCalled := false
	cluster := &routerTestCluster{
		id:         0x001F, // AccessControl
		endpointID: 0,
		writeFunc: func(ctx context.Context, req WriteAttributeRequest, r *tlv.Reader) error {
			writeCalled = true
			if req.Path.Endpoint != 0 {
				t.Errorf("expected endpoint 0, got %d", req.Path.Endpoint)
			}
			if req.Path.Cluster != 0x001F {
				t.Errorf("expected cluster 0x001F, got %d", req.Path.Cluster)
			}
			return nil
		},
	}

	router.RegisterCluster(0, cluster)

	req := WriteAttributeRequest{
		Path: ConcreteDataAttributePath{
			ConcreteAttributePath: ConcreteAttributePath{
				Endpoint:  0,
				Cluster:   0x001F,
				Attribute: 0x0000,
			},
		},
	}

	err := router.WriteAttribute(context.Background(), req, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !writeCalled {
		t.Error("expected write function to be called")
	}
}

func TestRouter_InvokeCommand(t *testing.T) {
	router := NewRouter()

	invokeCalled := false
	expectedResponse := []byte{0x15, 0x18}
	cluster := &routerTestCluster{
		id:         0x0030, // GeneralCommissioning
		endpointID: 0,
		invokeFunc: func(ctx context.Context, req InvokeRequest, r *tlv.Reader) ([]byte, error) {
			invokeCalled = true
			if req.Path.Endpoint != 0 {
				t.Errorf("expected endpoint 0, got %d", req.Path.Endpoint)
			}
			if req.Path.Cluster != 0x0030 {
				t.Errorf("expected cluster 0x0030, got %d", req.Path.Cluster)
			}
			if req.Path.Command != 0x00 {
				t.Errorf("expected command 0, got %d", req.Path.Command)
			}
			return expectedResponse, nil
		},
	}

	router.RegisterCluster(0, cluster)

	req := InvokeRequest{
		Path: ConcreteCommandPath{
			Endpoint: 0,
			Cluster:  0x0030,
			Command:  0x00,
		},
	}

	resp, err := router.InvokeCommand(context.Background(), req, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !invokeCalled {
		t.Error("expected invoke function to be called")
	}
	if string(resp) != string(expectedResponse) {
		t.Errorf("expected response %v, got %v", expectedResponse, resp)
	}
}

func TestRouterNode_GetEndpoint(t *testing.T) {
	router := NewRouter()
	router.RegisterCluster(0, &routerTestCluster{id: 0x001D, endpointID: 0})
	router.RegisterCluster(0, &routerTestCluster{id: 0x0028, endpointID: 0})
	router.RegisterCluster(1, &routerTestCluster{id: 0x0006, endpointID: 1})

	node := NewRouterNode(router)

	// Get existing endpoint
	ep := node.GetEndpoint(0)
	if ep == nil {
		t.Fatal("expected endpoint 0")
	}
	if ep.ID() != 0 {
		t.Errorf("expected endpoint ID 0, got %d", ep.ID())
	}

	clusters := ep.GetClusters()
	if len(clusters) != 2 {
		t.Errorf("expected 2 clusters on endpoint 0, got %d", len(clusters))
	}

	// Get non-existent endpoint
	ep = node.GetEndpoint(99)
	if ep != nil {
		t.Error("expected nil for non-existent endpoint")
	}
}

func TestRouterNode_GetEndpoints(t *testing.T) {
	router := NewRouter()
	router.RegisterCluster(0, &routerTestCluster{id: 0x001D, endpointID: 0})
	router.RegisterCluster(1, &routerTestCluster{id: 0x0006, endpointID: 1})

	node := NewRouterNode(router)

	endpoints := node.GetEndpoints()
	if len(endpoints) != 2 {
		t.Errorf("expected 2 endpoints, got %d", len(endpoints))
	}
}

func TestRouterEndpoint_GetCluster(t *testing.T) {
	router := NewRouter()
	descriptorCluster := &routerTestCluster{id: 0x001D, endpointID: 0}
	basicCluster := &routerTestCluster{id: 0x0028, endpointID: 0}
	router.RegisterCluster(0, descriptorCluster)
	router.RegisterCluster(0, basicCluster)

	node := NewRouterNode(router)
	ep := node.GetEndpoint(0)

	// Get existing cluster
	cluster := ep.GetCluster(0x001D)
	if cluster == nil {
		t.Fatal("expected descriptor cluster")
	}
	if cluster.ID() != 0x001D {
		t.Errorf("expected cluster ID 0x001D, got %d", cluster.ID())
	}

	// Get non-existent cluster
	cluster = ep.GetCluster(0x9999)
	if cluster != nil {
		t.Error("expected nil for non-existent cluster")
	}
}

func TestRouterEndpoint_Entry(t *testing.T) {
	router := NewRouter()
	router.RegisterCluster(5, &routerTestCluster{id: 0x0006, endpointID: 5})

	node := NewRouterNode(router)
	ep := node.GetEndpoint(5)

	entry := ep.Entry()
	if entry.ID != 5 {
		t.Errorf("expected entry ID 5, got %d", entry.ID)
	}
}

func TestRouterEndpoint_GetDeviceTypes(t *testing.T) {
	router := NewRouter()
	router.RegisterCluster(0, &routerTestCluster{id: 0x001D, endpointID: 0})

	node := NewRouterNode(router)
	ep := node.GetEndpoint(0)

	// Simple router doesn't track device types
	deviceTypes := ep.GetDeviceTypes()
	if deviceTypes != nil {
		t.Error("expected nil device types for simple router")
	}
}
