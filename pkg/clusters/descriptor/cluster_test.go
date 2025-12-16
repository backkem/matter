package descriptor

import (
	"bytes"
	"context"
	"testing"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/tlv"
)

// mockEndpoint implements datamodel.Endpoint for testing.
type mockEndpoint struct {
	id          datamodel.EndpointID
	entry       datamodel.EndpointEntry
	deviceTypes []datamodel.DeviceTypeEntry
	clusters    []datamodel.Cluster
}

func (e *mockEndpoint) ID() datamodel.EndpointID                    { return e.id }
func (e *mockEndpoint) Entry() datamodel.EndpointEntry              { return e.entry }
func (e *mockEndpoint) GetDeviceTypes() []datamodel.DeviceTypeEntry { return e.deviceTypes }
func (e *mockEndpoint) GetClusters() []datamodel.Cluster            { return e.clusters }
func (e *mockEndpoint) GetCluster(id datamodel.ClusterID) datamodel.Cluster {
	for _, c := range e.clusters {
		if c.ID() == id {
			return c
		}
	}
	return nil
}

// mockCluster implements datamodel.Cluster for testing.
type mockCluster struct {
	id datamodel.ClusterID
}

func (c *mockCluster) ID() datamodel.ClusterID           { return c.id }
func (c *mockCluster) EndpointID() datamodel.EndpointID  { return 0 }
func (c *mockCluster) DataVersion() datamodel.DataVersion { return 1 }
func (c *mockCluster) ClusterRevision() uint16           { return 1 }
func (c *mockCluster) FeatureMap() uint32                { return 0 }
func (c *mockCluster) AttributeList() []datamodel.AttributeEntry { return nil }
func (c *mockCluster) AcceptedCommandList() []datamodel.CommandEntry { return nil }
func (c *mockCluster) GeneratedCommandList() []datamodel.CommandID { return nil }
func (c *mockCluster) ReadAttribute(context.Context, datamodel.ReadAttributeRequest, *tlv.Writer) error {
	return nil
}
func (c *mockCluster) WriteAttribute(context.Context, datamodel.WriteAttributeRequest, *tlv.Reader) error {
	return nil
}
func (c *mockCluster) InvokeCommand(context.Context, datamodel.InvokeRequest, *tlv.Reader) ([]byte, error) {
	return nil, nil
}

// mockNode implements datamodel.Node for testing.
type mockNode struct {
	endpoints []datamodel.Endpoint
}

func (n *mockNode) GetEndpoint(id datamodel.EndpointID) datamodel.Endpoint {
	for _, ep := range n.endpoints {
		if ep.ID() == id {
			return ep
		}
	}
	return nil
}

func (n *mockNode) GetEndpoints() []datamodel.Endpoint {
	return n.endpoints
}

func TestCluster_New(t *testing.T) {
	node := &mockNode{}
	cfg := Config{
		EndpointID: 0,
		Node:       node,
	}

	cluster := New(cfg)

	if cluster.ID() != ClusterID {
		t.Errorf("ID() = 0x%04X, want 0x%04X", cluster.ID(), ClusterID)
	}
	if cluster.ClusterRevision() != ClusterRevision {
		t.Errorf("ClusterRevision() = %d, want %d", cluster.ClusterRevision(), ClusterRevision)
	}
	if cluster.FeatureMap() != 0 {
		t.Errorf("FeatureMap() = 0x%08X, want 0", cluster.FeatureMap())
	}
}

func TestCluster_NewWithTagList(t *testing.T) {
	node := &mockNode{}
	cfg := Config{
		EndpointID: 0,
		Node:       node,
		SemanticTags: []SemanticTag{
			{NamespaceID: 7, Tag: 0},
		},
	}

	cluster := New(cfg)

	if cluster.FeatureMap()&uint32(FeatureTagList) == 0 {
		t.Error("FeatureMap should have TAGLIST feature set")
	}
}

func TestCluster_AttributeList(t *testing.T) {
	node := &mockNode{}
	cfg := Config{
		EndpointID: 0,
		Node:       node,
	}

	cluster := New(cfg)
	attrs := cluster.AttributeList()

	// Check mandatory attributes are present
	mandatoryIDs := []datamodel.AttributeID{
		AttrDeviceTypeList,
		AttrServerList,
		AttrClientList,
		AttrPartsList,
	}

	for _, id := range mandatoryIDs {
		found := false
		for _, attr := range attrs {
			if attr.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AttributeList missing mandatory attribute 0x%04X", id)
		}
	}

	// Check global attributes are present
	globalIDs := []datamodel.AttributeID{
		datamodel.GlobalAttrClusterRevision,
		datamodel.GlobalAttrFeatureMap,
		datamodel.GlobalAttrAttributeList,
	}

	for _, id := range globalIDs {
		found := false
		for _, attr := range attrs {
			if attr.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AttributeList missing global attribute 0x%04X", id)
		}
	}
}

func TestCluster_ReadDeviceTypeList(t *testing.T) {
	endpoint := &mockEndpoint{
		id: 0,
		deviceTypes: []datamodel.DeviceTypeEntry{
			{DeviceTypeID: 17, Revision: 1},  // Root Node
			{DeviceTypeID: 22, Revision: 3},  // Root Node
		},
	}
	node := &mockNode{endpoints: []datamodel.Endpoint{endpoint}}

	cluster := New(Config{EndpointID: 0, Node: node})

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  0,
			Cluster:   ClusterID,
			Attribute: AttrDeviceTypeList,
		},
	}

	err := cluster.ReadAttribute(context.Background(), req, w)
	if err != nil {
		t.Fatalf("ReadAttribute() error = %v", err)
	}

	// Verify TLV is valid by parsing it
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("TLV read error: %v", err)
	}
	if r.Type() != tlv.ElementTypeArray {
		t.Errorf("Expected array, got %v", r.Type())
	}
}

func TestCluster_ReadServerList(t *testing.T) {
	endpoint := &mockEndpoint{
		id: 0,
		clusters: []datamodel.Cluster{
			&mockCluster{id: 0x001D}, // Descriptor
			&mockCluster{id: 0x0028}, // Basic Information
			&mockCluster{id: 0x0030}, // General Commissioning
		},
	}
	node := &mockNode{endpoints: []datamodel.Endpoint{endpoint}}

	cluster := New(Config{EndpointID: 0, Node: node})

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  0,
			Cluster:   ClusterID,
			Attribute: AttrServerList,
		},
	}

	err := cluster.ReadAttribute(context.Background(), req, w)
	if err != nil {
		t.Fatalf("ReadAttribute() error = %v", err)
	}

	// Verify TLV is valid by parsing it
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("TLV read error: %v", err)
	}
	if r.Type() != tlv.ElementTypeArray {
		t.Errorf("Expected array, got %v", r.Type())
	}
}

func TestCluster_ReadClientList(t *testing.T) {
	node := &mockNode{endpoints: []datamodel.Endpoint{
		&mockEndpoint{id: 0},
	}}

	cluster := New(Config{EndpointID: 0, Node: node})

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  0,
			Cluster:   ClusterID,
			Attribute: AttrClientList,
		},
	}

	err := cluster.ReadAttribute(context.Background(), req, w)
	if err != nil {
		t.Fatalf("ReadAttribute() error = %v", err)
	}

	// Should be empty array for server-only implementation
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("TLV read error: %v", err)
	}
	if r.Type() != tlv.ElementTypeArray {
		t.Errorf("Expected array, got %v", r.Type())
	}
}

func TestCluster_ReadPartsList_RootEndpoint(t *testing.T) {
	// Root endpoint should list all non-root endpoints
	ep0 := &mockEndpoint{id: 0}
	ep1 := &mockEndpoint{id: 1}
	ep2 := &mockEndpoint{id: 2}
	ep3 := &mockEndpoint{id: 3}

	node := &mockNode{endpoints: []datamodel.Endpoint{ep0, ep1, ep2, ep3}}

	cluster := New(Config{EndpointID: 0, Node: node})

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  0,
			Cluster:   ClusterID,
			Attribute: AttrPartsList,
		},
	}

	err := cluster.ReadAttribute(context.Background(), req, w)
	if err != nil {
		t.Fatalf("ReadAttribute() error = %v", err)
	}

	// Parse and verify - should contain endpoints 1, 2, 3
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("TLV read error: %v", err)
	}
	if r.Type() != tlv.ElementTypeArray {
		t.Errorf("Expected array, got %v", r.Type())
	}

	if err := r.EnterContainer(); err != nil {
		t.Fatalf("EnterContainer error: %v", err)
	}

	var parts []uint64
	for {
		if err := r.Next(); err != nil {
			t.Fatalf("Next error: %v", err)
		}
		if r.Type() == tlv.ElementTypeEnd {
			break
		}
		v, err := r.Uint()
		if err != nil {
			t.Fatalf("Uint error: %v", err)
		}
		parts = append(parts, v)
	}

	// Should have 3 parts (endpoints 1, 2, 3)
	if len(parts) != 3 {
		t.Errorf("PartsList length = %d, want 3", len(parts))
	}
}

func TestCluster_ReadPartsList_TreeComposition(t *testing.T) {
	// Test tree composition pattern - only direct children
	parentID := datamodel.EndpointID(1)

	ep0 := &mockEndpoint{id: 0}
	ep1 := &mockEndpoint{
		id: 1,
		entry: datamodel.EndpointEntry{
			ID:                 1,
			CompositionPattern: datamodel.CompositionTree,
		},
	}
	ep2 := &mockEndpoint{
		id: 2,
		entry: datamodel.EndpointEntry{
			ID:       2,
			ParentID: &parentID,
		},
	}
	ep3 := &mockEndpoint{
		id: 3,
		entry: datamodel.EndpointEntry{
			ID:       3,
			ParentID: &parentID,
		},
	}

	node := &mockNode{endpoints: []datamodel.Endpoint{ep0, ep1, ep2, ep3}}

	cluster := New(Config{EndpointID: 1, Node: node})

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  1,
			Cluster:   ClusterID,
			Attribute: AttrPartsList,
		},
	}

	err := cluster.ReadAttribute(context.Background(), req, w)
	if err != nil {
		t.Fatalf("ReadAttribute() error = %v", err)
	}

	// Parse and verify - should contain endpoints 2, 3 (direct children)
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("TLV read error: %v", err)
	}

	if err := r.EnterContainer(); err != nil {
		t.Fatalf("EnterContainer error: %v", err)
	}

	var parts []uint64
	for {
		if err := r.Next(); err != nil {
			t.Fatalf("Next error: %v", err)
		}
		if r.Type() == tlv.ElementTypeEnd {
			break
		}
		v, err := r.Uint()
		if err != nil {
			t.Fatalf("Uint error: %v", err)
		}
		parts = append(parts, v)
	}

	if len(parts) != 2 {
		t.Errorf("PartsList length = %d, want 2", len(parts))
	}
}

func TestCluster_ReadTagList(t *testing.T) {
	node := &mockNode{endpoints: []datamodel.Endpoint{&mockEndpoint{id: 0}}}

	mfgCode := uint16(0x1234)
	label := "Button 1"

	cluster := New(Config{
		EndpointID: 0,
		Node:       node,
		SemanticTags: []SemanticTag{
			{MfgCode: nil, NamespaceID: 7, Tag: 0},
			{MfgCode: &mfgCode, NamespaceID: 8, Tag: 3, Label: &label},
		},
	})

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  0,
			Cluster:   ClusterID,
			Attribute: AttrTagList,
		},
	}

	err := cluster.ReadAttribute(context.Background(), req, w)
	if err != nil {
		t.Fatalf("ReadAttribute() error = %v", err)
	}

	// Verify TLV is valid
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("TLV read error: %v", err)
	}
	if r.Type() != tlv.ElementTypeArray {
		t.Errorf("Expected array, got %v", r.Type())
	}
}

func TestCluster_ReadTagList_NotSupported(t *testing.T) {
	node := &mockNode{endpoints: []datamodel.Endpoint{&mockEndpoint{id: 0}}}

	// No semantic tags configured
	cluster := New(Config{EndpointID: 0, Node: node})

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  0,
			Cluster:   ClusterID,
			Attribute: AttrTagList,
		},
	}

	err := cluster.ReadAttribute(context.Background(), req, w)
	if err != datamodel.ErrUnsupportedAttribute {
		t.Errorf("ReadAttribute() error = %v, want ErrUnsupportedAttribute", err)
	}
}

func TestCluster_ReadEndpointUniqueID(t *testing.T) {
	node := &mockNode{endpoints: []datamodel.Endpoint{&mockEndpoint{id: 0}}}
	uniqueID := "EP0-UNIQUE-123"

	cluster := New(Config{
		EndpointID:       0,
		Node:             node,
		EndpointUniqueID: &uniqueID,
	})

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  0,
			Cluster:   ClusterID,
			Attribute: AttrEndpointUniqueID,
		},
	}

	err := cluster.ReadAttribute(context.Background(), req, w)
	if err != nil {
		t.Fatalf("ReadAttribute() error = %v", err)
	}

	// Verify TLV is valid string
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("TLV read error: %v", err)
	}
	s, err := r.String()
	if err != nil {
		t.Fatalf("String() error: %v", err)
	}
	if s != uniqueID {
		t.Errorf("EndpointUniqueID = %q, want %q", s, uniqueID)
	}
}

func TestCluster_ReadClusterRevision(t *testing.T) {
	node := &mockNode{endpoints: []datamodel.Endpoint{&mockEndpoint{id: 0}}}
	cluster := New(Config{EndpointID: 0, Node: node})

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  0,
			Cluster:   ClusterID,
			Attribute: datamodel.GlobalAttrClusterRevision,
		},
	}

	err := cluster.ReadAttribute(context.Background(), req, w)
	if err != nil {
		t.Fatalf("ReadAttribute() error = %v", err)
	}

	// Verify value is ClusterRevision (3)
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("TLV read error: %v", err)
	}
	v, err := r.Uint()
	if err != nil {
		t.Fatalf("Uint() error: %v", err)
	}
	if v != uint64(ClusterRevision) {
		t.Errorf("ClusterRevision = %d, want %d", v, ClusterRevision)
	}
}

func TestCluster_WriteAttribute_NotSupported(t *testing.T) {
	node := &mockNode{endpoints: []datamodel.Endpoint{&mockEndpoint{id: 0}}}
	cluster := New(Config{EndpointID: 0, Node: node})

	req := datamodel.WriteAttributeRequest{
		Path: datamodel.ConcreteDataAttributePath{
			ConcreteAttributePath: datamodel.ConcreteAttributePath{
				Endpoint:  0,
				Cluster:   ClusterID,
				Attribute: AttrDeviceTypeList,
			},
		},
	}

	err := cluster.WriteAttribute(context.Background(), req, nil)
	if err != datamodel.ErrUnsupportedWrite {
		t.Errorf("WriteAttribute() error = %v, want ErrUnsupportedWrite", err)
	}
}

func TestCluster_InvokeCommand_NotSupported(t *testing.T) {
	node := &mockNode{endpoints: []datamodel.Endpoint{&mockEndpoint{id: 0}}}
	cluster := New(Config{EndpointID: 0, Node: node})

	req := datamodel.InvokeRequest{
		Path: datamodel.ConcreteCommandPath{
			Endpoint: 0,
			Cluster:  ClusterID,
			Command:  0x00,
		},
	}

	_, err := cluster.InvokeCommand(context.Background(), req, nil)
	if err != datamodel.ErrUnsupportedCommand {
		t.Errorf("InvokeCommand() error = %v, want ErrUnsupportedCommand", err)
	}
}

func TestCluster_AcceptedCommandList_Empty(t *testing.T) {
	node := &mockNode{}
	cluster := New(Config{EndpointID: 0, Node: node})

	cmds := cluster.AcceptedCommandList()
	if len(cmds) != 0 {
		t.Errorf("AcceptedCommandList() len = %d, want 0", len(cmds))
	}
}

func TestCluster_GeneratedCommandList_Empty(t *testing.T) {
	node := &mockNode{}
	cluster := New(Config{EndpointID: 0, Node: node})

	cmds := cluster.GeneratedCommandList()
	if len(cmds) != 0 {
		t.Errorf("GeneratedCommandList() len = %d, want 0", len(cmds))
	}
}
