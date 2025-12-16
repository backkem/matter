package generalcommissioning

import (
	"bytes"
	"context"
	"testing"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/tlv"
)

// mockFailSafeManager implements FailSafeManager for testing.
type mockFailSafeManager struct {
	armed           bool
	armedFabric     fabric.FabricIndex
	expirySeconds   uint16
	completeError   error
	armError        error
	disarmError     error
	completedFabric fabric.FabricIndex
}

func newMockFailSafeManager() *mockFailSafeManager {
	return &mockFailSafeManager{}
}

func (m *mockFailSafeManager) IsArmed() bool                        { return m.armed }
func (m *mockFailSafeManager) ArmedFabricIndex() fabric.FabricIndex { return m.armedFabric }
func (m *mockFailSafeManager) Arm(fabricIndex fabric.FabricIndex, expirySeconds uint16) error {
	if m.armError != nil {
		return m.armError
	}
	m.armed = true
	m.armedFabric = fabricIndex
	m.expirySeconds = expirySeconds
	return nil
}
func (m *mockFailSafeManager) Disarm(fabricIndex fabric.FabricIndex) error {
	if m.disarmError != nil {
		return m.disarmError
	}
	m.armed = false
	m.armedFabric = 0
	return nil
}
func (m *mockFailSafeManager) ExtendArm(fabricIndex fabric.FabricIndex, expirySeconds uint16) error {
	if m.armError != nil {
		return m.armError
	}
	m.expirySeconds = expirySeconds
	return nil
}
func (m *mockFailSafeManager) Complete(fabricIndex fabric.FabricIndex) error {
	if m.completeError != nil {
		return m.completeError
	}
	m.completedFabric = fabricIndex
	m.armed = false
	m.armedFabric = 0
	return nil
}

// mockCommissioningWindowManager implements CommissioningWindowManager for testing.
type mockCommissioningWindowManager struct {
	windowOpen bool
}

func (m *mockCommissioningWindowManager) IsCommissioningWindowOpen() bool {
	return m.windowOpen
}

// createTestCluster creates a cluster with default test configuration.
func createTestCluster(fsm FailSafeManager) *Cluster {
	return New(Config{
		EndpointID: 0,
		BasicCommissioningInfo: BasicCommissioningInfo{
			FailSafeExpiryLengthSeconds:  60,
			MaxCumulativeFailsafeSeconds: 900,
		},
		LocationCapability:           RegulatoryIndoorOutdoor,
		SupportsConcurrentConnection: true,
		FailSafeManager:              fsm,
	})
}

func TestClusterID(t *testing.T) {
	c := createTestCluster(nil)
	if c.ID() != ClusterID {
		t.Errorf("expected cluster ID 0x%04X, got 0x%04X", ClusterID, c.ID())
	}
}

func TestClusterRevision(t *testing.T) {
	c := createTestCluster(nil)
	if c.ClusterRevision() != ClusterRevision {
		t.Errorf("expected revision %d, got %d", ClusterRevision, c.ClusterRevision())
	}
}

func TestReadBreadcrumb(t *testing.T) {
	c := createTestCluster(nil)
	ctx := context.Background()

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  0,
			Cluster:   ClusterID,
			Attribute: AttrBreadcrumb,
		},
	}

	err := c.ReadAttribute(ctx, req, w)
	if err != nil {
		t.Fatalf("failed to read Breadcrumb: %v", err)
	}

	// Parse the value
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read value: %v", err)
	}
	val, err := r.Uint()
	if err != nil {
		t.Fatalf("failed to get uint: %v", err)
	}
	if val != 0 {
		t.Errorf("expected breadcrumb 0, got %d", val)
	}
}

func TestWriteBreadcrumb(t *testing.T) {
	c := createTestCluster(nil)
	ctx := context.Background()

	// Write a value
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := w.PutUint(tlv.Anonymous(), 12345); err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))

	req := datamodel.WriteAttributeRequest{
		Path: datamodel.ConcreteDataAttributePath{
			ConcreteAttributePath: datamodel.ConcreteAttributePath{
				Endpoint:  0,
				Cluster:   ClusterID,
				Attribute: AttrBreadcrumb,
			},
		},
	}

	err := c.WriteAttribute(ctx, req, r)
	if err != nil {
		t.Fatalf("failed to write Breadcrumb: %v", err)
	}

	// Verify the value
	if c.GetBreadcrumb() != 12345 {
		t.Errorf("expected breadcrumb 12345, got %d", c.GetBreadcrumb())
	}
}

func TestReadBasicCommissioningInfo(t *testing.T) {
	c := createTestCluster(nil)
	ctx := context.Background()

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  0,
			Cluster:   ClusterID,
			Attribute: AttrBasicCommissioningInfo,
		},
	}

	err := c.ReadAttribute(ctx, req, w)
	if err != nil {
		t.Fatalf("failed to read BasicCommissioningInfo: %v", err)
	}

	// Parse the struct
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read struct: %v", err)
	}
	if r.Type() != tlv.ElementTypeStruct {
		t.Fatalf("expected structure, got %v", r.Type())
	}

	// Read FailSafeExpiryLengthSeconds (field 0)
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read field 0: %v", err)
	}
	expiry, err := r.Uint()
	if err != nil {
		t.Fatalf("failed to get uint: %v", err)
	}
	if expiry != 60 {
		t.Errorf("expected FailSafeExpiryLengthSeconds 60, got %d", expiry)
	}

	// Read MaxCumulativeFailsafeSeconds (field 1)
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read field 1: %v", err)
	}
	maxCumulative, err := r.Uint()
	if err != nil {
		t.Fatalf("failed to get uint: %v", err)
	}
	if maxCumulative != 900 {
		t.Errorf("expected MaxCumulativeFailsafeSeconds 900, got %d", maxCumulative)
	}
}

func TestReadRegulatoryConfig(t *testing.T) {
	c := createTestCluster(nil)
	ctx := context.Background()

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  0,
			Cluster:   ClusterID,
			Attribute: AttrRegulatoryConfig,
		},
	}

	err := c.ReadAttribute(ctx, req, w)
	if err != nil {
		t.Fatalf("failed to read RegulatoryConfig: %v", err)
	}

	// Parse the value
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read value: %v", err)
	}
	val, err := r.Uint()
	if err != nil {
		t.Fatalf("failed to get uint: %v", err)
	}
	if RegulatoryLocationType(val) != RegulatoryIndoorOutdoor {
		t.Errorf("expected RegulatoryIndoorOutdoor, got %d", val)
	}
}

func TestReadLocationCapability(t *testing.T) {
	c := createTestCluster(nil)
	ctx := context.Background()

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  0,
			Cluster:   ClusterID,
			Attribute: AttrLocationCapability,
		},
	}

	err := c.ReadAttribute(ctx, req, w)
	if err != nil {
		t.Fatalf("failed to read LocationCapability: %v", err)
	}

	// Parse the value
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read value: %v", err)
	}
	val, err := r.Uint()
	if err != nil {
		t.Fatalf("failed to get uint: %v", err)
	}
	if RegulatoryLocationType(val) != RegulatoryIndoorOutdoor {
		t.Errorf("expected RegulatoryIndoorOutdoor, got %d", val)
	}
}

func TestReadSupportsConcurrentConnection(t *testing.T) {
	c := createTestCluster(nil)
	ctx := context.Background()

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  0,
			Cluster:   ClusterID,
			Attribute: AttrSupportsConcurrentConnection,
		},
	}

	err := c.ReadAttribute(ctx, req, w)
	if err != nil {
		t.Fatalf("failed to read SupportsConcurrentConnection: %v", err)
	}

	// Parse the value
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read value: %v", err)
	}
	val, err := r.Bool()
	if err != nil {
		t.Fatalf("failed to get bool: %v", err)
	}
	if !val {
		t.Error("expected SupportsConcurrentConnection to be true")
	}
}

func TestAttributeList(t *testing.T) {
	c := createTestCluster(nil)
	attrList := c.AttributeList()

	// Check mandatory attributes are present
	mandatoryAttrs := []datamodel.AttributeID{
		AttrBreadcrumb,
		AttrBasicCommissioningInfo,
		AttrRegulatoryConfig,
		AttrLocationCapability,
		AttrSupportsConcurrentConnection,
	}

	for _, attrID := range mandatoryAttrs {
		found := false
		for _, entry := range attrList {
			if entry.ID == attrID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("mandatory attribute 0x%04X not in AttributeList", attrID)
		}
	}

	// Check global attributes are present
	globalAttrs := []datamodel.AttributeID{
		datamodel.GlobalAttrClusterRevision,
		datamodel.GlobalAttrFeatureMap,
		datamodel.GlobalAttrAttributeList,
	}

	for _, attrID := range globalAttrs {
		found := false
		for _, entry := range attrList {
			if entry.ID == attrID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("global attribute 0x%04X not in AttributeList", attrID)
		}
	}
}

func TestAcceptedCommandList(t *testing.T) {
	c := createTestCluster(nil)
	cmdList := c.AcceptedCommandList()

	expectedCmds := []datamodel.CommandID{
		CmdArmFailSafe,
		CmdSetRegulatoryConfig,
		CmdCommissioningComplete,
	}

	if len(cmdList) != len(expectedCmds) {
		t.Fatalf("expected %d commands, got %d", len(expectedCmds), len(cmdList))
	}

	for _, expectedID := range expectedCmds {
		found := false
		for _, cmd := range cmdList {
			if cmd.ID == expectedID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("command 0x%02X not in AcceptedCommandList", expectedID)
		}
	}
}

func TestGeneratedCommandList(t *testing.T) {
	c := createTestCluster(nil)
	cmdList := c.GeneratedCommandList()

	expectedCmds := []datamodel.CommandID{
		CmdArmFailSafeResponse,
		CmdSetRegulatoryConfigResponse,
		CmdCommissioningCompleteResp,
	}

	if len(cmdList) != len(expectedCmds) {
		t.Fatalf("expected %d commands, got %d", len(expectedCmds), len(cmdList))
	}

	for _, expectedID := range expectedCmds {
		found := false
		for _, cmdID := range cmdList {
			if cmdID == expectedID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("command 0x%02X not in GeneratedCommandList", expectedID)
		}
	}
}

func TestArmFailSafe_NewArm(t *testing.T) {
	fsm := newMockFailSafeManager()
	c := createTestCluster(fsm)
	ctx := context.Background()

	// Encode ArmFailSafe request
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		t.Fatal(err)
	}
	if err := w.PutUint(tlv.ContextTag(0), 60); err != nil { // ExpiryLengthSeconds
		t.Fatal(err)
	}
	if err := w.PutUint(tlv.ContextTag(1), 100); err != nil { // Breadcrumb
		t.Fatal(err)
	}
	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}

	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))

	req := datamodel.InvokeRequest{
		Path: datamodel.ConcreteCommandPath{
			Endpoint: 0,
			Cluster:  ClusterID,
			Command:  CmdArmFailSafe,
		},
	}

	respData, err := c.InvokeCommand(ctx, req, r)
	if err != nil {
		t.Fatalf("ArmFailSafe failed: %v", err)
	}

	// Verify response
	resp, err := decodeArmFailSafeResponseFromBytes(respData)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.ErrorCode != CommissioningOK {
		t.Errorf("expected OK, got %v", resp.ErrorCode)
	}

	// Verify fail-safe was armed
	if !fsm.armed {
		t.Error("fail-safe should be armed")
	}
	if fsm.expirySeconds != 60 {
		t.Errorf("expected expiry 60, got %d", fsm.expirySeconds)
	}

	// Verify breadcrumb was updated
	if c.GetBreadcrumb() != 100 {
		t.Errorf("expected breadcrumb 100, got %d", c.GetBreadcrumb())
	}
}

func TestArmFailSafe_Disarm(t *testing.T) {
	fsm := newMockFailSafeManager()
	fsm.armed = true
	fsm.armedFabric = 1
	c := createTestCluster(fsm)
	ctx := context.Background()

	// Encode ArmFailSafe request with expiry 0 to disarm
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		t.Fatal(err)
	}
	if err := w.PutUint(tlv.ContextTag(0), 0); err != nil { // ExpiryLengthSeconds = 0
		t.Fatal(err)
	}
	if err := w.PutUint(tlv.ContextTag(1), 0); err != nil { // Breadcrumb
		t.Fatal(err)
	}
	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}

	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))

	// Use matching fabric index
	req := datamodel.InvokeRequest{
		Path: datamodel.ConcreteCommandPath{
			Endpoint: 0,
			Cluster:  ClusterID,
			Command:  CmdArmFailSafe,
		},
		Subject: &datamodel.SubjectDescriptor{FabricIndex: 1},
	}

	respData, err := c.InvokeCommand(ctx, req, r)
	if err != nil {
		t.Fatalf("ArmFailSafe failed: %v", err)
	}

	// Verify response
	resp, err := decodeArmFailSafeResponseFromBytes(respData)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.ErrorCode != CommissioningOK {
		t.Errorf("expected OK, got %v", resp.ErrorCode)
	}

	// Verify fail-safe was disarmed
	if fsm.armed {
		t.Error("fail-safe should be disarmed")
	}
}

func TestArmFailSafe_BusyWithOtherAdmin(t *testing.T) {
	fsm := newMockFailSafeManager()
	fsm.armed = true
	fsm.armedFabric = 1 // Armed by fabric 1
	c := createTestCluster(fsm)
	ctx := context.Background()

	// Encode ArmFailSafe request
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		t.Fatal(err)
	}
	if err := w.PutUint(tlv.ContextTag(0), 60); err != nil {
		t.Fatal(err)
	}
	if err := w.PutUint(tlv.ContextTag(1), 100); err != nil {
		t.Fatal(err)
	}
	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}

	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))

	// Use different fabric index
	req := datamodel.InvokeRequest{
		Path: datamodel.ConcreteCommandPath{
			Endpoint: 0,
			Cluster:  ClusterID,
			Command:  CmdArmFailSafe,
		},
		Subject: &datamodel.SubjectDescriptor{FabricIndex: 2}, // Different fabric
	}

	respData, err := c.InvokeCommand(ctx, req, r)
	if err != nil {
		t.Fatalf("ArmFailSafe failed: %v", err)
	}

	// Verify response
	resp, err := decodeArmFailSafeResponseFromBytes(respData)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.ErrorCode != CommissioningBusyWithOtherAdmin {
		t.Errorf("expected BusyWithOtherAdmin, got %v", resp.ErrorCode)
	}
}

func TestSetRegulatoryConfig(t *testing.T) {
	c := createTestCluster(nil)
	ctx := context.Background()

	// Encode SetRegulatoryConfig request
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		t.Fatal(err)
	}
	if err := w.PutUint(tlv.ContextTag(0), uint64(RegulatoryIndoor)); err != nil {
		t.Fatal(err)
	}
	if err := w.PutString(tlv.ContextTag(1), "US"); err != nil {
		t.Fatal(err)
	}
	if err := w.PutUint(tlv.ContextTag(2), 200); err != nil { // Breadcrumb
		t.Fatal(err)
	}
	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}

	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))

	req := datamodel.InvokeRequest{
		Path: datamodel.ConcreteCommandPath{
			Endpoint: 0,
			Cluster:  ClusterID,
			Command:  CmdSetRegulatoryConfig,
		},
	}

	respData, err := c.InvokeCommand(ctx, req, r)
	if err != nil {
		t.Fatalf("SetRegulatoryConfig failed: %v", err)
	}

	// Verify response
	resp, err := decodeSetRegulatoryConfigResponseFromBytes(respData)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.ErrorCode != CommissioningOK {
		t.Errorf("expected OK, got %v", resp.ErrorCode)
	}

	// Verify regulatory config was updated
	if c.GetRegulatoryConfig() != RegulatoryIndoor {
		t.Errorf("expected RegulatoryIndoor, got %v", c.GetRegulatoryConfig())
	}

	// Verify breadcrumb was updated
	if c.GetBreadcrumb() != 200 {
		t.Errorf("expected breadcrumb 200, got %d", c.GetBreadcrumb())
	}
}

func TestCommissioningComplete_Success(t *testing.T) {
	fsm := newMockFailSafeManager()
	fsm.armed = true
	fsm.armedFabric = 1
	c := createTestCluster(fsm)
	c.SetBreadcrumb(500) // Set some breadcrumb
	ctx := context.Background()

	// CommissioningComplete has no request fields
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		t.Fatal(err)
	}
	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}

	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))

	req := datamodel.InvokeRequest{
		Path: datamodel.ConcreteCommandPath{
			Endpoint: 0,
			Cluster:  ClusterID,
			Command:  CmdCommissioningComplete,
		},
		Subject: &datamodel.SubjectDescriptor{FabricIndex: 1},
	}

	respData, err := c.InvokeCommand(ctx, req, r)
	if err != nil {
		t.Fatalf("CommissioningComplete failed: %v", err)
	}

	// Verify response
	resp, err := decodeCommissioningCompleteResponseFromBytes(respData)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.ErrorCode != CommissioningOK {
		t.Errorf("expected OK, got %v", resp.ErrorCode)
	}

	// Verify fail-safe was completed
	if fsm.completedFabric != 1 {
		t.Errorf("expected completed fabric 1, got %d", fsm.completedFabric)
	}

	// Verify breadcrumb was reset
	if c.GetBreadcrumb() != 0 {
		t.Errorf("expected breadcrumb 0, got %d", c.GetBreadcrumb())
	}
}

func TestCommissioningComplete_NoFailSafe(t *testing.T) {
	fsm := newMockFailSafeManager()
	fsm.armed = false // Not armed
	c := createTestCluster(fsm)
	ctx := context.Background()

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		t.Fatal(err)
	}
	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}

	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))

	req := datamodel.InvokeRequest{
		Path: datamodel.ConcreteCommandPath{
			Endpoint: 0,
			Cluster:  ClusterID,
			Command:  CmdCommissioningComplete,
		},
	}

	respData, err := c.InvokeCommand(ctx, req, r)
	if err != nil {
		t.Fatalf("CommissioningComplete failed: %v", err)
	}

	// Verify response
	resp, err := decodeCommissioningCompleteResponseFromBytes(respData)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.ErrorCode != CommissioningNoFailSafe {
		t.Errorf("expected NoFailSafe, got %v", resp.ErrorCode)
	}
}

// Helper functions for decoding responses

func decodeArmFailSafeResponseFromBytes(data []byte) (*ArmFailSafeResponse, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		return nil, err
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	var resp ArmFailSafeResponse
	for {
		if err := r.Next(); err != nil {
			break
		}
		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}
		switch tag.TagNumber() {
		case 0:
			val, err := r.Uint()
			if err != nil {
				return nil, err
			}
			resp.ErrorCode = CommissioningErrorCode(val)
		case 1:
			val, err := r.String()
			if err != nil {
				return nil, err
			}
			resp.DebugText = val
		}
	}
	return &resp, nil
}

func decodeSetRegulatoryConfigResponseFromBytes(data []byte) (*SetRegulatoryConfigResponse, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		return nil, err
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	var resp SetRegulatoryConfigResponse
	for {
		if err := r.Next(); err != nil {
			break
		}
		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}
		switch tag.TagNumber() {
		case 0:
			val, err := r.Uint()
			if err != nil {
				return nil, err
			}
			resp.ErrorCode = CommissioningErrorCode(val)
		case 1:
			val, err := r.String()
			if err != nil {
				return nil, err
			}
			resp.DebugText = val
		}
	}
	return &resp, nil
}

func decodeCommissioningCompleteResponseFromBytes(data []byte) (*CommissioningCompleteResponse, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		return nil, err
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	var resp CommissioningCompleteResponse
	for {
		if err := r.Next(); err != nil {
			break
		}
		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}
		switch tag.TagNumber() {
		case 0:
			val, err := r.Uint()
			if err != nil {
				return nil, err
			}
			resp.ErrorCode = CommissioningErrorCode(val)
		case 1:
			val, err := r.String()
			if err != nil {
				return nil, err
			}
			resp.DebugText = val
		}
	}
	return &resp, nil
}
