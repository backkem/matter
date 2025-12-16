package onoff

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/tlv"
)

// errNotFound is used by mock storage when key doesn't exist.
var errNotFound = errors.New("not found")

// mockStorage implements Storage for testing.
type mockStorage struct {
	data map[string][]byte
}

func newMockStorage() *mockStorage {
	return &mockStorage{data: make(map[string][]byte)}
}

func (s *mockStorage) Load(key string) ([]byte, error) {
	if v, ok := s.data[key]; ok {
		return v, nil
	}
	return nil, errNotFound
}

func (s *mockStorage) Store(key string, value []byte) error {
	s.data[key] = value
	return nil
}

// createTestCluster creates a cluster with default test configuration.
func createTestCluster(features Feature) *Cluster {
	return New(Config{
		EndpointID:   1,
		FeatureMap:   features,
		InitialOnOff: false,
	})
}

func TestClusterID(t *testing.T) {
	c := createTestCluster(0)
	if c.ID() != ClusterID {
		t.Errorf("expected cluster ID 0x%04X, got 0x%04X", ClusterID, c.ID())
	}
}

func TestClusterRevision(t *testing.T) {
	c := createTestCluster(0)
	if c.ClusterRevision() != ClusterRevision {
		t.Errorf("expected revision %d, got %d", ClusterRevision, c.ClusterRevision())
	}
}

func TestReadOnOff_InitialState(t *testing.T) {
	c := createTestCluster(0)

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  1,
			Cluster:   ClusterID,
			Attribute: AttrOnOff,
		},
	}

	if err := c.ReadAttribute(context.Background(), req, w); err != nil {
		t.Fatalf("ReadAttribute failed: %v", err)
	}

	// Decode and verify
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read value: %v", err)
	}

	val, err := r.Bool()
	if err != nil {
		t.Fatalf("failed to decode bool: %v", err)
	}

	if val != false {
		t.Errorf("expected OnOff=false, got %v", val)
	}
}

func TestOnCommand(t *testing.T) {
	c := createTestCluster(0)

	// Execute On command
	cmdData := encodeEmptyCommand()
	r := tlv.NewReader(bytes.NewReader(cmdData))

	req := datamodel.InvokeRequest{
		Path: datamodel.ConcreteCommandPath{
			Endpoint: 1,
			Cluster:  ClusterID,
			Command:  CmdOn,
		},
	}

	_, err := c.InvokeCommand(context.Background(), req, r)
	if err != nil {
		t.Fatalf("On command failed: %v", err)
	}

	// Verify state changed
	if !c.GetOnOff() {
		t.Error("expected OnOff=true after On command")
	}
}

func TestOffCommand(t *testing.T) {
	c := createTestCluster(0)
	c.SetOnOff(true) // Start with on

	// Execute Off command
	cmdData := encodeEmptyCommand()
	r := tlv.NewReader(bytes.NewReader(cmdData))

	req := datamodel.InvokeRequest{
		Path: datamodel.ConcreteCommandPath{
			Endpoint: 1,
			Cluster:  ClusterID,
			Command:  CmdOff,
		},
	}

	_, err := c.InvokeCommand(context.Background(), req, r)
	if err != nil {
		t.Fatalf("Off command failed: %v", err)
	}

	// Verify state changed
	if c.GetOnOff() {
		t.Error("expected OnOff=false after Off command")
	}
}

func TestToggleCommand(t *testing.T) {
	c := createTestCluster(0)

	// Start off, toggle to on
	cmdData := encodeEmptyCommand()

	req := datamodel.InvokeRequest{
		Path: datamodel.ConcreteCommandPath{
			Endpoint: 1,
			Cluster:  ClusterID,
			Command:  CmdToggle,
		},
	}

	r := tlv.NewReader(bytes.NewReader(cmdData))
	_, err := c.InvokeCommand(context.Background(), req, r)
	if err != nil {
		t.Fatalf("Toggle command failed: %v", err)
	}

	if !c.GetOnOff() {
		t.Error("expected OnOff=true after first Toggle")
	}

	// Toggle again - back to off
	r = tlv.NewReader(bytes.NewReader(cmdData))
	_, err = c.InvokeCommand(context.Background(), req, r)
	if err != nil {
		t.Fatalf("Toggle command failed: %v", err)
	}

	if c.GetOnOff() {
		t.Error("expected OnOff=false after second Toggle")
	}
}

func TestStateChangeCallback(t *testing.T) {
	var callbackCalled bool
	var callbackEndpoint datamodel.EndpointID
	var callbackState bool

	c := New(Config{
		EndpointID:   1,
		FeatureMap:   0,
		InitialOnOff: false,
		OnStateChange: func(endpoint datamodel.EndpointID, newState bool) {
			callbackCalled = true
			callbackEndpoint = endpoint
			callbackState = newState
		},
	})

	// Turn on
	c.SetOnOff(true)

	if !callbackCalled {
		t.Error("expected callback to be called")
	}
	if callbackEndpoint != 1 {
		t.Errorf("expected endpoint 1, got %d", callbackEndpoint)
	}
	if !callbackState {
		t.Error("expected callback state=true")
	}

	// Reset and turn off
	callbackCalled = false
	c.SetOnOff(false)

	if !callbackCalled {
		t.Error("expected callback to be called on off")
	}
	if callbackState {
		t.Error("expected callback state=false")
	}
}

func TestNoCallbackOnSameState(t *testing.T) {
	callCount := 0

	c := New(Config{
		EndpointID:   1,
		FeatureMap:   0,
		InitialOnOff: false,
		OnStateChange: func(endpoint datamodel.EndpointID, newState bool) {
			callCount++
		},
	})

	// Set to same state - should not trigger callback
	c.SetOnOff(false)

	if callCount != 0 {
		t.Errorf("expected no callback when state unchanged, got %d calls", callCount)
	}
}

func TestAttributeList_NoLighting(t *testing.T) {
	c := createTestCluster(0)
	attrs := c.AttributeList()

	// Should have OnOff + global attributes
	found := false
	for _, attr := range attrs {
		if attr.ID == AttrOnOff {
			found = true
		}
		// Should NOT have lighting attributes
		if attr.ID == AttrGlobalSceneControl || attr.ID == AttrOnTime ||
			attr.ID == AttrOffWaitTime || attr.ID == AttrStartUpOnOff {
			t.Errorf("unexpected lighting attribute 0x%04X without LT feature", attr.ID)
		}
	}

	if !found {
		t.Error("OnOff attribute not found in attribute list")
	}
}

func TestAttributeList_WithLighting(t *testing.T) {
	c := createTestCluster(FeatureLighting)
	attrs := c.AttributeList()

	required := []datamodel.AttributeID{
		AttrOnOff,
		AttrGlobalSceneControl,
		AttrOnTime,
		AttrOffWaitTime,
		AttrStartUpOnOff,
	}

	for _, reqID := range required {
		found := false
		for _, attr := range attrs {
			if attr.ID == reqID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("attribute 0x%04X not found in attribute list", reqID)
		}
	}
}

func TestAcceptedCommandList_NoLighting(t *testing.T) {
	c := createTestCluster(0)
	cmds := c.AcceptedCommandList()

	// Should have Off, On, Toggle
	expected := map[datamodel.CommandID]bool{
		CmdOff:    false,
		CmdOn:     false,
		CmdToggle: false,
	}

	for _, cmd := range cmds {
		if _, ok := expected[cmd.ID]; ok {
			expected[cmd.ID] = true
		}
		// Should NOT have lighting commands
		if cmd.ID == CmdOffWithEffect || cmd.ID == CmdOnWithRecallGlobalScene || cmd.ID == CmdOnWithTimedOff {
			t.Errorf("unexpected lighting command 0x%02X without LT feature", cmd.ID)
		}
	}

	for cmdID, found := range expected {
		if !found {
			t.Errorf("command 0x%02X not found in accepted command list", cmdID)
		}
	}
}

func TestAcceptedCommandList_WithLighting(t *testing.T) {
	c := createTestCluster(FeatureLighting)
	cmds := c.AcceptedCommandList()

	expected := map[datamodel.CommandID]bool{
		CmdOff:                     false,
		CmdOn:                      false,
		CmdToggle:                  false,
		CmdOffWithEffect:           false,
		CmdOnWithRecallGlobalScene: false,
		CmdOnWithTimedOff:          false,
	}

	for _, cmd := range cmds {
		if _, ok := expected[cmd.ID]; ok {
			expected[cmd.ID] = true
		}
	}

	for cmdID, found := range expected {
		if !found {
			t.Errorf("command 0x%02X not found in accepted command list", cmdID)
		}
	}
}

func TestReadGlobalSceneControl(t *testing.T) {
	c := createTestCluster(FeatureLighting)

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  1,
			Cluster:   ClusterID,
			Attribute: AttrGlobalSceneControl,
		},
	}

	if err := c.ReadAttribute(context.Background(), req, w); err != nil {
		t.Fatalf("ReadAttribute failed: %v", err)
	}

	// Decode and verify
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read value: %v", err)
	}

	val, err := r.Bool()
	if err != nil {
		t.Fatalf("failed to decode bool: %v", err)
	}

	// Default should be true
	if val != true {
		t.Errorf("expected GlobalSceneControl=true, got %v", val)
	}
}

func TestReadOnTime(t *testing.T) {
	c := createTestCluster(FeatureLighting)

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  1,
			Cluster:   ClusterID,
			Attribute: AttrOnTime,
		},
	}

	if err := c.ReadAttribute(context.Background(), req, w); err != nil {
		t.Fatalf("ReadAttribute failed: %v", err)
	}

	// Decode and verify
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read value: %v", err)
	}

	val, err := r.Uint()
	if err != nil {
		t.Fatalf("failed to decode uint: %v", err)
	}

	if val != 0 {
		t.Errorf("expected OnTime=0, got %d", val)
	}
}

func TestWriteOnTime(t *testing.T) {
	c := createTestCluster(FeatureLighting)

	// Write new value
	writeData := encodeUint16(500)
	r := tlv.NewReader(bytes.NewReader(writeData))

	req := datamodel.WriteAttributeRequest{
		Path: datamodel.ConcreteDataAttributePath{
			ConcreteAttributePath: datamodel.ConcreteAttributePath{
				Endpoint:  1,
				Cluster:   ClusterID,
				Attribute: AttrOnTime,
			},
		},
	}

	if err := c.WriteAttribute(context.Background(), req, r); err != nil {
		t.Fatalf("WriteAttribute failed: %v", err)
	}

	// Read back
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	readReq := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  1,
			Cluster:   ClusterID,
			Attribute: AttrOnTime,
		},
	}

	if err := c.ReadAttribute(context.Background(), readReq, w); err != nil {
		t.Fatalf("ReadAttribute failed: %v", err)
	}

	rr := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := rr.Next(); err != nil {
		t.Fatalf("failed to read value: %v", err)
	}

	val, _ := rr.Uint()
	if val != 500 {
		t.Errorf("expected OnTime=500, got %d", val)
	}
}

func TestWriteStartUpOnOff(t *testing.T) {
	storage := newMockStorage()
	c := New(Config{
		EndpointID:   1,
		FeatureMap:   FeatureLighting,
		InitialOnOff: false,
		Storage:      storage,
	})

	// Write StartUpOnOff to On
	writeData := encodeUint8(uint8(StartUpOnOffOn))
	r := tlv.NewReader(bytes.NewReader(writeData))

	req := datamodel.WriteAttributeRequest{
		Path: datamodel.ConcreteDataAttributePath{
			ConcreteAttributePath: datamodel.ConcreteAttributePath{
				Endpoint:  1,
				Cluster:   ClusterID,
				Attribute: AttrStartUpOnOff,
			},
		},
	}

	if err := c.WriteAttribute(context.Background(), req, r); err != nil {
		t.Fatalf("WriteAttribute failed: %v", err)
	}

	// Verify persisted
	if data, err := storage.Load("startupOnOff"); err != nil {
		t.Errorf("StartUpOnOff not persisted: %v", err)
	} else if data[0] != byte(StartUpOnOffOn) {
		t.Errorf("expected StartUpOnOff=%d, got %d", StartUpOnOffOn, data[0])
	}
}

func TestWriteStartUpOnOff_Null(t *testing.T) {
	c := createTestCluster(FeatureLighting)

	// First set to a value
	writeData := encodeUint8(uint8(StartUpOnOffOn))
	r := tlv.NewReader(bytes.NewReader(writeData))

	req := datamodel.WriteAttributeRequest{
		Path: datamodel.ConcreteDataAttributePath{
			ConcreteAttributePath: datamodel.ConcreteAttributePath{
				Endpoint:  1,
				Cluster:   ClusterID,
				Attribute: AttrStartUpOnOff,
			},
		},
	}

	_ = c.WriteAttribute(context.Background(), req, r)

	// Now write null
	nullData := encodeNull()
	r = tlv.NewReader(bytes.NewReader(nullData))

	if err := c.WriteAttribute(context.Background(), req, r); err != nil {
		t.Fatalf("WriteAttribute null failed: %v", err)
	}

	// Read back - should be null
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	readReq := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  1,
			Cluster:   ClusterID,
			Attribute: AttrStartUpOnOff,
		},
	}

	if err := c.ReadAttribute(context.Background(), readReq, w); err != nil {
		t.Fatalf("ReadAttribute failed: %v", err)
	}

	rr := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := rr.Next(); err != nil {
		t.Fatalf("failed to read value: %v", err)
	}

	if rr.Type() != tlv.ElementTypeNull {
		t.Error("expected null value for StartUpOnOff")
	}
}

func TestOnCommand_OffOnlyFeature(t *testing.T) {
	c := createTestCluster(FeatureOffOnly)

	// On command should fail with OffOnly feature
	cmdData := encodeEmptyCommand()
	r := tlv.NewReader(bytes.NewReader(cmdData))

	req := datamodel.InvokeRequest{
		Path: datamodel.ConcreteCommandPath{
			Endpoint: 1,
			Cluster:  ClusterID,
			Command:  CmdOn,
		},
	}

	_, err := c.InvokeCommand(context.Background(), req, r)
	if err != datamodel.ErrUnsupportedCommand {
		t.Errorf("expected ErrUnsupportedCommand for On with OffOnly feature, got %v", err)
	}
}

func TestOffWithEffect_NotSupported(t *testing.T) {
	c := createTestCluster(0) // No lighting feature

	cmdData := encodeOffWithEffectCommand(0, 0)
	r := tlv.NewReader(bytes.NewReader(cmdData))

	req := datamodel.InvokeRequest{
		Path: datamodel.ConcreteCommandPath{
			Endpoint: 1,
			Cluster:  ClusterID,
			Command:  CmdOffWithEffect,
		},
	}

	_, err := c.InvokeCommand(context.Background(), req, r)
	if err != datamodel.ErrUnsupportedCommand {
		t.Errorf("expected ErrUnsupportedCommand, got %v", err)
	}
}

func TestOffWithEffect_Supported(t *testing.T) {
	c := createTestCluster(FeatureLighting)
	c.SetOnOff(true)

	cmdData := encodeOffWithEffectCommand(0, 0)
	r := tlv.NewReader(bytes.NewReader(cmdData))

	req := datamodel.InvokeRequest{
		Path: datamodel.ConcreteCommandPath{
			Endpoint: 1,
			Cluster:  ClusterID,
			Command:  CmdOffWithEffect,
		},
	}

	_, err := c.InvokeCommand(context.Background(), req, r)
	if err != nil {
		t.Fatalf("OffWithEffect failed: %v", err)
	}

	// Should be off
	if c.GetOnOff() {
		t.Error("expected OnOff=false after OffWithEffect")
	}

	// GlobalSceneControl should be false
	c.mu.RLock()
	gsc := c.globalSceneControl
	c.mu.RUnlock()
	if gsc {
		t.Error("expected GlobalSceneControl=false after OffWithEffect")
	}
}

func TestOnWithRecallGlobalScene(t *testing.T) {
	c := createTestCluster(FeatureLighting)
	c.mu.Lock()
	c.globalSceneControl = false
	c.mu.Unlock()

	cmdData := encodeEmptyCommand()
	r := tlv.NewReader(bytes.NewReader(cmdData))

	req := datamodel.InvokeRequest{
		Path: datamodel.ConcreteCommandPath{
			Endpoint: 1,
			Cluster:  ClusterID,
			Command:  CmdOnWithRecallGlobalScene,
		},
	}

	_, err := c.InvokeCommand(context.Background(), req, r)
	if err != nil {
		t.Fatalf("OnWithRecallGlobalScene failed: %v", err)
	}

	// Should be on
	if !c.GetOnOff() {
		t.Error("expected OnOff=true after OnWithRecallGlobalScene")
	}

	// GlobalSceneControl should be true
	c.mu.RLock()
	gsc := c.globalSceneControl
	c.mu.RUnlock()
	if !gsc {
		t.Error("expected GlobalSceneControl=true after OnWithRecallGlobalScene")
	}
}

func TestOnWithTimedOff(t *testing.T) {
	c := createTestCluster(FeatureLighting)

	// OnOffControl=0, OnTime=100, OffWaitTime=50
	cmdData := encodeOnWithTimedOffCommand(0, 100, 50)
	r := tlv.NewReader(bytes.NewReader(cmdData))

	req := datamodel.InvokeRequest{
		Path: datamodel.ConcreteCommandPath{
			Endpoint: 1,
			Cluster:  ClusterID,
			Command:  CmdOnWithTimedOff,
		},
	}

	_, err := c.InvokeCommand(context.Background(), req, r)
	if err != nil {
		t.Fatalf("OnWithTimedOff failed: %v", err)
	}

	// Should be on
	if !c.GetOnOff() {
		t.Error("expected OnOff=true after OnWithTimedOff")
	}

	// Check timing attributes
	c.mu.RLock()
	onTime := c.onTime
	offWaitTime := c.offWaitTime
	c.mu.RUnlock()

	if onTime != 100 {
		t.Errorf("expected OnTime=100, got %d", onTime)
	}
	if offWaitTime != 50 {
		t.Errorf("expected OffWaitTime=50, got %d", offWaitTime)
	}
}

func TestStatePersistence(t *testing.T) {
	storage := newMockStorage()

	// Create first cluster, turn on, should persist
	c1 := New(Config{
		EndpointID:   1,
		FeatureMap:   0,
		InitialOnOff: false,
		Storage:      storage,
	})

	c1.SetOnOff(true)

	// Create second cluster with same storage - should load persisted state
	c2 := New(Config{
		EndpointID:   1,
		FeatureMap:   0,
		InitialOnOff: false,
		Storage:      storage,
	})

	if !c2.GetOnOff() {
		t.Error("expected persisted OnOff=true to be loaded")
	}
}

// Helper functions for encoding test data

func encodeEmptyCommand() []byte {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	_ = w.StartStructure(tlv.Anonymous())
	_ = w.EndContainer()
	return buf.Bytes()
}

func encodeUint8(val uint8) []byte {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	_ = w.PutUint(tlv.Anonymous(), uint64(val))
	return buf.Bytes()
}

func encodeUint16(val uint16) []byte {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	_ = w.PutUint(tlv.Anonymous(), uint64(val))
	return buf.Bytes()
}

func encodeNull() []byte {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	_ = w.PutNull(tlv.Anonymous())
	return buf.Bytes()
}

func encodeOffWithEffectCommand(effectID, effectVariant uint8) []byte {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	_ = w.StartStructure(tlv.Anonymous())
	_ = w.PutUint(tlv.ContextTag(0), uint64(effectID))
	_ = w.PutUint(tlv.ContextTag(1), uint64(effectVariant))
	_ = w.EndContainer()
	return buf.Bytes()
}

func encodeOnWithTimedOffCommand(onOffControl uint8, onTime, offWaitTime uint16) []byte {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	_ = w.StartStructure(tlv.Anonymous())
	_ = w.PutUint(tlv.ContextTag(0), uint64(onOffControl))
	_ = w.PutUint(tlv.ContextTag(1), uint64(onTime))
	_ = w.PutUint(tlv.ContextTag(2), uint64(offWaitTime))
	_ = w.EndContainer()
	return buf.Bytes()
}
