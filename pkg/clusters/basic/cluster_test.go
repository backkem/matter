package basic

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/tlv"
)

// Test constants matching C++ reference tests
const (
	testVendorName            = "TestVendor"
	testProductName           = "TestProduct"
	testHardwareVersionString = "HW1.0"
	testPartNumber            = "PART123"
	testProductURL            = "https://example.com"
	testProductLabel          = "Label123"
	testSerialNumber          = "SN123456"
	testVendorID              = uint16(0xFFF1)
	testProductID             = uint16(0x5678)
	testHardwareVersion       = uint16(1)
	testSoftwareVersion       = uint32(0x01020304)
	testSoftwareVersionString = "1.2.3.4"
	testUniqueID              = "TEST_UNIQUE_ID_12345"
	testManufacturingDate     = "20230615"
	testDataModelRevision     = uint16(18) // Current data model revision
	testSpecificationVersion  = uint32(0x01050000)
	testMaxPathsPerInvoke     = uint16(1)
)

// mockStorage implements Storage for testing.
type mockStorage struct {
	nodeLabel            string
	location             string
	localConfigDisabled  bool
	configurationVersion uint32
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		nodeLabel:            "",
		location:             "XX",
		localConfigDisabled:  false,
		configurationVersion: 1,
	}
}

func (m *mockStorage) LoadNodeLabel() string                              { return m.nodeLabel }
func (m *mockStorage) StoreNodeLabel(label string) error                  { m.nodeLabel = label; return nil }
func (m *mockStorage) LoadLocation() string                               { return m.location }
func (m *mockStorage) StoreLocation(location string) error                { m.location = location; return nil }
func (m *mockStorage) LoadLocalConfigDisabled() bool                      { return m.localConfigDisabled }
func (m *mockStorage) StoreLocalConfigDisabled(disabled bool) error       { m.localConfigDisabled = disabled; return nil }
func (m *mockStorage) LoadConfigurationVersion() uint32                   { return m.configurationVersion }
func (m *mockStorage) StoreConfigurationVersion(version uint32) error     { m.configurationVersion = version; return nil }

// mockEventPublisher implements EventPublisher for testing.
type mockEventPublisher struct {
	events []publishedEvent
}

type publishedEvent struct {
	endpoint    datamodel.EndpointID
	cluster     datamodel.ClusterID
	eventID     datamodel.EventID
	priority    datamodel.EventPriority
	data        interface{}
	fabricIndex uint8
}

func (m *mockEventPublisher) PublishEvent(
	endpoint datamodel.EndpointID,
	cluster datamodel.ClusterID,
	eventID datamodel.EventID,
	priority datamodel.EventPriority,
	data interface{},
	fabricIndex uint8,
) (datamodel.EventNumber, error) {
	m.events = append(m.events, publishedEvent{
		endpoint:    endpoint,
		cluster:     cluster,
		eventID:     eventID,
		priority:    priority,
		data:        data,
		fabricIndex: fabricIndex,
	})
	return datamodel.EventNumber(len(m.events)), nil
}

// createTestCluster creates a cluster with all mandatory and optional attributes
func createTestCluster(storage Storage, publisher datamodel.EventPublisher) *Cluster {
	mfgDate := testManufacturingDate
	partNum := testPartNumber
	prodURL := testProductURL
	prodLabel := testProductLabel
	serialNum := testSerialNumber
	reachable := true

	return New(Config{
		EndpointID: 0,
		DeviceInfo: DeviceInfo{
			DataModelRevision:     testDataModelRevision,
			VendorName:            testVendorName,
			VendorID:              testVendorID,
			ProductName:           testProductName,
			ProductID:             testProductID,
			HardwareVersion:       testHardwareVersion,
			HardwareVersionString: testHardwareVersionString,
			SoftwareVersion:       testSoftwareVersion,
			SoftwareVersionString: testSoftwareVersionString,
			UniqueID:              testUniqueID,
			SpecificationVersion:  testSpecificationVersion,
			MaxPathsPerInvoke:     testMaxPathsPerInvoke,
			CapabilityMinima: CapabilityMinima{
				CaseSessionsPerFabric:  3,
				SubscriptionsPerFabric: 3,
			},
			ManufacturingDate: &mfgDate,
			PartNumber:        &partNum,
			ProductURL:        &prodURL,
			ProductLabel:      &prodLabel,
			SerialNumber:      &serialNum,
			ProductAppearance: &ProductAppearance{
				Finish:       ProductFinishMatte,
				PrimaryColor: ptrColor(ColorBlack),
			},
			Reachable: &reachable,
		},
		Storage:        storage,
		EventPublisher: publisher,
	})
}

func ptrColor(c Color) *Color {
	return &c
}

// createMinimalCluster creates a cluster with only mandatory attributes
func createMinimalCluster() *Cluster {
	return New(Config{
		EndpointID: 0,
		DeviceInfo: DeviceInfo{
			DataModelRevision:     testDataModelRevision,
			VendorName:            testVendorName,
			VendorID:              testVendorID,
			ProductName:           testProductName,
			ProductID:             testProductID,
			HardwareVersion:       testHardwareVersion,
			HardwareVersionString: testHardwareVersionString,
			SoftwareVersion:       testSoftwareVersion,
			SoftwareVersionString: testSoftwareVersionString,
			UniqueID:              testUniqueID,
			SpecificationVersion:  testSpecificationVersion,
			MaxPathsPerInvoke:     testMaxPathsPerInvoke,
			CapabilityMinima: CapabilityMinima{
				CaseSessionsPerFabric:  3,
				SubscriptionsPerFabric: 3,
			},
		},
	})
}

func TestClusterID(t *testing.T) {
	c := createMinimalCluster()
	if c.ID() != ClusterID {
		t.Errorf("expected cluster ID 0x%04X, got 0x%04X", ClusterID, c.ID())
	}
}

func TestClusterRevision(t *testing.T) {
	c := createMinimalCluster()
	if c.ClusterRevision() != ClusterRevision {
		t.Errorf("expected revision %d, got %d", ClusterRevision, c.ClusterRevision())
	}
}

func TestReadMandatoryAttributes(t *testing.T) {
	c := createMinimalCluster()
	ctx := context.Background()

	tests := []struct {
		name     string
		attrID   datamodel.AttributeID
		validate func(t *testing.T, data []byte)
	}{
		{
			name:   "DataModelRevision",
			attrID: AttrDataModelRevision,
			validate: func(t *testing.T, data []byte) {
				val := readUint16(t, data)
				if val != testDataModelRevision {
					t.Errorf("expected %d, got %d", testDataModelRevision, val)
				}
			},
		},
		{
			name:   "VendorName",
			attrID: AttrVendorName,
			validate: func(t *testing.T, data []byte) {
				val := readString(t, data)
				if val != testVendorName {
					t.Errorf("expected %q, got %q", testVendorName, val)
				}
			},
		},
		{
			name:   "VendorID",
			attrID: AttrVendorID,
			validate: func(t *testing.T, data []byte) {
				val := readUint16(t, data)
				if val != testVendorID {
					t.Errorf("expected 0x%04X, got 0x%04X", testVendorID, val)
				}
			},
		},
		{
			name:   "ProductName",
			attrID: AttrProductName,
			validate: func(t *testing.T, data []byte) {
				val := readString(t, data)
				if val != testProductName {
					t.Errorf("expected %q, got %q", testProductName, val)
				}
			},
		},
		{
			name:   "ProductID",
			attrID: AttrProductID,
			validate: func(t *testing.T, data []byte) {
				val := readUint16(t, data)
				if val != testProductID {
					t.Errorf("expected 0x%04X, got 0x%04X", testProductID, val)
				}
			},
		},
		{
			name:   "HardwareVersion",
			attrID: AttrHardwareVersion,
			validate: func(t *testing.T, data []byte) {
				val := readUint16(t, data)
				if val != testHardwareVersion {
					t.Errorf("expected %d, got %d", testHardwareVersion, val)
				}
			},
		},
		{
			name:   "HardwareVersionString",
			attrID: AttrHardwareVersionStr,
			validate: func(t *testing.T, data []byte) {
				val := readString(t, data)
				if val != testHardwareVersionString {
					t.Errorf("expected %q, got %q", testHardwareVersionString, val)
				}
			},
		},
		{
			name:   "SoftwareVersion",
			attrID: AttrSoftwareVersion,
			validate: func(t *testing.T, data []byte) {
				val := readUint32(t, data)
				if val != testSoftwareVersion {
					t.Errorf("expected 0x%08X, got 0x%08X", testSoftwareVersion, val)
				}
			},
		},
		{
			name:   "SoftwareVersionString",
			attrID: AttrSoftwareVersionStr,
			validate: func(t *testing.T, data []byte) {
				val := readString(t, data)
				if val != testSoftwareVersionString {
					t.Errorf("expected %q, got %q", testSoftwareVersionString, val)
				}
			},
		},
		{
			name:   "UniqueID",
			attrID: AttrUniqueID,
			validate: func(t *testing.T, data []byte) {
				val := readString(t, data)
				if val != testUniqueID {
					t.Errorf("expected %q, got %q", testUniqueID, val)
				}
			},
		},
		{
			name:   "SpecificationVersion",
			attrID: AttrSpecificationVersion,
			validate: func(t *testing.T, data []byte) {
				val := readUint32(t, data)
				if val != testSpecificationVersion {
					t.Errorf("expected 0x%08X, got 0x%08X", testSpecificationVersion, val)
				}
			},
		},
		{
			name:   "MaxPathsPerInvoke",
			attrID: AttrMaxPathsPerInvoke,
			validate: func(t *testing.T, data []byte) {
				val := readUint16(t, data)
				if val != testMaxPathsPerInvoke {
					t.Errorf("expected %d, got %d", testMaxPathsPerInvoke, val)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			req := datamodel.ReadAttributeRequest{
				Path: datamodel.ConcreteAttributePath{
					Endpoint:  0,
					Cluster:   ClusterID,
					Attribute: tt.attrID,
				},
			}

			err := c.ReadAttribute(ctx, req, w)
			if err != nil {
				t.Fatalf("failed to read attribute: %v", err)
			}

			tt.validate(t, buf.Bytes())
		})
	}
}

func TestReadCapabilityMinima(t *testing.T) {
	c := createMinimalCluster()
	ctx := context.Background()

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  0,
			Cluster:   ClusterID,
			Attribute: AttrCapabilityMinima,
		},
	}

	err := c.ReadAttribute(ctx, req, w)
	if err != nil {
		t.Fatalf("failed to read CapabilityMinima: %v", err)
	}

	// Parse the struct
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read struct: %v", err)
	}
	if r.Type() != tlv.ElementTypeStruct {
		t.Fatalf("expected structure, got %v", r.Type())
	}

	// Read CaseSessionsPerFabric (field 0)
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read field 0: %v", err)
	}
	caseSessions, err := r.Uint()
	if err != nil {
		t.Fatalf("failed to get uint: %v", err)
	}
	if caseSessions < 3 {
		t.Errorf("CaseSessionsPerFabric should be >= 3, got %d", caseSessions)
	}

	// Read SubscriptionsPerFabric (field 1)
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read field 1: %v", err)
	}
	subscriptions, err := r.Uint()
	if err != nil {
		t.Fatalf("failed to get uint: %v", err)
	}
	if subscriptions < 3 {
		t.Errorf("SubscriptionsPerFabric should be >= 3, got %d", subscriptions)
	}
}

func TestReadOptionalAttributes(t *testing.T) {
	storage := newMockStorage()
	publisher := &mockEventPublisher{}
	c := createTestCluster(storage, publisher)
	ctx := context.Background()

	tests := []struct {
		name     string
		attrID   datamodel.AttributeID
		validate func(t *testing.T, data []byte)
	}{
		{
			name:   "ManufacturingDate",
			attrID: AttrManufacturingDate,
			validate: func(t *testing.T, data []byte) {
				val := readString(t, data)
				if val != testManufacturingDate {
					t.Errorf("expected %q, got %q", testManufacturingDate, val)
				}
			},
		},
		{
			name:   "PartNumber",
			attrID: AttrPartNumber,
			validate: func(t *testing.T, data []byte) {
				val := readString(t, data)
				if val != testPartNumber {
					t.Errorf("expected %q, got %q", testPartNumber, val)
				}
			},
		},
		{
			name:   "ProductURL",
			attrID: AttrProductURL,
			validate: func(t *testing.T, data []byte) {
				val := readString(t, data)
				if val != testProductURL {
					t.Errorf("expected %q, got %q", testProductURL, val)
				}
			},
		},
		{
			name:   "ProductLabel",
			attrID: AttrProductLabel,
			validate: func(t *testing.T, data []byte) {
				val := readString(t, data)
				if val != testProductLabel {
					t.Errorf("expected %q, got %q", testProductLabel, val)
				}
			},
		},
		{
			name:   "SerialNumber",
			attrID: AttrSerialNumber,
			validate: func(t *testing.T, data []byte) {
				val := readString(t, data)
				if val != testSerialNumber {
					t.Errorf("expected %q, got %q", testSerialNumber, val)
				}
			},
		},
		{
			name:   "Reachable",
			attrID: AttrReachable,
			validate: func(t *testing.T, data []byte) {
				val := readBool(t, data)
				if !val {
					t.Error("expected Reachable to be true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			req := datamodel.ReadAttributeRequest{
				Path: datamodel.ConcreteAttributePath{
					Endpoint:  0,
					Cluster:   ClusterID,
					Attribute: tt.attrID,
				},
			}

			err := c.ReadAttribute(ctx, req, w)
			if err != nil {
				t.Fatalf("failed to read attribute: %v", err)
			}

			tt.validate(t, buf.Bytes())
		})
	}
}

func TestReadProductAppearance(t *testing.T) {
	storage := newMockStorage()
	publisher := &mockEventPublisher{}
	c := createTestCluster(storage, publisher)
	ctx := context.Background()

	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	req := datamodel.ReadAttributeRequest{
		Path: datamodel.ConcreteAttributePath{
			Endpoint:  0,
			Cluster:   ClusterID,
			Attribute: AttrProductAppearance,
		},
	}

	err := c.ReadAttribute(ctx, req, w)
	if err != nil {
		t.Fatalf("failed to read ProductAppearance: %v", err)
	}

	// Parse the struct
	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read struct: %v", err)
	}
	if r.Type() != tlv.ElementTypeStruct {
		t.Fatalf("expected structure, got %v", r.Type())
	}

	// Read Finish (field 0)
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read field 0: %v", err)
	}
	finish, err := r.Uint()
	if err != nil {
		t.Fatalf("failed to get uint: %v", err)
	}
	if ProductFinish(finish) != ProductFinishMatte {
		t.Errorf("expected Matte finish, got %v", ProductFinish(finish))
	}

	// Read PrimaryColor (field 1)
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read field 1: %v", err)
	}
	color, err := r.Uint()
	if err != nil {
		t.Fatalf("failed to get uint: %v", err)
	}
	if Color(color) != ColorBlack {
		t.Errorf("expected Black color, got %v", Color(color))
	}
}

func TestOptionalAttributeNotPresent(t *testing.T) {
	// Create minimal cluster without optional attributes
	c := createMinimalCluster()
	ctx := context.Background()

	optionalAttrs := []datamodel.AttributeID{
		AttrManufacturingDate,
		AttrPartNumber,
		AttrProductURL,
		AttrProductLabel,
		AttrSerialNumber,
		AttrProductAppearance,
		AttrReachable,
	}

	for _, attrID := range optionalAttrs {
		t.Run(fmt.Sprintf("OptionalNotPresent_0x%04X", attrID), func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			req := datamodel.ReadAttributeRequest{
				Path: datamodel.ConcreteAttributePath{
					Endpoint:  0,
					Cluster:   ClusterID,
					Attribute: attrID,
				},
			}

			err := c.ReadAttribute(ctx, req, w)
			if err != datamodel.ErrUnsupportedAttribute {
				t.Errorf("expected ErrUnsupportedAttribute, got %v", err)
			}
		})
	}
}

func TestWriteNodeLabel(t *testing.T) {
	storage := newMockStorage()
	c := createTestCluster(storage, nil)
	ctx := context.Background()

	tests := []struct {
		name      string
		label     string
		expectErr bool
	}{
		{
			name:      "ValidLabel",
			label:     "My Awesome Hub",
			expectErr: false,
		},
		{
			name:      "EmptyLabel",
			label:     "",
			expectErr: false,
		},
		{
			name:      "MaxLengthLabel",
			label:     "12345678901234567890123456789012", // 32 chars
			expectErr: false,
		},
		{
			name:      "TooLongLabel",
			label:     "123456789012345678901234567890123", // 33 chars
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode the value
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)
			if err := w.PutString(tlv.Anonymous(), tt.label); err != nil {
				t.Fatalf("failed to encode: %v", err)
			}

			r := tlv.NewReader(bytes.NewReader(buf.Bytes()))

			req := datamodel.WriteAttributeRequest{
				Path: datamodel.ConcreteDataAttributePath{
					ConcreteAttributePath: datamodel.ConcreteAttributePath{
						Endpoint:  0,
						Cluster:   ClusterID,
						Attribute: AttrNodeLabel,
					},
				},
			}

			err := c.WriteAttribute(ctx, req, r)
			if tt.expectErr {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				// Verify the value was stored
				if c.GetNodeLabel() != tt.label {
					t.Errorf("expected label %q, got %q", tt.label, c.GetNodeLabel())
				}

				// Verify persistence
				if storage.nodeLabel != tt.label {
					t.Errorf("expected persisted label %q, got %q", tt.label, storage.nodeLabel)
				}
			}
		})
	}
}

func TestWriteLocation(t *testing.T) {
	storage := newMockStorage()
	c := createTestCluster(storage, nil)
	ctx := context.Background()

	tests := []struct {
		name      string
		location  string
		expectErr bool
	}{
		{
			name:      "ValidLocation_US",
			location:  "US",
			expectErr: false,
		},
		{
			name:      "ValidLocation_DE",
			location:  "DE",
			expectErr: false,
		},
		{
			name:      "ValidLocation_XX",
			location:  "XX",
			expectErr: false,
		},
		{
			name:      "TooShort",
			location:  "U",
			expectErr: true,
		},
		{
			name:      "TooLong",
			location:  "USA",
			expectErr: true,
		},
		{
			name:      "Empty",
			location:  "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode the value
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)
			if err := w.PutString(tlv.Anonymous(), tt.location); err != nil {
				t.Fatalf("failed to encode: %v", err)
			}

			r := tlv.NewReader(bytes.NewReader(buf.Bytes()))

			req := datamodel.WriteAttributeRequest{
				Path: datamodel.ConcreteDataAttributePath{
					ConcreteAttributePath: datamodel.ConcreteAttributePath{
						Endpoint:  0,
						Cluster:   ClusterID,
						Attribute: AttrLocation,
					},
				},
			}

			err := c.WriteAttribute(ctx, req, r)
			if tt.expectErr {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				// Verify the value was stored
				if c.GetLocation() != tt.location {
					t.Errorf("expected location %q, got %q", tt.location, c.GetLocation())
				}

				// Verify persistence
				if storage.location != tt.location {
					t.Errorf("expected persisted location %q, got %q", tt.location, storage.location)
				}
			}
		})
	}
}

func TestWriteLocalConfigDisabled(t *testing.T) {
	storage := newMockStorage()
	c := createTestCluster(storage, nil)
	ctx := context.Background()

	// Write true
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := w.PutBool(tlv.Anonymous(), true); err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	r := tlv.NewReader(bytes.NewReader(buf.Bytes()))

	req := datamodel.WriteAttributeRequest{
		Path: datamodel.ConcreteDataAttributePath{
			ConcreteAttributePath: datamodel.ConcreteAttributePath{
				Endpoint:  0,
				Cluster:   ClusterID,
				Attribute: AttrLocalConfigDisabled,
			},
		},
	}

	if err := c.WriteAttribute(ctx, req, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !c.GetLocalConfigDisabled() {
		t.Error("expected LocalConfigDisabled to be true")
	}

	if !storage.localConfigDisabled {
		t.Error("expected persisted LocalConfigDisabled to be true")
	}

	// Write false
	buf.Reset()
	w = tlv.NewWriter(&buf)
	if err := w.PutBool(tlv.Anonymous(), false); err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	r = tlv.NewReader(bytes.NewReader(buf.Bytes()))

	if err := c.WriteAttribute(ctx, req, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c.GetLocalConfigDisabled() {
		t.Error("expected LocalConfigDisabled to be false")
	}
}

func TestAttributeList(t *testing.T) {
	// Test minimal cluster (mandatory attributes only)
	t.Run("MinimalCluster", func(t *testing.T) {
		c := createMinimalCluster()
		attrList := c.AttributeList()

		// Check mandatory attributes are present
		mandatoryAttrs := []datamodel.AttributeID{
			AttrDataModelRevision,
			AttrVendorName,
			AttrVendorID,
			AttrProductName,
			AttrProductID,
			AttrNodeLabel,
			AttrLocation,
			AttrHardwareVersion,
			AttrHardwareVersionStr,
			AttrSoftwareVersion,
			AttrSoftwareVersionStr,
			AttrUniqueID,
			AttrCapabilityMinima,
			AttrSpecificationVersion,
			AttrMaxPathsPerInvoke,
			AttrConfigurationVersion,
			AttrLocalConfigDisabled, // Always present
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
			datamodel.GlobalAttrAcceptedCommandList,
			datamodel.GlobalAttrGeneratedCommandList,
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
	})

	// Test full cluster (all attributes)
	t.Run("FullCluster", func(t *testing.T) {
		storage := newMockStorage()
		c := createTestCluster(storage, nil)
		attrList := c.AttributeList()

		// Check optional attributes are present
		optionalAttrs := []datamodel.AttributeID{
			AttrManufacturingDate,
			AttrPartNumber,
			AttrProductURL,
			AttrProductLabel,
			AttrSerialNumber,
			AttrProductAppearance,
			AttrReachable,
		}

		for _, attrID := range optionalAttrs {
			found := false
			for _, entry := range attrList {
				if entry.ID == attrID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("optional attribute 0x%04X not in AttributeList", attrID)
			}
		}
	})
}

func TestNoCommands(t *testing.T) {
	c := createMinimalCluster()

	if len(c.AcceptedCommandList()) != 0 {
		t.Error("Basic Information cluster should have no accepted commands")
	}

	if len(c.GeneratedCommandList()) != 0 {
		t.Error("Basic Information cluster should have no generated commands")
	}
}

func TestEmitStartUp(t *testing.T) {
	storage := newMockStorage()
	publisher := &mockEventPublisher{}
	c := createTestCluster(storage, publisher)

	eventNum, err := c.EmitStartUp()
	if err != nil {
		t.Fatalf("failed to emit StartUp event: %v", err)
	}

	if eventNum == 0 {
		t.Error("expected non-zero event number")
	}

	if len(publisher.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(publisher.events))
	}

	event := publisher.events[0]
	if event.eventID != EventStartUp {
		t.Errorf("expected event ID %d, got %d", EventStartUp, event.eventID)
	}
	if event.priority != datamodel.EventPriorityCritical {
		t.Errorf("expected CRITICAL priority, got %v", event.priority)
	}

	// Verify event data
	startUpEvent, ok := event.data.(StartUpEvent)
	if !ok {
		t.Fatalf("expected StartUpEvent, got %T", event.data)
	}
	if startUpEvent.SoftwareVersion != testSoftwareVersion {
		t.Errorf("expected SoftwareVersion %d, got %d", testSoftwareVersion, startUpEvent.SoftwareVersion)
	}
}

func TestEmitShutDown(t *testing.T) {
	storage := newMockStorage()
	publisher := &mockEventPublisher{}
	c := createTestCluster(storage, publisher)

	eventNum, err := c.EmitShutDown()
	if err != nil {
		t.Fatalf("failed to emit ShutDown event: %v", err)
	}

	if eventNum == 0 {
		t.Error("expected non-zero event number")
	}

	if len(publisher.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(publisher.events))
	}

	event := publisher.events[0]
	if event.eventID != EventShutDown {
		t.Errorf("expected event ID %d, got %d", EventShutDown, event.eventID)
	}
	if event.priority != datamodel.EventPriorityCritical {
		t.Errorf("expected CRITICAL priority, got %v", event.priority)
	}
}

func TestEmitLeave(t *testing.T) {
	storage := newMockStorage()
	publisher := &mockEventPublisher{}
	c := createTestCluster(storage, publisher)

	fabricIndex := uint8(1)
	eventNum, err := c.EmitLeave(fabricIndex)
	if err != nil {
		t.Fatalf("failed to emit Leave event: %v", err)
	}

	if eventNum == 0 {
		t.Error("expected non-zero event number")
	}

	if len(publisher.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(publisher.events))
	}

	event := publisher.events[0]
	if event.eventID != EventLeave {
		t.Errorf("expected event ID %d, got %d", EventLeave, event.eventID)
	}
	if event.priority != datamodel.EventPriorityInfo {
		t.Errorf("expected INFO priority, got %v", event.priority)
	}

	// Verify event data
	leaveEvent, ok := event.data.(LeaveEvent)
	if !ok {
		t.Fatalf("expected LeaveEvent, got %T", event.data)
	}
	if leaveEvent.FabricIndex != fabricIndex {
		t.Errorf("expected FabricIndex %d, got %d", fabricIndex, leaveEvent.FabricIndex)
	}
}

func TestIncrementConfigurationVersion(t *testing.T) {
	storage := newMockStorage()
	c := createTestCluster(storage, nil)

	initial := c.GetConfigurationVersion()
	c.IncrementConfigurationVersion()

	if c.GetConfigurationVersion() != initial+1 {
		t.Errorf("expected ConfigurationVersion %d, got %d", initial+1, c.GetConfigurationVersion())
	}

	// Verify persistence
	if storage.configurationVersion != initial+1 {
		t.Errorf("expected persisted ConfigurationVersion %d, got %d", initial+1, storage.configurationVersion)
	}
}

func TestPersistenceLoadOnCreate(t *testing.T) {
	storage := newMockStorage()
	storage.nodeLabel = "Persisted Label"
	storage.location = "GB"
	storage.localConfigDisabled = true
	storage.configurationVersion = 42

	c := createTestCluster(storage, nil)

	if c.GetNodeLabel() != "Persisted Label" {
		t.Errorf("expected NodeLabel 'Persisted Label', got %q", c.GetNodeLabel())
	}
	if c.GetLocation() != "GB" {
		t.Errorf("expected Location 'GB', got %q", c.GetLocation())
	}
	if !c.GetLocalConfigDisabled() {
		t.Error("expected LocalConfigDisabled to be true")
	}
	if c.GetConfigurationVersion() != 42 {
		t.Errorf("expected ConfigurationVersion 42, got %d", c.GetConfigurationVersion())
	}
}

// Helper functions for reading TLV values

func readUint16(t *testing.T, data []byte) uint16 {
	t.Helper()
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	val, err := r.Uint()
	if err != nil {
		t.Fatalf("failed to get uint: %v", err)
	}
	return uint16(val)
}

func readUint32(t *testing.T, data []byte) uint32 {
	t.Helper()
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	val, err := r.Uint()
	if err != nil {
		t.Fatalf("failed to get uint: %v", err)
	}
	return uint32(val)
}

func readString(t *testing.T, data []byte) string {
	t.Helper()
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	val, err := r.String()
	if err != nil {
		t.Fatalf("failed to get string: %v", err)
	}
	return val
}

func readBool(t *testing.T, data []byte) bool {
	t.Helper()
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	val, err := r.Bool()
	if err != nil {
		t.Fatalf("failed to get bool: %v", err)
	}
	return val
}
