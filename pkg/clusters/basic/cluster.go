// Package basic implements the Basic Information Cluster (0x0028).
//
// The Basic Information cluster provides attributes and events for determining
// basic information about Nodes, such as Vendor ID, Product ID, serial number,
// and other characteristics that apply to the whole Node.
//
// This cluster is mandatory on the root endpoint (endpoint 0).
//
// Spec Reference: Section 11.1
//
// C++ Reference: src/app/clusters/basic-information/BasicInformationCluster.cpp
package basic

import (
	"context"
	"sync"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/tlv"
)

// Cluster constants.
const (
	ClusterID       datamodel.ClusterID = 0x0028
	ClusterRevision uint16              = 5
)

// Attribute IDs (Spec 11.1.5).
const (
	AttrDataModelRevision    datamodel.AttributeID = 0x0000
	AttrVendorName           datamodel.AttributeID = 0x0001
	AttrVendorID             datamodel.AttributeID = 0x0002
	AttrProductName          datamodel.AttributeID = 0x0003
	AttrProductID            datamodel.AttributeID = 0x0004
	AttrNodeLabel            datamodel.AttributeID = 0x0005
	AttrLocation             datamodel.AttributeID = 0x0006
	AttrHardwareVersion      datamodel.AttributeID = 0x0007
	AttrHardwareVersionStr   datamodel.AttributeID = 0x0008
	AttrSoftwareVersion      datamodel.AttributeID = 0x0009
	AttrSoftwareVersionStr   datamodel.AttributeID = 0x000A
	AttrManufacturingDate    datamodel.AttributeID = 0x000B
	AttrPartNumber           datamodel.AttributeID = 0x000C
	AttrProductURL           datamodel.AttributeID = 0x000D
	AttrProductLabel         datamodel.AttributeID = 0x000E
	AttrSerialNumber         datamodel.AttributeID = 0x000F
	AttrLocalConfigDisabled  datamodel.AttributeID = 0x0010
	AttrReachable            datamodel.AttributeID = 0x0011
	AttrUniqueID             datamodel.AttributeID = 0x0012
	AttrCapabilityMinima     datamodel.AttributeID = 0x0013
	AttrProductAppearance    datamodel.AttributeID = 0x0014
	AttrSpecificationVersion datamodel.AttributeID = 0x0015
	AttrMaxPathsPerInvoke    datamodel.AttributeID = 0x0016
	AttrConfigurationVersion datamodel.AttributeID = 0x0018
)

// Event IDs (Spec 11.1.6).
const (
	EventStartUp          datamodel.EventID = 0x00
	EventShutDown         datamodel.EventID = 0x01
	EventLeave            datamodel.EventID = 0x02
	EventReachableChanged datamodel.EventID = 0x03
)

// ProductFinish describes the visible finish of the product (Spec 11.1.4.1).
type ProductFinish uint8

const (
	ProductFinishOther    ProductFinish = 0
	ProductFinishMatte    ProductFinish = 1
	ProductFinishSatin    ProductFinish = 2
	ProductFinishPolished ProductFinish = 3
	ProductFinishRugged   ProductFinish = 4
	ProductFinishFabric   ProductFinish = 5
)

// String returns the name of the product finish.
func (p ProductFinish) String() string {
	switch p {
	case ProductFinishOther:
		return "Other"
	case ProductFinishMatte:
		return "Matte"
	case ProductFinishSatin:
		return "Satin"
	case ProductFinishPolished:
		return "Polished"
	case ProductFinishRugged:
		return "Rugged"
	case ProductFinishFabric:
		return "Fabric"
	default:
		return "Unknown"
	}
}

// Color describes the primary color of the product (Spec 11.1.4.2).
type Color uint8

const (
	ColorBlack   Color = 0
	ColorNavy    Color = 1
	ColorGreen   Color = 2
	ColorTeal    Color = 3
	ColorMaroon  Color = 4
	ColorPurple  Color = 5
	ColorOlive   Color = 6
	ColorGray    Color = 7
	ColorBlue    Color = 8
	ColorLime    Color = 9
	ColorAqua    Color = 10
	ColorRed     Color = 11
	ColorFuchsia Color = 12
	ColorYellow  Color = 13
	ColorWhite   Color = 14
	ColorNickel  Color = 15
	ColorChrome  Color = 16
	ColorBrass   Color = 17
	ColorCopper  Color = 18
	ColorSilver  Color = 19
	ColorGold    Color = 20
)

// ProductAppearance describes the product's appearance (Spec 11.1.4.3).
type ProductAppearance struct {
	Finish       ProductFinish
	PrimaryColor *Color // nullable
}

// CapabilityMinima provides constant values for system-wide capabilities (Spec 11.1.4.4).
type CapabilityMinima struct {
	CaseSessionsPerFabric  uint16
	SubscriptionsPerFabric uint16
}

// DeviceInfo provides static device information.
// These values are typically set at manufacturing time and don't change.
type DeviceInfo struct {
	// Mandatory attributes
	DataModelRevision     uint16
	VendorName            string // max 32 chars
	VendorID              uint16
	ProductName           string // max 32 chars
	ProductID             uint16
	HardwareVersion       uint16
	HardwareVersionString string // 1-64 chars
	SoftwareVersion       uint32
	SoftwareVersionString string // 1-64 chars
	UniqueID              string // max 32 chars
	CapabilityMinima      CapabilityMinima
	SpecificationVersion  uint32
	MaxPathsPerInvoke     uint16

	// Optional attributes
	ManufacturingDate *string            // 8-16 chars, format YYYYMMDD...
	PartNumber        *string            // max 32 chars
	ProductURL        *string            // max 256 chars
	ProductLabel      *string            // max 64 chars
	SerialNumber      *string            // max 32 chars
	ProductAppearance *ProductAppearance

	// Reachable is typically true for native nodes
	// Main use is in Bridged Device Basic Information
	Reachable *bool
}

// Storage provides persistence for mutable attributes.
type Storage interface {
	// LoadNodeLabel loads the persisted node label.
	// Returns empty string if not found.
	LoadNodeLabel() string

	// StoreNodeLabel persists the node label.
	StoreNodeLabel(label string) error

	// LoadLocation loads the persisted location code.
	// Returns "XX" if not found.
	LoadLocation() string

	// StoreLocation persists the location code.
	StoreLocation(location string) error

	// LoadLocalConfigDisabled loads the persisted value.
	// Returns false if not found.
	LoadLocalConfigDisabled() bool

	// StoreLocalConfigDisabled persists the value.
	StoreLocalConfigDisabled(disabled bool) error

	// LoadConfigurationVersion loads the configuration version.
	// Returns 1 if not found.
	LoadConfigurationVersion() uint32

	// StoreConfigurationVersion persists the configuration version.
	StoreConfigurationVersion(version uint32) error
}

// Config provides dependencies for the Basic Information cluster.
type Config struct {
	// EndpointID is the endpoint this cluster belongs to (should be 0).
	EndpointID datamodel.EndpointID

	// DeviceInfo provides static device information.
	DeviceInfo DeviceInfo

	// Storage for persisting mutable attributes.
	// If nil, mutable attributes are stored in memory only.
	Storage Storage

	// EventPublisher for StartUp/ShutDown/Leave events.
	// Optional - if nil, events are not emitted.
	EventPublisher datamodel.EventPublisher
}

// Cluster implements the Basic Information cluster (0x0028).
type Cluster struct {
	*datamodel.ClusterBase
	*datamodel.EventSource
	config Config

	// Mutable state (protected by mutex)
	mu                   sync.RWMutex
	nodeLabel            string
	location             string
	localConfigDisabled  bool
	configurationVersion uint32

	// Cached attribute list (built on construction)
	attrList []datamodel.AttributeEntry
}

// New creates a new Basic Information cluster.
func New(cfg Config) *Cluster {
	c := &Cluster{
		ClusterBase: datamodel.NewClusterBase(ClusterID, cfg.EndpointID, ClusterRevision),
		EventSource: datamodel.NewEventSource(),
		config:      cfg,
		// Defaults
		nodeLabel:            "",
		location:             "XX",
		localConfigDisabled:  false,
		configurationVersion: 1,
	}

	// Load persisted values
	if cfg.Storage != nil {
		c.nodeLabel = cfg.Storage.LoadNodeLabel()
		c.location = cfg.Storage.LoadLocation()
		c.localConfigDisabled = cfg.Storage.LoadLocalConfigDisabled()
		c.configurationVersion = cfg.Storage.LoadConfigurationVersion()
	}

	// Bind event source
	if cfg.EventPublisher != nil {
		c.EventSource.Bind(cfg.EndpointID, ClusterID, cfg.EventPublisher)
		c.registerEvents()
	}

	// Build attribute list
	c.attrList = c.buildAttributeList()

	return c
}

// registerEvents registers the cluster's events for validation.
func (c *Cluster) registerEvents() {
	// Mandatory event
	c.EventSource.RegisterEvent(datamodel.NewEventEntry(
		EventStartUp,
		datamodel.EventPriorityCritical,
		datamodel.PrivilegeView,
		false,
	))

	// Optional events (register all, actual emission depends on config)
	c.EventSource.RegisterEvent(datamodel.NewEventEntry(
		EventShutDown,
		datamodel.EventPriorityCritical,
		datamodel.PrivilegeView,
		false,
	))
	c.EventSource.RegisterEvent(datamodel.NewEventEntry(
		EventLeave,
		datamodel.EventPriorityInfo,
		datamodel.PrivilegeView,
		false,
	))
	if c.config.DeviceInfo.Reachable != nil {
		c.EventSource.RegisterEvent(datamodel.NewEventEntry(
			EventReachableChanged,
			datamodel.EventPriorityInfo,
			datamodel.PrivilegeView,
			false,
		))
	}
}

// buildAttributeList constructs the list of supported attributes.
func (c *Cluster) buildAttributeList() []datamodel.AttributeEntry {
	viewPriv := datamodel.PrivilegeView
	managePriv := datamodel.PrivilegeManage
	adminPriv := datamodel.PrivilegeAdminister

	attrs := []datamodel.AttributeEntry{
		// Mandatory fixed attributes
		datamodel.NewReadOnlyAttribute(AttrDataModelRevision, datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrVendorName, datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrVendorID, datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrProductName, datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrProductID, datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrHardwareVersion, datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrHardwareVersionStr, datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrSoftwareVersion, datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrSoftwareVersionStr, datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrUniqueID, datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrCapabilityMinima, datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrSpecificationVersion, datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrMaxPathsPerInvoke, datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrConfigurationVersion, datamodel.AttrQualityNonVolatile, viewPriv),

		// Mandatory writable attributes
		datamodel.NewReadWriteAttribute(AttrNodeLabel, datamodel.AttrQualityNonVolatile, viewPriv, managePriv),
		datamodel.NewReadWriteAttribute(AttrLocation, datamodel.AttrQualityNonVolatile, viewPriv, adminPriv),
	}

	// Optional attributes based on DeviceInfo
	if c.config.DeviceInfo.ManufacturingDate != nil {
		attrs = append(attrs, datamodel.NewReadOnlyAttribute(AttrManufacturingDate, datamodel.AttrQualityFixed, viewPriv))
	}
	if c.config.DeviceInfo.PartNumber != nil {
		attrs = append(attrs, datamodel.NewReadOnlyAttribute(AttrPartNumber, datamodel.AttrQualityFixed, viewPriv))
	}
	if c.config.DeviceInfo.ProductURL != nil {
		attrs = append(attrs, datamodel.NewReadOnlyAttribute(AttrProductURL, datamodel.AttrQualityFixed, viewPriv))
	}
	if c.config.DeviceInfo.ProductLabel != nil {
		attrs = append(attrs, datamodel.NewReadOnlyAttribute(AttrProductLabel, datamodel.AttrQualityFixed, viewPriv))
	}
	if c.config.DeviceInfo.SerialNumber != nil {
		attrs = append(attrs, datamodel.NewReadOnlyAttribute(AttrSerialNumber, datamodel.AttrQualityFixed, viewPriv))
	}
	if c.config.DeviceInfo.ProductAppearance != nil {
		attrs = append(attrs, datamodel.NewReadOnlyAttribute(AttrProductAppearance, datamodel.AttrQualityFixed, viewPriv))
	}
	if c.config.DeviceInfo.Reachable != nil {
		attrs = append(attrs, datamodel.NewReadOnlyAttribute(AttrReachable, 0, viewPriv))
	}

	// LocalConfigDisabled is always present (but optional per spec)
	attrs = append(attrs, datamodel.NewReadWriteAttribute(AttrLocalConfigDisabled, datamodel.AttrQualityNonVolatile, viewPriv, managePriv))

	// Add global attributes
	return datamodel.MergeAttributeLists(attrs)
}

// AttributeList implements datamodel.Cluster.
func (c *Cluster) AttributeList() []datamodel.AttributeEntry {
	return c.attrList
}

// AcceptedCommandList implements datamodel.Cluster.
// Basic Information cluster has no commands.
func (c *Cluster) AcceptedCommandList() []datamodel.CommandEntry {
	return nil
}

// GeneratedCommandList implements datamodel.Cluster.
// Basic Information cluster has no commands.
func (c *Cluster) GeneratedCommandList() []datamodel.CommandID {
	return nil
}

// ReadAttribute implements datamodel.Cluster.
func (c *Cluster) ReadAttribute(ctx context.Context, req datamodel.ReadAttributeRequest, w *tlv.Writer) error {
	// Handle global attributes first
	handled, err := c.ReadGlobalAttribute(ctx, req.Path.Attribute, w, c.attrList, nil, nil)
	if handled || err != nil {
		return err
	}

	switch req.Path.Attribute {
	// Mandatory fixed attributes
	case AttrDataModelRevision:
		return w.PutUint(tlv.Anonymous(), uint64(c.config.DeviceInfo.DataModelRevision))
	case AttrVendorName:
		return w.PutString(tlv.Anonymous(), c.config.DeviceInfo.VendorName)
	case AttrVendorID:
		return w.PutUint(tlv.Anonymous(), uint64(c.config.DeviceInfo.VendorID))
	case AttrProductName:
		return w.PutString(tlv.Anonymous(), c.config.DeviceInfo.ProductName)
	case AttrProductID:
		return w.PutUint(tlv.Anonymous(), uint64(c.config.DeviceInfo.ProductID))
	case AttrHardwareVersion:
		return w.PutUint(tlv.Anonymous(), uint64(c.config.DeviceInfo.HardwareVersion))
	case AttrHardwareVersionStr:
		return w.PutString(tlv.Anonymous(), c.config.DeviceInfo.HardwareVersionString)
	case AttrSoftwareVersion:
		return w.PutUint(tlv.Anonymous(), uint64(c.config.DeviceInfo.SoftwareVersion))
	case AttrSoftwareVersionStr:
		return w.PutString(tlv.Anonymous(), c.config.DeviceInfo.SoftwareVersionString)
	case AttrUniqueID:
		return w.PutString(tlv.Anonymous(), c.config.DeviceInfo.UniqueID)
	case AttrSpecificationVersion:
		return w.PutUint(tlv.Anonymous(), uint64(c.config.DeviceInfo.SpecificationVersion))
	case AttrMaxPathsPerInvoke:
		return w.PutUint(tlv.Anonymous(), uint64(c.config.DeviceInfo.MaxPathsPerInvoke))

	// Structs
	case AttrCapabilityMinima:
		return c.readCapabilityMinima(w)

	// Mutable attributes
	case AttrNodeLabel:
		c.mu.RLock()
		defer c.mu.RUnlock()
		return w.PutString(tlv.Anonymous(), c.nodeLabel)
	case AttrLocation:
		c.mu.RLock()
		defer c.mu.RUnlock()
		return w.PutString(tlv.Anonymous(), c.location)
	case AttrLocalConfigDisabled:
		c.mu.RLock()
		defer c.mu.RUnlock()
		return w.PutBool(tlv.Anonymous(), c.localConfigDisabled)
	case AttrConfigurationVersion:
		c.mu.RLock()
		defer c.mu.RUnlock()
		return w.PutUint(tlv.Anonymous(), uint64(c.configurationVersion))

	// Optional fixed attributes
	case AttrManufacturingDate:
		if c.config.DeviceInfo.ManufacturingDate == nil {
			return datamodel.ErrUnsupportedAttribute
		}
		return w.PutString(tlv.Anonymous(), *c.config.DeviceInfo.ManufacturingDate)
	case AttrPartNumber:
		if c.config.DeviceInfo.PartNumber == nil {
			return datamodel.ErrUnsupportedAttribute
		}
		return w.PutString(tlv.Anonymous(), *c.config.DeviceInfo.PartNumber)
	case AttrProductURL:
		if c.config.DeviceInfo.ProductURL == nil {
			return datamodel.ErrUnsupportedAttribute
		}
		return w.PutString(tlv.Anonymous(), *c.config.DeviceInfo.ProductURL)
	case AttrProductLabel:
		if c.config.DeviceInfo.ProductLabel == nil {
			return datamodel.ErrUnsupportedAttribute
		}
		return w.PutString(tlv.Anonymous(), *c.config.DeviceInfo.ProductLabel)
	case AttrSerialNumber:
		if c.config.DeviceInfo.SerialNumber == nil {
			return datamodel.ErrUnsupportedAttribute
		}
		return w.PutString(tlv.Anonymous(), *c.config.DeviceInfo.SerialNumber)
	case AttrProductAppearance:
		return c.readProductAppearance(w)
	case AttrReachable:
		if c.config.DeviceInfo.Reachable == nil {
			return datamodel.ErrUnsupportedAttribute
		}
		return w.PutBool(tlv.Anonymous(), *c.config.DeviceInfo.Reachable)

	default:
		return datamodel.ErrUnsupportedAttribute
	}
}

// WriteAttribute implements datamodel.Cluster.
func (c *Cluster) WriteAttribute(ctx context.Context, req datamodel.WriteAttributeRequest, r *tlv.Reader) error {
	switch req.Path.Attribute {
	case AttrNodeLabel:
		return c.writeNodeLabel(r)
	case AttrLocation:
		return c.writeLocation(r)
	case AttrLocalConfigDisabled:
		return c.writeLocalConfigDisabled(r)
	default:
		return datamodel.ErrUnsupportedWrite
	}
}

// InvokeCommand implements datamodel.Cluster.
// Basic Information cluster has no commands.
func (c *Cluster) InvokeCommand(ctx context.Context, req datamodel.InvokeRequest, r *tlv.Reader) ([]byte, error) {
	return nil, datamodel.ErrUnsupportedCommand
}

// GetNodeLabel returns the current node label.
func (c *Cluster) GetNodeLabel() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nodeLabel
}

// GetLocation returns the current location code.
func (c *Cluster) GetLocation() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.location
}

// GetLocalConfigDisabled returns the current local config disabled state.
func (c *Cluster) GetLocalConfigDisabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.localConfigDisabled
}

// GetConfigurationVersion returns the current configuration version.
func (c *Cluster) GetConfigurationVersion() uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.configurationVersion
}

// IncrementConfigurationVersion increments the configuration version.
// Call this when the node's configuration changes (endpoints/clusters added).
func (c *Cluster) IncrementConfigurationVersion() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.configurationVersion++
	if c.config.Storage != nil {
		_ = c.config.Storage.StoreConfigurationVersion(c.configurationVersion)
	}
	c.IncrementDataVersion()
}
