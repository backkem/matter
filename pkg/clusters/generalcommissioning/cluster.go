// Package generalcommissioning implements the General Commissioning Cluster (0x0030).
//
// The General Commissioning cluster provides commands and attributes to support
// the commissioning process including fail-safe timer management, regulatory
// configuration, and commissioning completion.
//
// This cluster is mandatory on the root endpoint (endpoint 0).
//
// Spec Reference: Section 11.10
//
// C++ Reference: src/app/clusters/general-commissioning-server/GeneralCommissioningCluster.cpp
package generalcommissioning

import (
	"context"
	"errors"
	"sync"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/tlv"
)

// Cluster constants.
const (
	ClusterID       datamodel.ClusterID = 0x0030
	ClusterRevision uint16              = 3
)

// Attribute IDs (Spec 11.10.6).
const (
	AttrBreadcrumb                   datamodel.AttributeID = 0x0000
	AttrBasicCommissioningInfo       datamodel.AttributeID = 0x0001
	AttrRegulatoryConfig             datamodel.AttributeID = 0x0002
	AttrLocationCapability           datamodel.AttributeID = 0x0003
	AttrSupportsConcurrentConnection datamodel.AttributeID = 0x0004
	// TC feature attributes (0x0005-0x0009) - optional
	AttrTCAcceptedVersion         datamodel.AttributeID = 0x0005
	AttrTCMinRequiredVersion      datamodel.AttributeID = 0x0006
	AttrTCAcknowledgements        datamodel.AttributeID = 0x0007
	AttrTCAcknowledgementsReqired datamodel.AttributeID = 0x0008
	AttrTCUpdateDeadline          datamodel.AttributeID = 0x0009
)

// Command IDs (Spec 11.10.7).
const (
	CmdArmFailSafe                 datamodel.CommandID = 0x00
	CmdArmFailSafeResponse         datamodel.CommandID = 0x01
	CmdSetRegulatoryConfig         datamodel.CommandID = 0x02
	CmdSetRegulatoryConfigResponse datamodel.CommandID = 0x03
	CmdCommissioningComplete       datamodel.CommandID = 0x04
	CmdCommissioningCompleteResp   datamodel.CommandID = 0x05
	CmdSetTCAcknowledgements       datamodel.CommandID = 0x06
	CmdSetTCAcknowledgementsResp   datamodel.CommandID = 0x07
)

// Feature bits (Spec 11.10.4).
type Feature uint32

const (
	// FeatureTermsAndConditions indicates T&C support.
	FeatureTermsAndConditions Feature = 1 << 0 // TC
)

// RegulatoryLocationType indicates the regulatory location type (Spec 11.10.5.3).
type RegulatoryLocationType uint8

const (
	RegulatoryIndoor        RegulatoryLocationType = 0
	RegulatoryOutdoor       RegulatoryLocationType = 1
	RegulatoryIndoorOutdoor RegulatoryLocationType = 2
)

// String returns the name of the regulatory location type.
func (r RegulatoryLocationType) String() string {
	switch r {
	case RegulatoryIndoor:
		return "Indoor"
	case RegulatoryOutdoor:
		return "Outdoor"
	case RegulatoryIndoorOutdoor:
		return "IndoorOutdoor"
	default:
		return "Unknown"
	}
}

// CommissioningErrorCode defines error codes for commissioning responses (Spec 11.10.5.1).
type CommissioningErrorCode uint8

const (
	CommissioningOK                           CommissioningErrorCode = 0
	CommissioningValueOutsideRange            CommissioningErrorCode = 1
	CommissioningInvalidAuthentication        CommissioningErrorCode = 2
	CommissioningNoFailSafe                   CommissioningErrorCode = 3
	CommissioningBusyWithOtherAdmin           CommissioningErrorCode = 4
	CommissioningRequiredTCNotAccepted        CommissioningErrorCode = 5
	CommissioningTCAcknowledgementsNotReceved CommissioningErrorCode = 6
	CommissioningTCMinVersionNotMet           CommissioningErrorCode = 7
)

// String returns the name of the commissioning error code.
func (c CommissioningErrorCode) String() string {
	switch c {
	case CommissioningOK:
		return "OK"
	case CommissioningValueOutsideRange:
		return "ValueOutsideRange"
	case CommissioningInvalidAuthentication:
		return "InvalidAuthentication"
	case CommissioningNoFailSafe:
		return "NoFailSafe"
	case CommissioningBusyWithOtherAdmin:
		return "BusyWithOtherAdmin"
	case CommissioningRequiredTCNotAccepted:
		return "RequiredTCNotAccepted"
	case CommissioningTCAcknowledgementsNotReceved:
		return "TCAcknowledgementsNotReceived"
	case CommissioningTCMinVersionNotMet:
		return "TCMinVersionNotMet"
	default:
		return "Unknown"
	}
}

// BasicCommissioningInfo provides constant values for commissioning (Spec 11.10.5.4).
type BasicCommissioningInfo struct {
	// FailSafeExpiryLengthSeconds is the initial fail-safe duration.
	FailSafeExpiryLengthSeconds uint16

	// MaxCumulativeFailsafeSeconds is the maximum total fail-safe duration.
	MaxCumulativeFailsafeSeconds uint16
}

// FailSafeManager provides the fail-safe context management.
// This interface allows the cluster to manage the fail-safe timer
// without coupling to specific implementation details.
type FailSafeManager interface {
	// IsArmed returns true if the fail-safe timer is currently armed.
	IsArmed() bool

	// ArmedFabricIndex returns the fabric index that armed the fail-safe.
	// Returns 0 if not armed.
	ArmedFabricIndex() fabric.FabricIndex

	// Arm arms the fail-safe timer for the specified duration.
	// Returns an error if the fail-safe is already armed by a different fabric.
	Arm(fabricIndex fabric.FabricIndex, expirySeconds uint16) error

	// Disarm disarms the fail-safe timer.
	// Can only be called by the fabric that armed it.
	Disarm(fabricIndex fabric.FabricIndex) error

	// ExtendArm extends the fail-safe timer.
	// Can only be called by the fabric that armed it.
	ExtendArm(fabricIndex fabric.FabricIndex, expirySeconds uint16) error

	// Complete marks commissioning as complete.
	// This is called when CommissioningComplete command succeeds.
	Complete(fabricIndex fabric.FabricIndex) error
}

// CommissioningWindowManager provides commissioning window state.
type CommissioningWindowManager interface {
	// IsCommissioningWindowOpen returns true if the commissioning window is open.
	IsCommissioningWindowOpen() bool
}

// Config provides dependencies for the General Commissioning cluster.
type Config struct {
	// EndpointID is the endpoint this cluster belongs to (should be 0).
	EndpointID datamodel.EndpointID

	// BasicCommissioningInfo provides commissioning timing parameters.
	BasicCommissioningInfo BasicCommissioningInfo

	// LocationCapability indicates the regulatory location capability.
	LocationCapability RegulatoryLocationType

	// SupportsConcurrentConnection indicates concurrent connection support.
	SupportsConcurrentConnection bool

	// FailSafeManager provides fail-safe context management.
	// Required for ArmFailSafe and CommissioningComplete commands.
	FailSafeManager FailSafeManager

	// CommissioningWindowManager provides commissioning window state.
	// Optional - if nil, commissioning window is assumed closed.
	CommissioningWindowManager CommissioningWindowManager
}

// Cluster implements the General Commissioning cluster (0x0030).
type Cluster struct {
	*datamodel.ClusterBase
	config Config

	// Mutable state (protected by mutex)
	mu               sync.RWMutex
	breadcrumb       uint64
	regulatoryConfig RegulatoryLocationType

	// Cached attribute list (built on construction)
	attrList []datamodel.AttributeEntry
}

// New creates a new General Commissioning cluster.
func New(cfg Config) *Cluster {
	c := &Cluster{
		ClusterBase:      datamodel.NewClusterBase(ClusterID, cfg.EndpointID, ClusterRevision),
		config:           cfg,
		breadcrumb:       0,
		regulatoryConfig: cfg.LocationCapability, // Default to capability
	}

	// Build attribute list
	c.attrList = c.buildAttributeList()

	return c
}

// buildAttributeList constructs the list of supported attributes.
func (c *Cluster) buildAttributeList() []datamodel.AttributeEntry {
	viewPriv := datamodel.PrivilegeView
	adminPriv := datamodel.PrivilegeAdminister

	attrs := []datamodel.AttributeEntry{
		// Mandatory attributes
		datamodel.NewReadWriteAttribute(AttrBreadcrumb, 0, viewPriv, adminPriv),
		datamodel.NewReadOnlyAttribute(AttrBasicCommissioningInfo, datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrRegulatoryConfig, 0, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrLocationCapability, datamodel.AttrQualityFixed, viewPriv),
		datamodel.NewReadOnlyAttribute(AttrSupportsConcurrentConnection, datamodel.AttrQualityFixed, viewPriv),
	}

	// Add global attributes
	return datamodel.MergeAttributeLists(attrs)
}

// AttributeList implements datamodel.Cluster.
func (c *Cluster) AttributeList() []datamodel.AttributeEntry {
	return c.attrList
}

// AcceptedCommandList implements datamodel.Cluster.
func (c *Cluster) AcceptedCommandList() []datamodel.CommandEntry {
	adminPriv := datamodel.PrivilegeAdminister

	return []datamodel.CommandEntry{
		datamodel.NewCommandEntry(CmdArmFailSafe, 0, adminPriv),
		datamodel.NewCommandEntry(CmdSetRegulatoryConfig, 0, adminPriv),
		datamodel.NewCommandEntry(CmdCommissioningComplete, datamodel.CmdQualityFabricScoped, adminPriv),
	}
}

// GeneratedCommandList implements datamodel.Cluster.
func (c *Cluster) GeneratedCommandList() []datamodel.CommandID {
	return []datamodel.CommandID{
		CmdArmFailSafeResponse,
		CmdSetRegulatoryConfigResponse,
		CmdCommissioningCompleteResp,
	}
}

// ReadAttribute implements datamodel.Cluster.
func (c *Cluster) ReadAttribute(ctx context.Context, req datamodel.ReadAttributeRequest, w *tlv.Writer) error {
	// Handle global attributes first
	handled, err := c.ReadGlobalAttribute(ctx, req.Path.Attribute, w,
		c.attrList, c.AcceptedCommandList(), c.GeneratedCommandList())
	if handled || err != nil {
		return err
	}

	switch req.Path.Attribute {
	case AttrBreadcrumb:
		c.mu.RLock()
		defer c.mu.RUnlock()
		return w.PutUint(tlv.Anonymous(), c.breadcrumb)

	case AttrBasicCommissioningInfo:
		return c.readBasicCommissioningInfo(w)

	case AttrRegulatoryConfig:
		c.mu.RLock()
		defer c.mu.RUnlock()
		return w.PutUint(tlv.Anonymous(), uint64(c.regulatoryConfig))

	case AttrLocationCapability:
		return w.PutUint(tlv.Anonymous(), uint64(c.config.LocationCapability))

	case AttrSupportsConcurrentConnection:
		return w.PutBool(tlv.Anonymous(), c.config.SupportsConcurrentConnection)

	default:
		return datamodel.ErrUnsupportedAttribute
	}
}

// readBasicCommissioningInfo writes the BasicCommissioningInfo struct.
func (c *Cluster) readBasicCommissioningInfo(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	// FailSafeExpiryLengthSeconds (field 0)
	if err := w.PutUint(tlv.ContextTag(0), uint64(c.config.BasicCommissioningInfo.FailSafeExpiryLengthSeconds)); err != nil {
		return err
	}

	// MaxCumulativeFailsafeSeconds (field 1)
	if err := w.PutUint(tlv.ContextTag(1), uint64(c.config.BasicCommissioningInfo.MaxCumulativeFailsafeSeconds)); err != nil {
		return err
	}

	return w.EndContainer()
}

// WriteAttribute implements datamodel.Cluster.
func (c *Cluster) WriteAttribute(ctx context.Context, req datamodel.WriteAttributeRequest, r *tlv.Reader) error {
	switch req.Path.Attribute {
	case AttrBreadcrumb:
		return c.writeBreadcrumb(r)
	default:
		return datamodel.ErrUnsupportedWrite
	}
}

// writeBreadcrumb handles writing the Breadcrumb attribute.
func (c *Cluster) writeBreadcrumb(r *tlv.Reader) error {
	if err := r.Next(); err != nil {
		return err
	}

	val, err := r.Uint()
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.breadcrumb = val
	c.mu.Unlock()

	c.IncrementDataVersion()
	return nil
}

// InvokeCommand implements datamodel.Cluster.
func (c *Cluster) InvokeCommand(ctx context.Context, req datamodel.InvokeRequest, r *tlv.Reader) ([]byte, error) {
	switch req.Path.Command {
	case CmdArmFailSafe:
		return c.handleArmFailSafe(ctx, req, r)
	case CmdSetRegulatoryConfig:
		return c.handleSetRegulatoryConfig(ctx, req, r)
	case CmdCommissioningComplete:
		return c.handleCommissioningComplete(ctx, req, r)
	default:
		return nil, datamodel.ErrUnsupportedCommand
	}
}

// GetBreadcrumb returns the current breadcrumb value.
func (c *Cluster) GetBreadcrumb() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.breadcrumb
}

// SetBreadcrumb sets the breadcrumb value.
// This is also called by fail-safe expiry to reset to 0.
func (c *Cluster) SetBreadcrumb(value uint64) {
	c.mu.Lock()
	c.breadcrumb = value
	c.mu.Unlock()
	c.IncrementDataVersion()
}

// GetRegulatoryConfig returns the current regulatory configuration.
func (c *Cluster) GetRegulatoryConfig() RegulatoryLocationType {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.regulatoryConfig
}

// Errors for commissioning operations.
var (
	ErrFailSafeNotArmed       = errors.New("fail-safe not armed")
	ErrBusyWithOtherAdmin     = errors.New("busy with other admin")
	ErrCommissioningNotActive = errors.New("commissioning not active")
)
