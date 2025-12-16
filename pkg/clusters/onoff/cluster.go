// Package onoff implements the On/Off Cluster (0x0006).
//
// The On/Off cluster provides commands and attributes to control
// an on/off state, such as a light switch or power outlet.
//
// This is a commonly used application cluster for Matter devices.
//
// C++ Reference: src/app/clusters/on-off-server/codegen/on-off-server.cpp
package onoff

import (
	"context"
	"sync"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/tlv"
)

// Cluster constants.
const (
	ClusterID       datamodel.ClusterID = 0x0006
	ClusterRevision uint16              = 6
)

// Attribute IDs.
const (
	AttrOnOff              datamodel.AttributeID = 0x0000
	AttrGlobalSceneControl datamodel.AttributeID = 0x4000
	AttrOnTime             datamodel.AttributeID = 0x4001
	AttrOffWaitTime        datamodel.AttributeID = 0x4002
	AttrStartUpOnOff       datamodel.AttributeID = 0x4003
)

// Command IDs.
const (
	CmdOff                      datamodel.CommandID = 0x00
	CmdOn                       datamodel.CommandID = 0x01
	CmdToggle                   datamodel.CommandID = 0x02
	CmdOffWithEffect            datamodel.CommandID = 0x40
	CmdOnWithRecallGlobalScene  datamodel.CommandID = 0x41
	CmdOnWithTimedOff           datamodel.CommandID = 0x42
)

// Feature bits.
type Feature uint32

const (
	// FeatureLighting indicates support for lighting applications.
	// Enables GlobalSceneControl, OnTime, OffWaitTime, StartUpOnOff attributes.
	FeatureLighting Feature = 1 << 0 // LT

	// FeatureDeadFrontBehavior indicates dead front behavior support.
	FeatureDeadFrontBehavior Feature = 1 << 1 // DF

	// FeatureOffOnly indicates the device can only be turned off, not on.
	FeatureOffOnly Feature = 1 << 2 // OFFONLY
)

// StartUpOnOff indicates the startup behavior.
type StartUpOnOff uint8

const (
	// StartUpOnOffOff sets OnOff to false on startup.
	StartUpOnOffOff StartUpOnOff = 0

	// StartUpOnOffOn sets OnOff to true on startup.
	StartUpOnOffOn StartUpOnOff = 1

	// StartUpOnOffToggle toggles the previous value on startup.
	StartUpOnOffToggle StartUpOnOff = 2

	// StartUpOnOffPrevious restores the previous value on startup.
	StartUpOnOffPrevious StartUpOnOff = 0xFF
)

// String returns the name of the startup behavior.
func (s StartUpOnOff) String() string {
	switch s {
	case StartUpOnOffOff:
		return "Off"
	case StartUpOnOffOn:
		return "On"
	case StartUpOnOffToggle:
		return "Toggle"
	case StartUpOnOffPrevious:
		return "Previous"
	default:
		return "Unknown"
	}
}

// EffectIdentifier identifies the effect to apply when turning off.
type EffectIdentifier uint8

const (
	EffectDelayedAllOff EffectIdentifier = 0
	EffectDyingLight    EffectIdentifier = 1
)

// String returns the name of the effect identifier.
func (e EffectIdentifier) String() string {
	switch e {
	case EffectDelayedAllOff:
		return "DelayedAllOff"
	case EffectDyingLight:
		return "DyingLight"
	default:
		return "Unknown"
	}
}

// Storage provides persistence for On/Off cluster state.
type Storage interface {
	// Load retrieves a value by key.
	Load(key string) ([]byte, error)
	// Store persists a value.
	Store(key string, value []byte) error
}

// StateChangeCallback is called when the on/off state changes.
type StateChangeCallback func(endpoint datamodel.EndpointID, newState bool)

// Config provides dependencies for the On/Off cluster.
type Config struct {
	// EndpointID is the endpoint this cluster belongs to.
	EndpointID datamodel.EndpointID

	// FeatureMap indicates supported features.
	FeatureMap Feature

	// Storage for persisting state (optional).
	// If nil, state is not persisted.
	Storage Storage

	// OnStateChange callback when state changes (optional).
	OnStateChange StateChangeCallback

	// InitialOnOff is the initial on/off state if no persisted value exists.
	InitialOnOff bool
}

// Cluster implements the On/Off cluster (0x0006).
type Cluster struct {
	*datamodel.ClusterBase
	config Config

	// Mutable state (protected by mutex)
	mu    sync.RWMutex
	onOff bool

	// Lighting feature attributes (LT)
	globalSceneControl bool
	onTime             uint16
	offWaitTime        uint16
	startUpOnOff       *StartUpOnOff // nullable

	// Cached attribute list
	attrList []datamodel.AttributeEntry
}

// New creates a new On/Off cluster.
func New(cfg Config) *Cluster {
	c := &Cluster{
		ClusterBase:        datamodel.NewClusterBase(ClusterID, cfg.EndpointID, ClusterRevision),
		config:             cfg,
		onOff:              cfg.InitialOnOff,
		globalSceneControl: true, // Default per spec
		onTime:             0,
		offWaitTime:        0,
	}

	// Set feature map
	c.ClusterBase.SetFeatureMap(uint32(cfg.FeatureMap))

	// Load persisted state if storage available
	if cfg.Storage != nil {
		c.loadPersistedState()
	}

	// Build attribute list
	c.attrList = c.buildAttributeList()

	return c
}

// loadPersistedState loads state from storage.
func (c *Cluster) loadPersistedState() {
	if c.config.Storage == nil {
		return
	}

	// Load OnOff
	if data, err := c.config.Storage.Load("onoff"); err == nil && len(data) == 1 {
		c.onOff = data[0] != 0
	}

	// Load StartUpOnOff if lighting feature enabled
	if c.config.FeatureMap&FeatureLighting != 0 {
		if data, err := c.config.Storage.Load("startupOnOff"); err == nil && len(data) == 1 {
			val := StartUpOnOff(data[0])
			c.startUpOnOff = &val
		}
	}
}

// saveOnOff persists the on/off state.
func (c *Cluster) saveOnOff() {
	if c.config.Storage == nil {
		return
	}
	val := byte(0)
	if c.onOff {
		val = 1
	}
	_ = c.config.Storage.Store("onoff", []byte{val})
}

// buildAttributeList constructs the list of supported attributes.
func (c *Cluster) buildAttributeList() []datamodel.AttributeEntry {
	viewPriv := datamodel.PrivilegeView
	managePriv := datamodel.PrivilegeManage

	attrs := []datamodel.AttributeEntry{
		// Mandatory attribute
		datamodel.NewReadOnlyAttribute(AttrOnOff, 0, viewPriv),
	}

	// Lighting feature attributes
	if c.config.FeatureMap&FeatureLighting != 0 {
		attrs = append(attrs,
			datamodel.NewReadOnlyAttribute(AttrGlobalSceneControl, 0, viewPriv),
			datamodel.NewReadWriteAttribute(AttrOnTime, 0, viewPriv, managePriv),
			datamodel.NewReadWriteAttribute(AttrOffWaitTime, 0, viewPriv, managePriv),
			datamodel.NewReadWriteAttribute(AttrStartUpOnOff, datamodel.AttrQualityNullable|datamodel.AttrQualityNonVolatile, viewPriv, managePriv),
		)
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
	operatePriv := datamodel.PrivilegeOperate

	cmds := []datamodel.CommandEntry{
		datamodel.NewCommandEntry(CmdOff, 0, operatePriv),
		datamodel.NewCommandEntry(CmdOn, 0, operatePriv),
		datamodel.NewCommandEntry(CmdToggle, 0, operatePriv),
	}

	// Lighting feature commands
	if c.config.FeatureMap&FeatureLighting != 0 {
		cmds = append(cmds,
			datamodel.NewCommandEntry(CmdOffWithEffect, 0, operatePriv),
			datamodel.NewCommandEntry(CmdOnWithRecallGlobalScene, 0, operatePriv),
			datamodel.NewCommandEntry(CmdOnWithTimedOff, 0, operatePriv),
		)
	}

	return cmds
}

// GeneratedCommandList implements datamodel.Cluster.
func (c *Cluster) GeneratedCommandList() []datamodel.CommandID {
	// On/Off cluster doesn't generate response commands
	return nil
}

// ReadAttribute implements datamodel.Cluster.
func (c *Cluster) ReadAttribute(ctx context.Context, req datamodel.ReadAttributeRequest, w *tlv.Writer) error {
	// Handle global attributes first
	handled, err := c.ReadGlobalAttribute(ctx, req.Path.Attribute, w,
		c.attrList, c.AcceptedCommandList(), c.GeneratedCommandList())
	if handled || err != nil {
		return err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	switch req.Path.Attribute {
	case AttrOnOff:
		return w.PutBool(tlv.Anonymous(), c.onOff)

	case AttrGlobalSceneControl:
		if c.config.FeatureMap&FeatureLighting == 0 {
			return datamodel.ErrUnsupportedAttribute
		}
		return w.PutBool(tlv.Anonymous(), c.globalSceneControl)

	case AttrOnTime:
		if c.config.FeatureMap&FeatureLighting == 0 {
			return datamodel.ErrUnsupportedAttribute
		}
		return w.PutUint(tlv.Anonymous(), uint64(c.onTime))

	case AttrOffWaitTime:
		if c.config.FeatureMap&FeatureLighting == 0 {
			return datamodel.ErrUnsupportedAttribute
		}
		return w.PutUint(tlv.Anonymous(), uint64(c.offWaitTime))

	case AttrStartUpOnOff:
		if c.config.FeatureMap&FeatureLighting == 0 {
			return datamodel.ErrUnsupportedAttribute
		}
		if c.startUpOnOff == nil {
			return w.PutNull(tlv.Anonymous())
		}
		return w.PutUint(tlv.Anonymous(), uint64(*c.startUpOnOff))

	default:
		return datamodel.ErrUnsupportedAttribute
	}
}

// WriteAttribute implements datamodel.Cluster.
func (c *Cluster) WriteAttribute(ctx context.Context, req datamodel.WriteAttributeRequest, r *tlv.Reader) error {
	switch req.Path.Attribute {
	case AttrOnTime:
		return c.writeOnTime(r)
	case AttrOffWaitTime:
		return c.writeOffWaitTime(r)
	case AttrStartUpOnOff:
		return c.writeStartUpOnOff(r)
	default:
		return datamodel.ErrUnsupportedWrite
	}
}

// writeOnTime handles writing the OnTime attribute.
func (c *Cluster) writeOnTime(r *tlv.Reader) error {
	if c.config.FeatureMap&FeatureLighting == 0 {
		return datamodel.ErrUnsupportedWrite
	}

	if err := r.Next(); err != nil {
		return err
	}

	val, err := r.Uint()
	if err != nil {
		return err
	}

	if val > 0xFFFE {
		return datamodel.ErrConstraintError
	}

	c.mu.Lock()
	c.onTime = uint16(val)
	c.mu.Unlock()

	c.IncrementDataVersion()
	return nil
}

// writeOffWaitTime handles writing the OffWaitTime attribute.
func (c *Cluster) writeOffWaitTime(r *tlv.Reader) error {
	if c.config.FeatureMap&FeatureLighting == 0 {
		return datamodel.ErrUnsupportedWrite
	}

	if err := r.Next(); err != nil {
		return err
	}

	val, err := r.Uint()
	if err != nil {
		return err
	}

	if val > 0xFFFE {
		return datamodel.ErrConstraintError
	}

	c.mu.Lock()
	c.offWaitTime = uint16(val)
	c.mu.Unlock()

	c.IncrementDataVersion()
	return nil
}

// writeStartUpOnOff handles writing the StartUpOnOff attribute.
func (c *Cluster) writeStartUpOnOff(r *tlv.Reader) error {
	if c.config.FeatureMap&FeatureLighting == 0 {
		return datamodel.ErrUnsupportedWrite
	}

	if err := r.Next(); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if r.Type() == tlv.ElementTypeNull {
		c.startUpOnOff = nil
	} else {
		val, err := r.Uint()
		if err != nil {
			return err
		}
		// Validate: 0, 1, 2, or 0xFF
		if val > 2 && val != 0xFF {
			return datamodel.ErrConstraintError
		}
		s := StartUpOnOff(val)
		c.startUpOnOff = &s

		// Persist
		if c.config.Storage != nil {
			_ = c.config.Storage.Store("startupOnOff", []byte{byte(s)})
		}
	}

	c.IncrementDataVersion()
	return nil
}

// InvokeCommand implements datamodel.Cluster.
func (c *Cluster) InvokeCommand(ctx context.Context, req datamodel.InvokeRequest, r *tlv.Reader) ([]byte, error) {
	switch req.Path.Command {
	case CmdOff:
		return nil, c.handleOff()
	case CmdOn:
		return nil, c.handleOn()
	case CmdToggle:
		return nil, c.handleToggle()
	case CmdOffWithEffect:
		return nil, c.handleOffWithEffect(r)
	case CmdOnWithRecallGlobalScene:
		return nil, c.handleOnWithRecallGlobalScene()
	case CmdOnWithTimedOff:
		return nil, c.handleOnWithTimedOff(r)
	default:
		return nil, datamodel.ErrUnsupportedCommand
	}
}

// handleOff handles the Off command.
func (c *Cluster) handleOff() error {
	c.setOnOff(false)
	return nil
}

// handleOn handles the On command.
func (c *Cluster) handleOn() error {
	// Check OffOnly feature - if set, On command is not supported
	if c.config.FeatureMap&FeatureOffOnly != 0 {
		return datamodel.ErrUnsupportedCommand
	}

	c.setOnOff(true)

	// Per spec: when turning on with lighting feature
	if c.config.FeatureMap&FeatureLighting != 0 {
		c.mu.Lock()
		if c.onTime == 0 {
			c.offWaitTime = 0
		}
		c.globalSceneControl = true
		c.mu.Unlock()
	}

	return nil
}

// handleToggle handles the Toggle command.
func (c *Cluster) handleToggle() error {
	c.mu.RLock()
	currentState := c.onOff
	c.mu.RUnlock()

	if currentState {
		return c.handleOff()
	}
	return c.handleOn()
}

// handleOffWithEffect handles the OffWithEffect command.
func (c *Cluster) handleOffWithEffect(r *tlv.Reader) error {
	if c.config.FeatureMap&FeatureLighting == 0 {
		return datamodel.ErrUnsupportedCommand
	}

	// Decode the command
	var effectID EffectIdentifier
	var effectVariant uint8

	if err := r.Next(); err != nil {
		return err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return datamodel.ErrInvalidCommand
	}
	if err := r.EnterContainer(); err != nil {
		return err
	}

	for {
		if err := r.Next(); err != nil {
			break
		}
		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}
		switch tag.TagNumber() {
		case 0: // EffectIdentifier
			val, err := r.Uint()
			if err != nil {
				return err
			}
			effectID = EffectIdentifier(val)
		case 1: // EffectVariant
			val, err := r.Uint()
			if err != nil {
				return err
			}
			effectVariant = uint8(val)
		}
	}
	_ = r.ExitContainer()

	// Store the effect for potential use
	_ = effectID
	_ = effectVariant

	// Set GlobalSceneControl to false
	c.mu.Lock()
	c.globalSceneControl = false
	c.mu.Unlock()

	// Turn off
	c.setOnOff(false)

	return nil
}

// handleOnWithRecallGlobalScene handles the OnWithRecallGlobalScene command.
func (c *Cluster) handleOnWithRecallGlobalScene() error {
	if c.config.FeatureMap&FeatureLighting == 0 {
		return datamodel.ErrUnsupportedCommand
	}

	c.mu.Lock()
	// If GlobalSceneControl is true, do nothing
	if c.globalSceneControl {
		c.mu.Unlock()
		return nil
	}
	c.globalSceneControl = true
	c.mu.Unlock()

	// Turn on and recall global scene (simplified - just turn on)
	c.setOnOff(true)

	return nil
}

// handleOnWithTimedOff handles the OnWithTimedOff command.
func (c *Cluster) handleOnWithTimedOff(r *tlv.Reader) error {
	if c.config.FeatureMap&FeatureLighting == 0 {
		return datamodel.ErrUnsupportedCommand
	}

	// Decode the command
	var onOffControl uint8
	var onTime uint16
	var offWaitTime uint16

	if err := r.Next(); err != nil {
		return err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return datamodel.ErrInvalidCommand
	}
	if err := r.EnterContainer(); err != nil {
		return err
	}

	for {
		if err := r.Next(); err != nil {
			break
		}
		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}
		switch tag.TagNumber() {
		case 0: // OnOffControl
			val, err := r.Uint()
			if err != nil {
				return err
			}
			onOffControl = uint8(val)
		case 1: // OnTime
			val, err := r.Uint()
			if err != nil {
				return err
			}
			onTime = uint16(val)
		case 2: // OffWaitTime
			val, err := r.Uint()
			if err != nil {
				return err
			}
			offWaitTime = uint16(val)
		}
	}
	_ = r.ExitContainer()

	// AcceptOnlyWhenOn bit check (bit 0)
	acceptOnlyWhenOn := (onOffControl & 0x01) != 0

	c.mu.Lock()
	defer c.mu.Unlock()

	// If AcceptOnlyWhenOn is set and device is off, reject
	if acceptOnlyWhenOn && !c.onOff {
		return nil // No error, just no-op
	}

	// Set OnTime and OffWaitTime
	if c.onOff {
		// Already on - use max of current and new values
		if onTime > c.onTime {
			c.onTime = onTime
		}
	} else {
		// Turning on
		c.onTime = onTime
	}
	c.offWaitTime = offWaitTime

	// Turn on (will unlock then relock)
	c.mu.Unlock()
	c.setOnOff(true)
	c.mu.Lock()

	c.globalSceneControl = true

	return nil
}

// setOnOff sets the on/off state and triggers callbacks.
func (c *Cluster) setOnOff(newState bool) {
	c.mu.Lock()
	oldState := c.onOff
	if oldState == newState {
		c.mu.Unlock()
		return
	}
	c.onOff = newState
	c.mu.Unlock()

	// Persist
	c.saveOnOff()

	// Increment data version
	c.IncrementDataVersion()

	// Callback
	if c.config.OnStateChange != nil {
		c.config.OnStateChange(c.config.EndpointID, newState)
	}
}

// GetOnOff returns the current on/off state.
func (c *Cluster) GetOnOff() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.onOff
}

// SetOnOff sets the on/off state directly (for external control).
func (c *Cluster) SetOnOff(newState bool) {
	c.setOnOff(newState)
}
