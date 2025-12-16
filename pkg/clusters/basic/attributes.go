package basic

import (
	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/tlv"
)

// readCapabilityMinima writes the CapabilityMinima attribute (0x0013).
// This is a struct with two uint16 fields.
//
// Spec: Section 11.1.4.4, 11.1.5.20
func (c *Cluster) readCapabilityMinima(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	// CaseSessionsPerFabric (field 0)
	if err := w.PutUint(tlv.ContextTag(0), uint64(c.config.DeviceInfo.CapabilityMinima.CaseSessionsPerFabric)); err != nil {
		return err
	}

	// SubscriptionsPerFabric (field 1)
	if err := w.PutUint(tlv.ContextTag(1), uint64(c.config.DeviceInfo.CapabilityMinima.SubscriptionsPerFabric)); err != nil {
		return err
	}

	return w.EndContainer()
}

// readProductAppearance writes the ProductAppearance attribute (0x0014).
// This is an optional struct with finish and optional primary color.
//
// Spec: Section 11.1.4.3, 11.1.5.21
func (c *Cluster) readProductAppearance(w *tlv.Writer) error {
	if c.config.DeviceInfo.ProductAppearance == nil {
		return datamodel.ErrUnsupportedAttribute
	}

	appearance := c.config.DeviceInfo.ProductAppearance

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	// Finish (field 0)
	if err := w.PutUint(tlv.ContextTag(0), uint64(appearance.Finish)); err != nil {
		return err
	}

	// PrimaryColor (field 1) - nullable
	if appearance.PrimaryColor != nil {
		if err := w.PutUint(tlv.ContextTag(1), uint64(*appearance.PrimaryColor)); err != nil {
			return err
		}
	} else {
		if err := w.PutNull(tlv.ContextTag(1)); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// writeNodeLabel handles writing the NodeLabel attribute.
// Max length is 32 characters.
//
// Spec: Section 11.1.5.6
func (c *Cluster) writeNodeLabel(r *tlv.Reader) error {
	// Read the value
	if err := r.Next(); err != nil {
		return err
	}

	label, err := r.String()
	if err != nil {
		return err
	}

	// Validate length constraint
	if len(label) > 32 {
		return datamodel.ErrConstraintError
	}

	// Update state
	c.mu.Lock()
	c.nodeLabel = label
	c.mu.Unlock()

	// Persist
	if c.config.Storage != nil {
		if err := c.config.Storage.StoreNodeLabel(label); err != nil {
			return err
		}
	}

	c.IncrementDataVersion()
	return nil
}

// writeLocation handles writing the Location attribute.
// Must be exactly 2 characters (ISO 3166-1 alpha-2).
//
// Spec: Section 11.1.5.7
func (c *Cluster) writeLocation(r *tlv.Reader) error {
	// Read the value
	if err := r.Next(); err != nil {
		return err
	}

	location, err := r.String()
	if err != nil {
		return err
	}

	// Validate length constraint - must be exactly 2 chars
	if len(location) != 2 {
		return datamodel.ErrConstraintError
	}

	// Update state
	c.mu.Lock()
	c.location = location
	c.mu.Unlock()

	// Persist
	if c.config.Storage != nil {
		if err := c.config.Storage.StoreLocation(location); err != nil {
			return err
		}
	}

	c.IncrementDataVersion()
	return nil
}

// writeLocalConfigDisabled handles writing the LocalConfigDisabled attribute.
//
// Spec: Section 11.1.5.17
func (c *Cluster) writeLocalConfigDisabled(r *tlv.Reader) error {
	// Read the value
	if err := r.Next(); err != nil {
		return err
	}

	disabled, err := r.Bool()
	if err != nil {
		return err
	}

	// Update state
	c.mu.Lock()
	c.localConfigDisabled = disabled
	c.mu.Unlock()

	// Persist
	if c.config.Storage != nil {
		if err := c.config.Storage.StoreLocalConfigDisabled(disabled); err != nil {
			return err
		}
	}

	c.IncrementDataVersion()
	return nil
}
