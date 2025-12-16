package generalcommissioning

import (
	"bytes"
	"context"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/tlv"
)

// ArmFailSafeRequest represents the ArmFailSafe command request (Spec 11.10.7.2).
type ArmFailSafeRequest struct {
	ExpiryLengthSeconds uint16
	Breadcrumb          uint64
}

// ArmFailSafeResponse represents the ArmFailSafe command response (Spec 11.10.7.3).
type ArmFailSafeResponse struct {
	ErrorCode CommissioningErrorCode
	DebugText string
}

// SetRegulatoryConfigRequest represents the SetRegulatoryConfig command request (Spec 11.10.7.4).
type SetRegulatoryConfigRequest struct {
	NewRegulatoryConfig RegulatoryLocationType
	CountryCode         string
	Breadcrumb          uint64
}

// SetRegulatoryConfigResponse represents the SetRegulatoryConfig command response (Spec 11.10.7.5).
type SetRegulatoryConfigResponse struct {
	ErrorCode CommissioningErrorCode
	DebugText string
}

// CommissioningCompleteResponse represents the CommissioningComplete response (Spec 11.10.7.7).
type CommissioningCompleteResponse struct {
	ErrorCode CommissioningErrorCode
	DebugText string
}

// handleArmFailSafe handles the ArmFailSafe command.
//
// Spec: Section 11.10.7.2
func (c *Cluster) handleArmFailSafe(ctx context.Context, req datamodel.InvokeRequest, r *tlv.Reader) ([]byte, error) {
	// Decode request
	var armReq ArmFailSafeRequest
	if err := decodeArmFailSafeRequest(r, &armReq); err != nil {
		return nil, err
	}

	fabricIndex := req.FabricIndex()

	var errorCode CommissioningErrorCode
	var debugText string

	// Check if fail-safe manager is available
	if c.config.FailSafeManager == nil {
		// No fail-safe manager - accept but do nothing
		errorCode = CommissioningOK
	} else {
		// Check commissioning window and CASE session constraints
		// If fail-safe not armed, commissioning window open, and this is CASE session,
		// return BusyWithOtherAdmin to let PASE commissioners use the window
		if !c.config.FailSafeManager.IsArmed() &&
			c.config.CommissioningWindowManager != nil &&
			c.config.CommissioningWindowManager.IsCommissioningWindowOpen() {
			// For now we'll accept - full session type checking would require
			// access to the session context
		}

		if armReq.ExpiryLengthSeconds == 0 {
			// Disarm the fail-safe
			if c.config.FailSafeManager.IsArmed() {
				if c.config.FailSafeManager.ArmedFabricIndex() == fabricIndex {
					if err := c.config.FailSafeManager.Disarm(fabricIndex); err != nil {
						errorCode = CommissioningNoFailSafe
						debugText = err.Error()
					} else {
						errorCode = CommissioningOK
					}
				} else {
					// Armed by different fabric
					errorCode = CommissioningBusyWithOtherAdmin
					debugText = "fail-safe armed by different fabric"
				}
			} else {
				// Not armed - success with no side-effects
				errorCode = CommissioningOK
			}
		} else {
			// Arm or re-arm the fail-safe
			if c.config.FailSafeManager.IsArmed() {
				// Already armed - check if same fabric
				if c.config.FailSafeManager.ArmedFabricIndex() == fabricIndex {
					// Re-arm
					if err := c.config.FailSafeManager.ExtendArm(fabricIndex, armReq.ExpiryLengthSeconds); err != nil {
						errorCode = CommissioningNoFailSafe
						debugText = err.Error()
					} else {
						errorCode = CommissioningOK
					}
				} else {
					// Different fabric
					errorCode = CommissioningBusyWithOtherAdmin
					debugText = "fail-safe armed by different fabric"
				}
			} else {
				// Arm new fail-safe
				if err := c.config.FailSafeManager.Arm(fabricIndex, armReq.ExpiryLengthSeconds); err != nil {
					errorCode = CommissioningNoFailSafe
					debugText = err.Error()
				} else {
					errorCode = CommissioningOK
				}
			}
		}
	}

	// Update breadcrumb on success
	if errorCode == CommissioningOK {
		c.SetBreadcrumb(armReq.Breadcrumb)
	}

	// Encode response
	return encodeArmFailSafeResponse(ArmFailSafeResponse{
		ErrorCode: errorCode,
		DebugText: debugText,
	})
}

// handleSetRegulatoryConfig handles the SetRegulatoryConfig command.
//
// Spec: Section 11.10.7.4
func (c *Cluster) handleSetRegulatoryConfig(ctx context.Context, req datamodel.InvokeRequest, r *tlv.Reader) ([]byte, error) {
	// Decode request
	var setReq SetRegulatoryConfigRequest
	if err := decodeSetRegulatoryConfigRequest(r, &setReq); err != nil {
		return nil, err
	}

	var errorCode CommissioningErrorCode
	var debugText string

	// Validate the new regulatory config against location capability
	if setReq.NewRegulatoryConfig > c.config.LocationCapability {
		if c.config.LocationCapability == RegulatoryIndoor && setReq.NewRegulatoryConfig == RegulatoryOutdoor {
			errorCode = CommissioningValueOutsideRange
			debugText = "device is indoor only"
		} else if c.config.LocationCapability == RegulatoryOutdoor && setReq.NewRegulatoryConfig == RegulatoryIndoor {
			errorCode = CommissioningValueOutsideRange
			debugText = "device is outdoor only"
		}
	}

	if errorCode == CommissioningOK {
		// Update the regulatory config
		c.mu.Lock()
		c.regulatoryConfig = setReq.NewRegulatoryConfig
		c.mu.Unlock()

		// Update breadcrumb
		c.SetBreadcrumb(setReq.Breadcrumb)
	}

	// Encode response
	return encodeSetRegulatoryConfigResponse(SetRegulatoryConfigResponse{
		ErrorCode: errorCode,
		DebugText: debugText,
	})
}

// handleCommissioningComplete handles the CommissioningComplete command.
//
// Spec: Section 11.10.7.6
func (c *Cluster) handleCommissioningComplete(ctx context.Context, req datamodel.InvokeRequest, r *tlv.Reader) ([]byte, error) {
	fabricIndex := req.FabricIndex()

	var errorCode CommissioningErrorCode
	var debugText string

	// Check fail-safe state
	if c.config.FailSafeManager == nil {
		// No fail-safe manager - accept
		errorCode = CommissioningOK
	} else if !c.config.FailSafeManager.IsArmed() {
		errorCode = CommissioningNoFailSafe
		debugText = "fail-safe not armed"
	} else if c.config.FailSafeManager.ArmedFabricIndex() != fabricIndex {
		errorCode = CommissioningInvalidAuthentication
		debugText = "fail-safe armed by different fabric"
	} else {
		// Complete commissioning
		if err := c.config.FailSafeManager.Complete(fabricIndex); err != nil {
			errorCode = CommissioningNoFailSafe
			debugText = err.Error()
		} else {
			errorCode = CommissioningOK
		}
	}

	// Reset breadcrumb on success
	if errorCode == CommissioningOK {
		c.SetBreadcrumb(0)
	}

	// Encode response
	return encodeCommissioningCompleteResponse(CommissioningCompleteResponse{
		ErrorCode: errorCode,
		DebugText: debugText,
	})
}

// decodeArmFailSafeRequest decodes an ArmFailSafe request from TLV.
func decodeArmFailSafeRequest(r *tlv.Reader, req *ArmFailSafeRequest) error {
	// Enter the structure
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return datamodel.ErrInvalidCommand
	}

	if err := r.EnterContainer(); err != nil {
		return err
	}

	// Read fields
	for {
		if err := r.Next(); err != nil {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}

		switch tag.TagNumber() {
		case 0: // ExpiryLengthSeconds
			val, err := r.Uint()
			if err != nil {
				return err
			}
			req.ExpiryLengthSeconds = uint16(val)
		case 1: // Breadcrumb
			val, err := r.Uint()
			if err != nil {
				return err
			}
			req.Breadcrumb = val
		}
	}

	return r.ExitContainer()
}

// decodeSetRegulatoryConfigRequest decodes a SetRegulatoryConfig request from TLV.
func decodeSetRegulatoryConfigRequest(r *tlv.Reader, req *SetRegulatoryConfigRequest) error {
	// Enter the structure
	if err := r.Next(); err != nil {
		return err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return datamodel.ErrInvalidCommand
	}

	if err := r.EnterContainer(); err != nil {
		return err
	}

	// Read fields
	for {
		if err := r.Next(); err != nil {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}

		switch tag.TagNumber() {
		case 0: // NewRegulatoryConfig
			val, err := r.Uint()
			if err != nil {
				return err
			}
			req.NewRegulatoryConfig = RegulatoryLocationType(val)
		case 1: // CountryCode
			val, err := r.String()
			if err != nil {
				return err
			}
			req.CountryCode = val
		case 2: // Breadcrumb
			val, err := r.Uint()
			if err != nil {
				return err
			}
			req.Breadcrumb = val
		}
	}

	return r.ExitContainer()
}

// encodeArmFailSafeResponse encodes an ArmFailSafeResponse to TLV.
func encodeArmFailSafeResponse(resp ArmFailSafeResponse) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	// ErrorCode (field 0)
	if err := w.PutUint(tlv.ContextTag(0), uint64(resp.ErrorCode)); err != nil {
		return nil, err
	}

	// DebugText (field 1)
	if err := w.PutString(tlv.ContextTag(1), resp.DebugText); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// encodeSetRegulatoryConfigResponse encodes a SetRegulatoryConfigResponse to TLV.
func encodeSetRegulatoryConfigResponse(resp SetRegulatoryConfigResponse) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	// ErrorCode (field 0)
	if err := w.PutUint(tlv.ContextTag(0), uint64(resp.ErrorCode)); err != nil {
		return nil, err
	}

	// DebugText (field 1)
	if err := w.PutString(tlv.ContextTag(1), resp.DebugText); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// encodeCommissioningCompleteResponse encodes a CommissioningCompleteResponse to TLV.
func encodeCommissioningCompleteResponse(resp CommissioningCompleteResponse) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	// ErrorCode (field 0)
	if err := w.PutUint(tlv.ContextTag(0), uint64(resp.ErrorCode)); err != nil {
		return nil, err
	}

	// DebugText (field 1)
	if err := w.PutString(tlv.ContextTag(1), resp.DebugText); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
