package generalcommissioning

import (
	"bytes"
	"errors"

	"github.com/backkem/matter/pkg/tlv"
)

// Client-side encoding/decoding functions for GeneralCommissioning cluster commands.
// These are used by the commissioner (controller) to send commands and parse responses.

// EncodeArmFailSafeRequest encodes an ArmFailSafe request to TLV.
func EncodeArmFailSafeRequest(req *ArmFailSafeRequest) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	// ExpiryLengthSeconds (field 0)
	if err := w.PutUint(tlv.ContextTag(0), uint64(req.ExpiryLengthSeconds)); err != nil {
		return nil, err
	}

	// Breadcrumb (field 1)
	if err := w.PutUint(tlv.ContextTag(1), req.Breadcrumb); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodeArmFailSafeResponse decodes an ArmFailSafe response from TLV.
func DecodeArmFailSafeResponse(data []byte) (*ArmFailSafeResponse, error) {
	r := tlv.NewReader(bytes.NewReader(data))

	resp := &ArmFailSafeResponse{}

	// Enter structure
	if err := r.Next(); err != nil {
		return nil, err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return nil, errors.New("expected structure")
	}

	if err := r.EnterContainer(); err != nil {
		return nil, err
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
		case 0: // ErrorCode
			val, err := r.Uint()
			if err != nil {
				return nil, err
			}
			resp.ErrorCode = CommissioningErrorCode(val)
		case 1: // DebugText
			val, err := r.String()
			if err != nil {
				return nil, err
			}
			resp.DebugText = val
		}
	}

	if err := r.ExitContainer(); err != nil {
		return nil, err
	}

	return resp, nil
}

// EncodeSetRegulatoryConfigRequest encodes a SetRegulatoryConfig request to TLV.
func EncodeSetRegulatoryConfigRequest(req *SetRegulatoryConfigRequest) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	// NewRegulatoryConfig (field 0)
	if err := w.PutUint(tlv.ContextTag(0), uint64(req.NewRegulatoryConfig)); err != nil {
		return nil, err
	}

	// CountryCode (field 1)
	if err := w.PutString(tlv.ContextTag(1), req.CountryCode); err != nil {
		return nil, err
	}

	// Breadcrumb (field 2)
	if err := w.PutUint(tlv.ContextTag(2), req.Breadcrumb); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodeSetRegulatoryConfigResponse decodes a SetRegulatoryConfig response from TLV.
func DecodeSetRegulatoryConfigResponse(data []byte) (*SetRegulatoryConfigResponse, error) {
	r := tlv.NewReader(bytes.NewReader(data))

	resp := &SetRegulatoryConfigResponse{}

	// Enter structure
	if err := r.Next(); err != nil {
		return nil, err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return nil, errors.New("expected structure")
	}

	if err := r.EnterContainer(); err != nil {
		return nil, err
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
		case 0: // ErrorCode
			val, err := r.Uint()
			if err != nil {
				return nil, err
			}
			resp.ErrorCode = CommissioningErrorCode(val)
		case 1: // DebugText
			val, err := r.String()
			if err != nil {
				return nil, err
			}
			resp.DebugText = val
		}
	}

	if err := r.ExitContainer(); err != nil {
		return nil, err
	}

	return resp, nil
}

// EncodeCommissioningCompleteRequest encodes a CommissioningComplete request to TLV.
// This command has no fields, so it's an empty structure.
func EncodeCommissioningCompleteRequest() ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodeCommissioningCompleteResponse decodes a CommissioningComplete response from TLV.
func DecodeCommissioningCompleteResponse(data []byte) (*CommissioningCompleteResponse, error) {
	r := tlv.NewReader(bytes.NewReader(data))

	resp := &CommissioningCompleteResponse{}

	// Enter structure
	if err := r.Next(); err != nil {
		return nil, err
	}

	if r.Type() != tlv.ElementTypeStruct {
		return nil, errors.New("expected structure")
	}

	if err := r.EnterContainer(); err != nil {
		return nil, err
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
		case 0: // ErrorCode
			val, err := r.Uint()
			if err != nil {
				return nil, err
			}
			resp.ErrorCode = CommissioningErrorCode(val)
		case 1: // DebugText
			val, err := r.String()
			if err != nil {
				return nil, err
			}
			resp.DebugText = val
		}
	}

	if err := r.ExitContainer(); err != nil {
		return nil, err
	}

	return resp, nil
}
