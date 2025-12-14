package pase

import (
	"bytes"
	"io"

	"github.com/backkem/matter/pkg/tlv"
)

// TLV context tags for PASE messages.
const (
	// PBKDFParamRequest tags
	tagPBKDFReqInitiatorRandom    = 1
	tagPBKDFReqInitiatorSessionID = 2
	tagPBKDFReqPasscodeID         = 3
	tagPBKDFReqHasPBKDFParams     = 4
	tagPBKDFReqInitiatorMRPParams = 5

	// PBKDFParamResponse tags
	tagPBKDFRespInitiatorRandom    = 1
	tagPBKDFRespResponderRandom    = 2
	tagPBKDFRespResponderSessionID = 3
	tagPBKDFRespPBKDFParams        = 4
	tagPBKDFRespResponderMRPParams = 5

	// PBKDFParameters sub-struct tags
	tagPBKDFParamsIterations = 1
	tagPBKDFParamsSalt       = 2

	// Pake message tags
	tagPake1PA = 1
	tagPake2PB = 1
	tagPake2CB = 2
	tagPake3CA = 1
)

// MRPParameters contains MRP timing parameters for session establishment.
type MRPParameters struct {
	IdleRetransTimeout   uint32 // ms, optional (0 = not present)
	ActiveRetransTimeout uint32 // ms, optional (0 = not present)
	ActiveThreshold      uint16 // ms, optional (0 = not present)
}

// PBKDFParameters contains PBKDF configuration.
type PBKDFParameters struct {
	Iterations uint32
	Salt       []byte
}

// PBKDFParamRequest is sent by the initiator to request PBKDF parameters.
type PBKDFParamRequest struct {
	InitiatorRandom    [RandomSize]byte
	InitiatorSessionID uint16
	PasscodeID         uint16
	HasPBKDFParameters bool
	MRPParams          *MRPParameters // Optional
}

// Encode serializes the PBKDFParamRequest to TLV bytes.
func (p *PBKDFParamRequest) Encode() ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutBytes(tlv.ContextTag(tagPBKDFReqInitiatorRandom), p.InitiatorRandom[:]); err != nil {
		return nil, err
	}
	if err := w.PutUint(tlv.ContextTag(tagPBKDFReqInitiatorSessionID), uint64(p.InitiatorSessionID)); err != nil {
		return nil, err
	}
	if err := w.PutUint(tlv.ContextTag(tagPBKDFReqPasscodeID), uint64(p.PasscodeID)); err != nil {
		return nil, err
	}
	if err := w.PutBool(tlv.ContextTag(tagPBKDFReqHasPBKDFParams), p.HasPBKDFParameters); err != nil {
		return nil, err
	}

	if p.MRPParams != nil {
		if err := encodeMRPParams(w, tagPBKDFReqInitiatorMRPParams, p.MRPParams); err != nil {
			return nil, err
		}
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodePBKDFParamRequest parses a PBKDFParamRequest from TLV bytes.
func DecodePBKDFParamRequest(data []byte) (*PBKDFParamRequest, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	p := &PBKDFParamRequest{}

	// Enter structure
	if err := r.Next(); err != nil {
		return nil, err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return nil, ErrInvalidMessage
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	for {
		err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if r.Type() == tlv.ElementTypeEnd {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			continue // Skip unknown tags
		}

		switch tag.TagNumber() {
		case tagPBKDFReqInitiatorRandom:
			random, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			if len(random) != RandomSize {
				return nil, ErrInvalidRandom
			}
			copy(p.InitiatorRandom[:], random)

		case tagPBKDFReqInitiatorSessionID:
			v, err := r.Uint()
			if err != nil {
				return nil, err
			}
			p.InitiatorSessionID = uint16(v)

		case tagPBKDFReqPasscodeID:
			v, err := r.Uint()
			if err != nil {
				return nil, err
			}
			p.PasscodeID = uint16(v)

		case tagPBKDFReqHasPBKDFParams:
			v, err := r.Bool()
			if err != nil {
				return nil, err
			}
			p.HasPBKDFParameters = v

		case tagPBKDFReqInitiatorMRPParams:
			mrp, err := decodeMRPParams(r)
			if err != nil {
				return nil, err
			}
			p.MRPParams = mrp
		}
	}

	return p, nil
}

// PBKDFParamResponse is sent by the responder with PBKDF parameters.
type PBKDFParamResponse struct {
	InitiatorRandom    [RandomSize]byte
	ResponderRandom    [RandomSize]byte
	ResponderSessionID uint16
	PBKDFParams        *PBKDFParameters // Optional (nil if initiator has params)
	MRPParams          *MRPParameters   // Optional
}

// Encode serializes the PBKDFParamResponse to TLV bytes.
func (p *PBKDFParamResponse) Encode() ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutBytes(tlv.ContextTag(tagPBKDFRespInitiatorRandom), p.InitiatorRandom[:]); err != nil {
		return nil, err
	}
	if err := w.PutBytes(tlv.ContextTag(tagPBKDFRespResponderRandom), p.ResponderRandom[:]); err != nil {
		return nil, err
	}
	if err := w.PutUint(tlv.ContextTag(tagPBKDFRespResponderSessionID), uint64(p.ResponderSessionID)); err != nil {
		return nil, err
	}

	if p.PBKDFParams != nil {
		if err := encodePBKDFParams(w, tagPBKDFRespPBKDFParams, p.PBKDFParams); err != nil {
			return nil, err
		}
	}

	if p.MRPParams != nil {
		if err := encodeMRPParams(w, tagPBKDFRespResponderMRPParams, p.MRPParams); err != nil {
			return nil, err
		}
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodePBKDFParamResponse parses a PBKDFParamResponse from TLV bytes.
func DecodePBKDFParamResponse(data []byte) (*PBKDFParamResponse, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	p := &PBKDFParamResponse{}

	// Enter structure
	if err := r.Next(); err != nil {
		return nil, err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return nil, ErrInvalidMessage
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	for {
		err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if r.Type() == tlv.ElementTypeEnd {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}

		switch tag.TagNumber() {
		case tagPBKDFRespInitiatorRandom:
			random, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			if len(random) != RandomSize {
				return nil, ErrInvalidRandom
			}
			copy(p.InitiatorRandom[:], random)

		case tagPBKDFRespResponderRandom:
			random, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			if len(random) != RandomSize {
				return nil, ErrInvalidRandom
			}
			copy(p.ResponderRandom[:], random)

		case tagPBKDFRespResponderSessionID:
			v, err := r.Uint()
			if err != nil {
				return nil, err
			}
			p.ResponderSessionID = uint16(v)

		case tagPBKDFRespPBKDFParams:
			params, err := decodePBKDFParams(r)
			if err != nil {
				return nil, err
			}
			p.PBKDFParams = params

		case tagPBKDFRespResponderMRPParams:
			mrp, err := decodeMRPParams(r)
			if err != nil {
				return nil, err
			}
			p.MRPParams = mrp
		}
	}

	return p, nil
}

// Pake1 contains the initiator's SPAKE2+ public share.
type Pake1 struct {
	PA []byte // 65 bytes uncompressed P-256 point
}

// Encode serializes Pake1 to TLV bytes.
func (p *Pake1) Encode() ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}
	if err := w.PutBytes(tlv.ContextTag(tagPake1PA), p.PA); err != nil {
		return nil, err
	}
	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodePake1 parses a Pake1 from TLV bytes.
func DecodePake1(data []byte) (*Pake1, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	p := &Pake1{}

	if err := r.Next(); err != nil {
		return nil, err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return nil, ErrInvalidMessage
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	for {
		err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if r.Type() == tlv.ElementTypeEnd {
			break
		}

		tag := r.Tag()
		if tag.IsContext() && tag.TagNumber() == tagPake1PA {
			pa, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			p.PA = pa
		}
	}

	if len(p.PA) == 0 {
		return nil, ErrInvalidMessage
	}

	return p, nil
}

// Pake2 contains the responder's SPAKE2+ public share and confirmation.
type Pake2 struct {
	PB []byte // 65 bytes uncompressed P-256 point
	CB []byte // 32 bytes HMAC confirmation
}

// Encode serializes Pake2 to TLV bytes.
func (p *Pake2) Encode() ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}
	if err := w.PutBytes(tlv.ContextTag(tagPake2PB), p.PB); err != nil {
		return nil, err
	}
	if err := w.PutBytes(tlv.ContextTag(tagPake2CB), p.CB); err != nil {
		return nil, err
	}
	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodePake2 parses a Pake2 from TLV bytes.
func DecodePake2(data []byte) (*Pake2, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	p := &Pake2{}

	if err := r.Next(); err != nil {
		return nil, err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return nil, ErrInvalidMessage
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	for {
		err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if r.Type() == tlv.ElementTypeEnd {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}

		switch tag.TagNumber() {
		case tagPake2PB:
			pb, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			p.PB = pb

		case tagPake2CB:
			cb, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			p.CB = cb
		}
	}

	if len(p.PB) == 0 || len(p.CB) == 0 {
		return nil, ErrInvalidMessage
	}

	return p, nil
}

// Pake3 contains the initiator's SPAKE2+ confirmation.
type Pake3 struct {
	CA []byte // 32 bytes HMAC confirmation
}

// Encode serializes Pake3 to TLV bytes.
func (p *Pake3) Encode() ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}
	if err := w.PutBytes(tlv.ContextTag(tagPake3CA), p.CA); err != nil {
		return nil, err
	}
	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodePake3 parses a Pake3 from TLV bytes.
func DecodePake3(data []byte) (*Pake3, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	p := &Pake3{}

	if err := r.Next(); err != nil {
		return nil, err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return nil, ErrInvalidMessage
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	for {
		err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if r.Type() == tlv.ElementTypeEnd {
			break
		}

		tag := r.Tag()
		if tag.IsContext() && tag.TagNumber() == tagPake3CA {
			ca, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			p.CA = ca
		}
	}

	if len(p.CA) == 0 {
		return nil, ErrInvalidMessage
	}

	return p, nil
}

// Helper functions for encoding/decoding nested structures

func encodePBKDFParams(w *tlv.Writer, tag uint8, params *PBKDFParameters) error {
	if err := w.StartStructure(tlv.ContextTag(tag)); err != nil {
		return err
	}
	if err := w.PutUint(tlv.ContextTag(tagPBKDFParamsIterations), uint64(params.Iterations)); err != nil {
		return err
	}
	if err := w.PutBytes(tlv.ContextTag(tagPBKDFParamsSalt), params.Salt); err != nil {
		return err
	}
	return w.EndContainer()
}

func decodePBKDFParams(r *tlv.Reader) (*PBKDFParameters, error) {
	if r.Type() != tlv.ElementTypeStruct {
		return nil, ErrInvalidMessage
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	params := &PBKDFParameters{}

	for {
		err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if r.Type() == tlv.ElementTypeEnd {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}

		switch tag.TagNumber() {
		case tagPBKDFParamsIterations:
			v, err := r.Uint()
			if err != nil {
				return nil, err
			}
			params.Iterations = uint32(v)

		case tagPBKDFParamsSalt:
			salt, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			params.Salt = salt
		}
	}

	if err := r.ExitContainer(); err != nil {
		return nil, err
	}

	return params, nil
}

// MRP parameter tags (SessionParameterStruct)
const (
	tagMRPIdleRetrans   = 1
	tagMRPActiveRetrans = 2
	tagMRPActiveThresh  = 4
)

func encodeMRPParams(w *tlv.Writer, tag uint8, params *MRPParameters) error {
	if err := w.StartStructure(tlv.ContextTag(tag)); err != nil {
		return err
	}

	if params.IdleRetransTimeout != 0 {
		if err := w.PutUint(tlv.ContextTag(tagMRPIdleRetrans), uint64(params.IdleRetransTimeout)); err != nil {
			return err
		}
	}
	if params.ActiveRetransTimeout != 0 {
		if err := w.PutUint(tlv.ContextTag(tagMRPActiveRetrans), uint64(params.ActiveRetransTimeout)); err != nil {
			return err
		}
	}
	if params.ActiveThreshold != 0 {
		if err := w.PutUint(tlv.ContextTag(tagMRPActiveThresh), uint64(params.ActiveThreshold)); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

func decodeMRPParams(r *tlv.Reader) (*MRPParameters, error) {
	if r.Type() != tlv.ElementTypeStruct {
		return nil, ErrInvalidMessage
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	params := &MRPParameters{}

	for {
		err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if r.Type() == tlv.ElementTypeEnd {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}

		switch tag.TagNumber() {
		case tagMRPIdleRetrans:
			v, err := r.Uint()
			if err != nil {
				return nil, err
			}
			params.IdleRetransTimeout = uint32(v)

		case tagMRPActiveRetrans:
			v, err := r.Uint()
			if err != nil {
				return nil, err
			}
			params.ActiveRetransTimeout = uint32(v)

		case tagMRPActiveThresh:
			v, err := r.Uint()
			if err != nil {
				return nil, err
			}
			params.ActiveThreshold = uint16(v)
		}
	}

	if err := r.ExitContainer(); err != nil {
		return nil, err
	}

	return params, nil
}
