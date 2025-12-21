package casesession

import (
	"bytes"
	"io"

	"github.com/backkem/matter/pkg/crypto"
	"github.com/backkem/matter/pkg/securechannel/messages"
	"github.com/backkem/matter/pkg/tlv"
)

// TLV context tags for CASE messages.
const (
	// Sigma1 tags
	tagSigma1InitiatorRandom      = 1
	tagSigma1InitiatorSessionID   = 2
	tagSigma1DestinationID        = 3
	tagSigma1InitiatorEphPubKey   = 4
	tagSigma1InitiatorSessionParams = 5
	tagSigma1ResumptionID         = 6
	tagSigma1InitiatorResumeMIC   = 7

	// Sigma2 tags
	tagSigma2ResponderRandom      = 1
	tagSigma2ResponderSessionID   = 2
	tagSigma2ResponderEphPubKey   = 3
	tagSigma2Encrypted2           = 4
	tagSigma2ResponderSessionParams = 5

	// Sigma3 tags
	tagSigma3Encrypted3 = 1

	// Sigma2Resume tags
	tagSigma2ResumeResumptionID       = 1
	tagSigma2ResumeResponderMIC       = 2
	tagSigma2ResumeResponderSessionID = 3
	tagSigma2ResumeResponderSessionParams = 4

	// TBEData2 tags (decrypted content of encrypted2)
	tagTBEData2ResponderNOC  = 1
	tagTBEData2ResponderICAC = 2
	tagTBEData2Signature     = 3
	tagTBEData2ResumptionID  = 4

	// TBSData2 tags (sigma-2-tbsdata, signed but not transmitted)
	tagTBSData2ResponderNOC       = 1
	tagTBSData2ResponderICAC      = 2
	tagTBSData2ResponderEphPubKey = 3
	tagTBSData2InitiatorEphPubKey = 4

	// TBEData3 tags (decrypted content of encrypted3)
	tagTBEData3InitiatorNOC  = 1
	tagTBEData3InitiatorICAC = 2
	tagTBEData3Signature     = 3

	// TBSData3 tags (sigma-3-tbsdata, signed but not transmitted)
	tagTBSData3InitiatorNOC       = 1
	tagTBSData3InitiatorICAC      = 2
	tagTBSData3InitiatorEphPubKey = 3
	tagTBSData3ResponderEphPubKey = 4
)

// MRP parameter tags (SessionParameterStruct) - same as PASE.
const (
	tagMRPIdleRetrans   = 1
	tagMRPActiveRetrans = 2
	tagMRPActiveThresh  = 4
)

// MRPParameters contains MRP timing parameters for session establishment.
type MRPParameters struct {
	IdleRetransTimeout   uint32 // ms, optional (0 = not present)
	ActiveRetransTimeout uint32 // ms, optional (0 = not present)
	ActiveThreshold      uint16 // ms, optional (0 = not present)
}

// Sigma1 is the first message in CASE, sent by the initiator.
type Sigma1 struct {
	InitiatorRandom    [RandomSize]byte
	InitiatorSessionID uint16
	DestinationID      [DestinationIDSize]byte
	InitiatorEphPubKey [crypto.P256PublicKeySizeBytes]byte
	MRPParams          *MRPParameters // Optional

	// Resumption fields (both must be present or both absent)
	ResumptionID       *[ResumptionIDSize]byte // Optional, for session resumption
	InitiatorResumeMIC *[MICSize]byte          // Optional, for session resumption
}

// HasResumption returns true if this Sigma1 includes resumption fields.
func (s *Sigma1) HasResumption() bool {
	return s.ResumptionID != nil && s.InitiatorResumeMIC != nil
}

// Encode serializes the Sigma1 to TLV bytes.
func (s *Sigma1) Encode() ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutBytes(tlv.ContextTag(tagSigma1InitiatorRandom), s.InitiatorRandom[:]); err != nil {
		return nil, err
	}
	if err := messages.PutSessionID(w, tlv.ContextTag(tagSigma1InitiatorSessionID), s.InitiatorSessionID); err != nil {
		return nil, err
	}
	if err := w.PutBytes(tlv.ContextTag(tagSigma1DestinationID), s.DestinationID[:]); err != nil {
		return nil, err
	}
	if err := w.PutBytes(tlv.ContextTag(tagSigma1InitiatorEphPubKey), s.InitiatorEphPubKey[:]); err != nil {
		return nil, err
	}

	if s.MRPParams != nil {
		if err := encodeMRPParams(w, tagSigma1InitiatorSessionParams, s.MRPParams); err != nil {
			return nil, err
		}
	}

	if s.ResumptionID != nil {
		if err := w.PutBytes(tlv.ContextTag(tagSigma1ResumptionID), s.ResumptionID[:]); err != nil {
			return nil, err
		}
	}
	if s.InitiatorResumeMIC != nil {
		if err := w.PutBytes(tlv.ContextTag(tagSigma1InitiatorResumeMIC), s.InitiatorResumeMIC[:]); err != nil {
			return nil, err
		}
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodeSigma1 parses a Sigma1 from TLV bytes.
func DecodeSigma1(data []byte) (*Sigma1, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	s := &Sigma1{}

	if err := r.Next(); err != nil {
		return nil, err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return nil, ErrInvalidMessage
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	var hasInitiatorRandom, hasSessionID, hasDestinationID, hasEphPubKey bool

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
		case tagSigma1InitiatorRandom:
			random, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			if len(random) != RandomSize {
				return nil, ErrInvalidRandom
			}
			copy(s.InitiatorRandom[:], random)
			hasInitiatorRandom = true

		case tagSigma1InitiatorSessionID:
			v, err := r.Uint()
			if err != nil {
				return nil, err
			}
			s.InitiatorSessionID = uint16(v)
			hasSessionID = true

		case tagSigma1DestinationID:
			destID, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			if len(destID) != DestinationIDSize {
				return nil, ErrInvalidMessage
			}
			copy(s.DestinationID[:], destID)
			hasDestinationID = true

		case tagSigma1InitiatorEphPubKey:
			pubKey, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			if len(pubKey) != crypto.P256PublicKeySizeBytes {
				return nil, ErrInvalidMessage
			}
			copy(s.InitiatorEphPubKey[:], pubKey)
			hasEphPubKey = true

		case tagSigma1InitiatorSessionParams:
			mrp, err := decodeMRPParams(r)
			if err != nil {
				return nil, err
			}
			s.MRPParams = mrp

		case tagSigma1ResumptionID:
			resumptionID, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			if len(resumptionID) != ResumptionIDSize {
				return nil, ErrInvalidMessage
			}
			s.ResumptionID = new([ResumptionIDSize]byte)
			copy(s.ResumptionID[:], resumptionID)

		case tagSigma1InitiatorResumeMIC:
			mic, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			if len(mic) != MICSize {
				return nil, ErrInvalidMessage
			}
			s.InitiatorResumeMIC = new([MICSize]byte)
			copy(s.InitiatorResumeMIC[:], mic)
		}
	}

	// Validate required fields
	if !hasInitiatorRandom || !hasSessionID || !hasDestinationID || !hasEphPubKey {
		return nil, ErrInvalidMessage
	}

	return s, nil
}

// Sigma2 is the second message in CASE, sent by the responder.
type Sigma2 struct {
	ResponderRandom    [RandomSize]byte
	ResponderSessionID uint16
	ResponderEphPubKey [crypto.P256PublicKeySizeBytes]byte
	Encrypted2         []byte         // TBEData2 encrypted with S2K
	MRPParams          *MRPParameters // Optional
}

// Encode serializes the Sigma2 to TLV bytes.
func (s *Sigma2) Encode() ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutBytes(tlv.ContextTag(tagSigma2ResponderRandom), s.ResponderRandom[:]); err != nil {
		return nil, err
	}
	if err := messages.PutSessionID(w, tlv.ContextTag(tagSigma2ResponderSessionID), s.ResponderSessionID); err != nil {
		return nil, err
	}
	if err := w.PutBytes(tlv.ContextTag(tagSigma2ResponderEphPubKey), s.ResponderEphPubKey[:]); err != nil {
		return nil, err
	}
	if err := w.PutBytes(tlv.ContextTag(tagSigma2Encrypted2), s.Encrypted2); err != nil {
		return nil, err
	}

	if s.MRPParams != nil {
		if err := encodeMRPParams(w, tagSigma2ResponderSessionParams, s.MRPParams); err != nil {
			return nil, err
		}
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodeSigma2 parses a Sigma2 from TLV bytes.
func DecodeSigma2(data []byte) (*Sigma2, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	s := &Sigma2{}

	if err := r.Next(); err != nil {
		return nil, err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return nil, ErrInvalidMessage
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	var hasResponderRandom, hasSessionID, hasEphPubKey, hasEncrypted2 bool

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
		case tagSigma2ResponderRandom:
			random, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			if len(random) != RandomSize {
				return nil, ErrInvalidRandom
			}
			copy(s.ResponderRandom[:], random)
			hasResponderRandom = true

		case tagSigma2ResponderSessionID:
			v, err := r.Uint()
			if err != nil {
				return nil, err
			}
			s.ResponderSessionID = uint16(v)
			hasSessionID = true

		case tagSigma2ResponderEphPubKey:
			pubKey, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			if len(pubKey) != crypto.P256PublicKeySizeBytes {
				return nil, ErrInvalidMessage
			}
			copy(s.ResponderEphPubKey[:], pubKey)
			hasEphPubKey = true

		case tagSigma2Encrypted2:
			encrypted, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			s.Encrypted2 = encrypted
			hasEncrypted2 = true

		case tagSigma2ResponderSessionParams:
			mrp, err := decodeMRPParams(r)
			if err != nil {
				return nil, err
			}
			s.MRPParams = mrp
		}
	}

	if !hasResponderRandom || !hasSessionID || !hasEphPubKey || !hasEncrypted2 {
		return nil, ErrInvalidMessage
	}

	return s, nil
}

// TBEData2 is the decrypted content of Sigma2.Encrypted2.
type TBEData2 struct {
	ResponderNOC  []byte                 // Matter TLV certificate
	ResponderICAC []byte                 // Optional, Matter TLV certificate
	Signature     [crypto.P256SignatureSizeBytes]byte
	ResumptionID  [ResumptionIDSize]byte
}

// Encode serializes TBEData2 to TLV bytes.
func (t *TBEData2) Encode() ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutBytes(tlv.ContextTag(tagTBEData2ResponderNOC), t.ResponderNOC); err != nil {
		return nil, err
	}
	if len(t.ResponderICAC) > 0 {
		if err := w.PutBytes(tlv.ContextTag(tagTBEData2ResponderICAC), t.ResponderICAC); err != nil {
			return nil, err
		}
	}
	if err := w.PutBytes(tlv.ContextTag(tagTBEData2Signature), t.Signature[:]); err != nil {
		return nil, err
	}
	if err := w.PutBytes(tlv.ContextTag(tagTBEData2ResumptionID), t.ResumptionID[:]); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodeTBEData2 parses TBEData2 from TLV bytes.
func DecodeTBEData2(data []byte) (*TBEData2, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	t := &TBEData2{}

	if err := r.Next(); err != nil {
		return nil, err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return nil, ErrInvalidMessage
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	var hasNOC, hasSignature, hasResumptionID bool

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
		case tagTBEData2ResponderNOC:
			noc, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			t.ResponderNOC = noc
			hasNOC = true

		case tagTBEData2ResponderICAC:
			icac, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			t.ResponderICAC = icac

		case tagTBEData2Signature:
			sig, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			if len(sig) != crypto.P256SignatureSizeBytes {
				return nil, ErrInvalidMessage
			}
			copy(t.Signature[:], sig)
			hasSignature = true

		case tagTBEData2ResumptionID:
			resumptionID, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			if len(resumptionID) != ResumptionIDSize {
				return nil, ErrInvalidMessage
			}
			copy(t.ResumptionID[:], resumptionID)
			hasResumptionID = true
		}
	}

	if !hasNOC || !hasSignature || !hasResumptionID {
		return nil, ErrInvalidMessage
	}

	return t, nil
}

// TBSData2 is the data to be signed for Sigma2 (sigma-2-tbsdata).
// This is NOT transmitted; it's used locally to compute/verify the signature.
type TBSData2 struct {
	ResponderNOC       []byte
	ResponderICAC      []byte // Optional
	ResponderEphPubKey [crypto.P256PublicKeySizeBytes]byte
	InitiatorEphPubKey [crypto.P256PublicKeySizeBytes]byte
}

// Encode serializes TBSData2 to TLV bytes for signing.
func (t *TBSData2) Encode() ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutBytes(tlv.ContextTag(tagTBSData2ResponderNOC), t.ResponderNOC); err != nil {
		return nil, err
	}
	if len(t.ResponderICAC) > 0 {
		if err := w.PutBytes(tlv.ContextTag(tagTBSData2ResponderICAC), t.ResponderICAC); err != nil {
			return nil, err
		}
	}
	if err := w.PutBytes(tlv.ContextTag(tagTBSData2ResponderEphPubKey), t.ResponderEphPubKey[:]); err != nil {
		return nil, err
	}
	if err := w.PutBytes(tlv.ContextTag(tagTBSData2InitiatorEphPubKey), t.InitiatorEphPubKey[:]); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Sigma3 is the third message in CASE, sent by the initiator.
type Sigma3 struct {
	Encrypted3 []byte // TBEData3 encrypted with S3K
}

// Encode serializes the Sigma3 to TLV bytes.
func (s *Sigma3) Encode() ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutBytes(tlv.ContextTag(tagSigma3Encrypted3), s.Encrypted3); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodeSigma3 parses a Sigma3 from TLV bytes.
func DecodeSigma3(data []byte) (*Sigma3, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	s := &Sigma3{}

	if err := r.Next(); err != nil {
		return nil, err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return nil, ErrInvalidMessage
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	var hasEncrypted3 bool

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
		if tag.IsContext() && tag.TagNumber() == tagSigma3Encrypted3 {
			encrypted, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			s.Encrypted3 = encrypted
			hasEncrypted3 = true
		}
	}

	if !hasEncrypted3 {
		return nil, ErrInvalidMessage
	}

	return s, nil
}

// TBEData3 is the decrypted content of Sigma3.Encrypted3.
type TBEData3 struct {
	InitiatorNOC  []byte // Matter TLV certificate
	InitiatorICAC []byte // Optional, Matter TLV certificate
	Signature     [crypto.P256SignatureSizeBytes]byte
}

// Encode serializes TBEData3 to TLV bytes.
func (t *TBEData3) Encode() ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutBytes(tlv.ContextTag(tagTBEData3InitiatorNOC), t.InitiatorNOC); err != nil {
		return nil, err
	}
	if len(t.InitiatorICAC) > 0 {
		if err := w.PutBytes(tlv.ContextTag(tagTBEData3InitiatorICAC), t.InitiatorICAC); err != nil {
			return nil, err
		}
	}
	if err := w.PutBytes(tlv.ContextTag(tagTBEData3Signature), t.Signature[:]); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodeTBEData3 parses TBEData3 from TLV bytes.
func DecodeTBEData3(data []byte) (*TBEData3, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	t := &TBEData3{}

	if err := r.Next(); err != nil {
		return nil, err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return nil, ErrInvalidMessage
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	var hasNOC, hasSignature bool

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
		case tagTBEData3InitiatorNOC:
			noc, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			t.InitiatorNOC = noc
			hasNOC = true

		case tagTBEData3InitiatorICAC:
			icac, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			t.InitiatorICAC = icac

		case tagTBEData3Signature:
			sig, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			if len(sig) != crypto.P256SignatureSizeBytes {
				return nil, ErrInvalidMessage
			}
			copy(t.Signature[:], sig)
			hasSignature = true
		}
	}

	if !hasNOC || !hasSignature {
		return nil, ErrInvalidMessage
	}

	return t, nil
}

// TBSData3 is the data to be signed for Sigma3 (sigma-3-tbsdata).
// This is NOT transmitted; it's used locally to compute/verify the signature.
type TBSData3 struct {
	InitiatorNOC       []byte
	InitiatorICAC      []byte // Optional
	InitiatorEphPubKey [crypto.P256PublicKeySizeBytes]byte
	ResponderEphPubKey [crypto.P256PublicKeySizeBytes]byte
}

// Encode serializes TBSData3 to TLV bytes for signing.
func (t *TBSData3) Encode() ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutBytes(tlv.ContextTag(tagTBSData3InitiatorNOC), t.InitiatorNOC); err != nil {
		return nil, err
	}
	if len(t.InitiatorICAC) > 0 {
		if err := w.PutBytes(tlv.ContextTag(tagTBSData3InitiatorICAC), t.InitiatorICAC); err != nil {
			return nil, err
		}
	}
	if err := w.PutBytes(tlv.ContextTag(tagTBSData3InitiatorEphPubKey), t.InitiatorEphPubKey[:]); err != nil {
		return nil, err
	}
	if err := w.PutBytes(tlv.ContextTag(tagTBSData3ResponderEphPubKey), t.ResponderEphPubKey[:]); err != nil {
		return nil, err
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Sigma2Resume is sent by the responder for session resumption.
type Sigma2Resume struct {
	ResumptionID       [ResumptionIDSize]byte
	Resume2MIC         [MICSize]byte
	ResponderSessionID uint16
	MRPParams          *MRPParameters // Optional
}

// Encode serializes the Sigma2Resume to TLV bytes.
func (s *Sigma2Resume) Encode() ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if err := w.PutBytes(tlv.ContextTag(tagSigma2ResumeResumptionID), s.ResumptionID[:]); err != nil {
		return nil, err
	}
	if err := w.PutBytes(tlv.ContextTag(tagSigma2ResumeResponderMIC), s.Resume2MIC[:]); err != nil {
		return nil, err
	}
	if err := messages.PutSessionID(w, tlv.ContextTag(tagSigma2ResumeResponderSessionID), s.ResponderSessionID); err != nil {
		return nil, err
	}

	if s.MRPParams != nil {
		if err := encodeMRPParams(w, tagSigma2ResumeResponderSessionParams, s.MRPParams); err != nil {
			return nil, err
		}
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodeSigma2Resume parses a Sigma2Resume from TLV bytes.
func DecodeSigma2Resume(data []byte) (*Sigma2Resume, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	s := &Sigma2Resume{}

	if err := r.Next(); err != nil {
		return nil, err
	}
	if r.Type() != tlv.ElementTypeStruct {
		return nil, ErrInvalidMessage
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	var hasResumptionID, hasMIC, hasSessionID bool

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
		case tagSigma2ResumeResumptionID:
			resumptionID, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			if len(resumptionID) != ResumptionIDSize {
				return nil, ErrInvalidMessage
			}
			copy(s.ResumptionID[:], resumptionID)
			hasResumptionID = true

		case tagSigma2ResumeResponderMIC:
			mic, err := r.Bytes()
			if err != nil {
				return nil, err
			}
			if len(mic) != MICSize {
				return nil, ErrInvalidMessage
			}
			copy(s.Resume2MIC[:], mic)
			hasMIC = true

		case tagSigma2ResumeResponderSessionID:
			v, err := r.Uint()
			if err != nil {
				return nil, err
			}
			s.ResponderSessionID = uint16(v)
			hasSessionID = true

		case tagSigma2ResumeResponderSessionParams:
			mrp, err := decodeMRPParams(r)
			if err != nil {
				return nil, err
			}
			s.MRPParams = mrp
		}
	}

	if !hasResumptionID || !hasMIC || !hasSessionID {
		return nil, ErrInvalidMessage
	}

	return s, nil
}

// Helper functions for MRP parameters encoding/decoding

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
