package credentials

import (
	"bytes"
	"fmt"

	"github.com/backkem/matter/pkg/tlv"
)

// Extension represents a certificate extension in Matter TLV format.
// Spec Section 6.5.11
type Extension interface {
	// ExtTag returns the Matter TLV context tag for this extension.
	ExtTag() uint8
	// EncodeTLV writes the extension value to the TLV writer.
	EncodeTLV(w *tlv.Writer) error
}

// BasicConstraints represents the Basic Constraints extension.
// Spec Section 6.5.11.1
type BasicConstraints struct {
	IsCA              bool
	PathLenConstraint *uint8 // Optional, only valid when IsCA is true
}

func (b BasicConstraints) ExtTag() uint8 { return TagExtBasicConstraints }

func (b BasicConstraints) EncodeTLV(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.ContextTag(TagExtBasicConstraints)); err != nil {
		return err
	}

	// is-ca [1] is always encoded
	if err := w.PutBool(tlv.ContextTag(TagBasicConstraintsIsCA), b.IsCA); err != nil {
		return err
	}

	// path-len-constraint [2] is optional, only when IsCA is true
	if b.IsCA && b.PathLenConstraint != nil {
		if err := w.PutUint(tlv.ContextTag(TagBasicConstraintsPathLen), uint64(*b.PathLenConstraint)); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// DecodeBasicConstraints decodes a BasicConstraints from a TLV reader.
// The reader must be positioned at the structure element.
func DecodeBasicConstraints(r *tlv.Reader) (BasicConstraints, error) {
	var bc BasicConstraints

	if r.Type() != tlv.ElementTypeStruct {
		return bc, fmt.Errorf("expected structure, got %v", r.Type())
	}

	if err := r.EnterContainer(); err != nil {
		return bc, err
	}

	for {
		if err := r.Next(); err != nil {
			return bc, err
		}
		if r.IsEndOfContainer() {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}

		switch uint8(tag.TagNumber()) {
		case TagBasicConstraintsIsCA:
			isCA, err := r.Bool()
			if err != nil {
				return bc, fmt.Errorf("failed to read is-ca: %w", err)
			}
			bc.IsCA = isCA

		case TagBasicConstraintsPathLen:
			pathLen, err := r.Uint()
			if err != nil {
				return bc, fmt.Errorf("failed to read path-len: %w", err)
			}
			pl := uint8(pathLen)
			bc.PathLenConstraint = &pl
		}
	}

	return bc, nil
}

// KeyUsageExt represents the Key Usage extension.
// Spec Section 6.5.11.2
type KeyUsageExt struct {
	Usage KeyUsage
}

func (k KeyUsageExt) ExtTag() uint8 { return TagExtKeyUsage }

func (k KeyUsageExt) EncodeTLV(w *tlv.Writer) error {
	return w.PutUint(tlv.ContextTag(TagExtKeyUsage), uint64(k.Usage))
}

// ExtendedKeyUsageExt represents the Extended Key Usage extension.
// Spec Section 6.5.11.3
type ExtendedKeyUsageExt struct {
	KeyPurposes []KeyPurposeID
}

func (e ExtendedKeyUsageExt) ExtTag() uint8 { return TagExtExtendedKeyUsage }

func (e ExtendedKeyUsageExt) EncodeTLV(w *tlv.Writer) error {
	if err := w.StartArray(tlv.ContextTag(TagExtExtendedKeyUsage)); err != nil {
		return err
	}
	for _, kp := range e.KeyPurposes {
		if err := w.PutUint(tlv.Anonymous(), uint64(kp)); err != nil {
			return err
		}
	}
	return w.EndContainer()
}

// DecodeExtendedKeyUsage decodes an ExtendedKeyUsageExt from a TLV reader.
// The reader must be positioned at the array element.
func DecodeExtendedKeyUsage(r *tlv.Reader) (ExtendedKeyUsageExt, error) {
	var eku ExtendedKeyUsageExt

	if r.Type() != tlv.ElementTypeArray {
		return eku, fmt.Errorf("expected array, got %v", r.Type())
	}

	if err := r.EnterContainer(); err != nil {
		return eku, err
	}

	for {
		if err := r.Next(); err != nil {
			return eku, err
		}
		if r.IsEndOfContainer() {
			break
		}

		kp, err := r.Uint()
		if err != nil {
			return eku, fmt.Errorf("failed to read key-purpose-id: %w", err)
		}
		eku.KeyPurposes = append(eku.KeyPurposes, KeyPurposeID(kp))
	}

	return eku, nil
}

// SubjectKeyIDExt represents the Subject Key Identifier extension.
// Spec Section 6.5.11.4
type SubjectKeyIDExt struct {
	KeyID [20]byte // SHA-1 hash of the public key
}

func (s SubjectKeyIDExt) ExtTag() uint8 { return TagExtSubjectKeyID }

func (s SubjectKeyIDExt) EncodeTLV(w *tlv.Writer) error {
	return w.PutBytes(tlv.ContextTag(TagExtSubjectKeyID), s.KeyID[:])
}

// AuthorityKeyIDExt represents the Authority Key Identifier extension.
// Spec Section 6.5.11.5
type AuthorityKeyIDExt struct {
	KeyID [20]byte // SHA-1 hash of the issuer's public key
}

func (a AuthorityKeyIDExt) ExtTag() uint8 { return TagExtAuthorityKeyID }

func (a AuthorityKeyIDExt) EncodeTLV(w *tlv.Writer) error {
	return w.PutBytes(tlv.ContextTag(TagExtAuthorityKeyID), a.KeyID[:])
}

// FutureExtensionExt represents a future/unknown extension.
// Spec Section 6.5.11.6
type FutureExtensionExt struct {
	Data []byte // Raw DER-encoded extension (including OID)
}

func (f FutureExtensionExt) ExtTag() uint8 { return TagExtFutureExtension }

func (f FutureExtensionExt) EncodeTLV(w *tlv.Writer) error {
	return w.PutBytes(tlv.ContextTag(TagExtFutureExtension), f.Data)
}

// Extensions represents the list of extensions in a Matter certificate.
type Extensions struct {
	BasicConstraints  *BasicConstraints
	KeyUsage          *KeyUsageExt
	ExtendedKeyUsage  *ExtendedKeyUsageExt
	SubjectKeyID      *SubjectKeyIDExt
	AuthorityKeyID    *AuthorityKeyIDExt
	FutureExtensions  []FutureExtensionExt
}

// EncodeTLV encodes all extensions as a TLV list.
func (e Extensions) EncodeTLV(w *tlv.Writer) error {
	if err := w.StartList(tlv.ContextTag(TagExtensions)); err != nil {
		return err
	}

	// Extensions must appear in the same order as in X.509
	if e.BasicConstraints != nil {
		if err := e.BasicConstraints.EncodeTLV(w); err != nil {
			return err
		}
	}

	if e.KeyUsage != nil {
		if err := e.KeyUsage.EncodeTLV(w); err != nil {
			return err
		}
	}

	if e.ExtendedKeyUsage != nil {
		if err := e.ExtendedKeyUsage.EncodeTLV(w); err != nil {
			return err
		}
	}

	if e.SubjectKeyID != nil {
		if err := e.SubjectKeyID.EncodeTLV(w); err != nil {
			return err
		}
	}

	if e.AuthorityKeyID != nil {
		if err := e.AuthorityKeyID.EncodeTLV(w); err != nil {
			return err
		}
	}

	for _, fe := range e.FutureExtensions {
		if err := fe.EncodeTLV(w); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// DecodeExtensions decodes an Extensions from a TLV reader.
// The reader must be positioned at the list element.
func DecodeExtensions(r *tlv.Reader) (Extensions, error) {
	var ext Extensions

	if r.Type() != tlv.ElementTypeList {
		return ext, fmt.Errorf("expected list, got %v", r.Type())
	}

	if err := r.EnterContainer(); err != nil {
		return ext, err
	}

	for {
		if err := r.Next(); err != nil {
			return ext, err
		}
		if r.IsEndOfContainer() {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			// Skip unknown tags
			if err := r.Skip(); err != nil {
				return ext, err
			}
			continue
		}

		switch uint8(tag.TagNumber()) {
		case TagExtBasicConstraints:
			bc, err := DecodeBasicConstraints(r)
			if err != nil {
				return ext, fmt.Errorf("failed to decode basic-constraints: %w", err)
			}
			ext.BasicConstraints = &bc

		case TagExtKeyUsage:
			ku, err := r.Uint()
			if err != nil {
				return ext, fmt.Errorf("failed to decode key-usage: %w", err)
			}
			ext.KeyUsage = &KeyUsageExt{Usage: KeyUsage(ku)}

		case TagExtExtendedKeyUsage:
			eku, err := DecodeExtendedKeyUsage(r)
			if err != nil {
				return ext, fmt.Errorf("failed to decode extended-key-usage: %w", err)
			}
			ext.ExtendedKeyUsage = &eku

		case TagExtSubjectKeyID:
			keyID, err := r.Bytes()
			if err != nil {
				return ext, fmt.Errorf("failed to decode subject-key-id: %w", err)
			}
			if len(keyID) != 20 {
				return ext, fmt.Errorf("subject-key-id must be 20 bytes, got %d", len(keyID))
			}
			ski := SubjectKeyIDExt{}
			copy(ski.KeyID[:], keyID)
			ext.SubjectKeyID = &ski

		case TagExtAuthorityKeyID:
			keyID, err := r.Bytes()
			if err != nil {
				return ext, fmt.Errorf("failed to decode authority-key-id: %w", err)
			}
			if len(keyID) != 20 {
				return ext, fmt.Errorf("authority-key-id must be 20 bytes, got %d", len(keyID))
			}
			aki := AuthorityKeyIDExt{}
			copy(aki.KeyID[:], keyID)
			ext.AuthorityKeyID = &aki

		case TagExtFutureExtension:
			data, err := r.Bytes()
			if err != nil {
				return ext, fmt.Errorf("failed to decode future-extension: %w", err)
			}
			ext.FutureExtensions = append(ext.FutureExtensions, FutureExtensionExt{Data: data})

		default:
			// Unknown extension tag, skip
			if err := r.Skip(); err != nil {
				return ext, err
			}
		}
	}

	return ext, nil
}

// MarshalExtensions encodes Extensions to standalone TLV bytes.
func MarshalExtensions(ext Extensions) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	// Write with anonymous tag at the root
	if err := w.StartList(tlv.Anonymous()); err != nil {
		return nil, err
	}

	if ext.BasicConstraints != nil {
		if err := ext.BasicConstraints.EncodeTLV(w); err != nil {
			return nil, err
		}
	}
	if ext.KeyUsage != nil {
		if err := ext.KeyUsage.EncodeTLV(w); err != nil {
			return nil, err
		}
	}
	if ext.ExtendedKeyUsage != nil {
		if err := ext.ExtendedKeyUsage.EncodeTLV(w); err != nil {
			return nil, err
		}
	}
	if ext.SubjectKeyID != nil {
		if err := ext.SubjectKeyID.EncodeTLV(w); err != nil {
			return nil, err
		}
	}
	if ext.AuthorityKeyID != nil {
		if err := ext.AuthorityKeyID.EncodeTLV(w); err != nil {
			return nil, err
		}
	}
	for _, fe := range ext.FutureExtensions {
		if err := fe.EncodeTLV(w); err != nil {
			return nil, err
		}
	}

	if err := w.EndContainer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// UnmarshalExtensions decodes Extensions from TLV bytes.
func UnmarshalExtensions(data []byte) (Extensions, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		return Extensions{}, err
	}
	return DecodeExtensions(r)
}
