package fabric

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/backkem/matter/pkg/tlv"
)

// TLV context tags for NOCStruct (Spec Section 11.18.4.4).
const (
	tagNOCStructNOC  = 1
	tagNOCStructICAC = 2
	// tagNOCStructVVSC = 3 // Not implemented in initial version
)

// TLV context tags for FabricDescriptorStruct (Spec Section 11.18.4.5).
const (
	tagFabricDescriptorRootPublicKey = 1
	tagFabricDescriptorVendorID      = 2
	tagFabricDescriptorFabricID      = 3
	tagFabricDescriptorNodeID        = 4
	tagFabricDescriptorLabel         = 5
	// tagFabricDescriptorVIDVerificationStatement = 6 // Not implemented
)

// NOCStruct encodes a NOC chain for a fabric.
// Spec Section 11.18.4.4
//
// This is the wire format for entries in the NOCs attribute of the
// Operational Credentials Cluster.
type NOCStruct struct {
	// NOC is the Node Operational Certificate in Matter TLV encoding.
	// Maximum size: 400 bytes.
	NOC []byte

	// ICAC is the Intermediate CA Certificate in Matter TLV encoding.
	// This field is nullable - nil means no ICAC is present.
	// Maximum size: 400 bytes.
	ICAC []byte
}

// EncodeTLV encodes the NOCStruct to a TLV writer.
func (n *NOCStruct) EncodeTLV(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	// [1] NOC (required)
	if err := w.PutBytes(tlv.ContextTag(tagNOCStructNOC), n.NOC); err != nil {
		return err
	}

	// [2] ICAC (nullable)
	if n.ICAC != nil {
		if err := w.PutBytes(tlv.ContextTag(tagNOCStructICAC), n.ICAC); err != nil {
			return err
		}
	} else {
		if err := w.PutNull(tlv.ContextTag(tagNOCStructICAC)); err != nil {
			return err
		}
	}

	return w.EndContainer()
}

// MarshalTLV encodes the NOCStruct to TLV bytes.
func (n *NOCStruct) MarshalTLV() ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := n.EncodeTLV(w); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodeNOCStruct decodes a NOCStruct from a TLV reader.
// The reader must be positioned at the structure element.
func DecodeNOCStruct(r *tlv.Reader) (*NOCStruct, error) {
	if r.Type() != tlv.ElementTypeStruct {
		return nil, fmt.Errorf("fabric: expected structure, got %v", r.Type())
	}

	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	n := &NOCStruct{}
	for {
		if err := r.Next(); err != nil {
			return nil, err
		}
		if r.IsEndOfContainer() {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			if err := r.Skip(); err != nil {
				return nil, err
			}
			continue
		}

		switch tag.TagNumber() {
		case tagNOCStructNOC:
			data, err := r.Bytes()
			if err != nil {
				return nil, fmt.Errorf("fabric: failed to read NOC: %w", err)
			}
			n.NOC = data

		case tagNOCStructICAC:
			if r.Type() == tlv.ElementTypeNull {
				n.ICAC = nil
			} else {
				data, err := r.Bytes()
				if err != nil {
					return nil, fmt.Errorf("fabric: failed to read ICAC: %w", err)
				}
				n.ICAC = data
			}

		default:
			if err := r.Skip(); err != nil {
				return nil, err
			}
		}
	}

	return n, nil
}

// UnmarshalNOCStruct decodes a NOCStruct from TLV bytes.
func UnmarshalNOCStruct(data []byte) (*NOCStruct, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		return nil, err
	}
	return DecodeNOCStruct(r)
}

// FabricDescriptorStruct is the wire format for fabric metadata.
// Spec Section 11.18.4.5
//
// This is the wire format for entries in the Fabrics attribute of the
// Operational Credentials Cluster.
type FabricDescriptorStruct struct {
	// RootPublicKey is the 65-byte uncompressed public key from the RCAC.
	RootPublicKey [RootPublicKeySize]byte

	// VendorID is the admin vendor ID provided at commissioning.
	VendorID VendorID

	// FabricID is the 64-bit fabric identifier from the NOC.
	FabricID FabricID

	// NodeID is the 64-bit node identifier from the NOC.
	NodeID NodeID

	// Label is a user-assigned label for this fabric (max 32 chars).
	Label string
}

// EncodeTLV encodes the FabricDescriptorStruct to a TLV writer.
func (f *FabricDescriptorStruct) EncodeTLV(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	// [1] RootPublicKey (65 bytes)
	if err := w.PutBytes(tlv.ContextTag(tagFabricDescriptorRootPublicKey), f.RootPublicKey[:]); err != nil {
		return err
	}

	// [2] VendorID (uint16)
	if err := w.PutUint(tlv.ContextTag(tagFabricDescriptorVendorID), uint64(f.VendorID)); err != nil {
		return err
	}

	// [3] FabricID (uint64)
	if err := w.PutUint(tlv.ContextTag(tagFabricDescriptorFabricID), uint64(f.FabricID)); err != nil {
		return err
	}

	// [4] NodeID (uint64)
	if err := w.PutUint(tlv.ContextTag(tagFabricDescriptorNodeID), uint64(f.NodeID)); err != nil {
		return err
	}

	// [5] Label (string, max 32 chars)
	if err := w.PutString(tlv.ContextTag(tagFabricDescriptorLabel), f.Label); err != nil {
		return err
	}

	return w.EndContainer()
}

// MarshalTLV encodes the FabricDescriptorStruct to TLV bytes.
func (f *FabricDescriptorStruct) MarshalTLV() ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := f.EncodeTLV(w); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodeFabricDescriptorStruct decodes a FabricDescriptorStruct from a TLV reader.
// The reader must be positioned at the structure element.
func DecodeFabricDescriptorStruct(r *tlv.Reader) (*FabricDescriptorStruct, error) {
	if r.Type() != tlv.ElementTypeStruct {
		return nil, fmt.Errorf("fabric: expected structure, got %v", r.Type())
	}

	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	f := &FabricDescriptorStruct{}
	for {
		if err := r.Next(); err != nil {
			return nil, err
		}
		if r.IsEndOfContainer() {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			if err := r.Skip(); err != nil {
				return nil, err
			}
			continue
		}

		switch tag.TagNumber() {
		case tagFabricDescriptorRootPublicKey:
			data, err := r.Bytes()
			if err != nil {
				return nil, fmt.Errorf("fabric: failed to read RootPublicKey: %w", err)
			}
			if len(data) != RootPublicKeySize {
				return nil, fmt.Errorf("fabric: invalid RootPublicKey size: %d", len(data))
			}
			copy(f.RootPublicKey[:], data)

		case tagFabricDescriptorVendorID:
			u, err := r.Uint()
			if err != nil {
				return nil, fmt.Errorf("fabric: failed to read VendorID: %w", err)
			}
			f.VendorID = VendorID(u)

		case tagFabricDescriptorFabricID:
			u, err := r.Uint()
			if err != nil {
				return nil, fmt.Errorf("fabric: failed to read FabricID: %w", err)
			}
			f.FabricID = FabricID(u)

		case tagFabricDescriptorNodeID:
			u, err := r.Uint()
			if err != nil {
				return nil, fmt.Errorf("fabric: failed to read NodeID: %w", err)
			}
			f.NodeID = NodeID(u)

		case tagFabricDescriptorLabel:
			s, err := r.String()
			if err != nil {
				return nil, fmt.Errorf("fabric: failed to read Label: %w", err)
			}
			f.Label = s

		default:
			if err := r.Skip(); err != nil {
				return nil, err
			}
		}
	}

	return f, nil
}

// UnmarshalFabricDescriptorStruct decodes a FabricDescriptorStruct from TLV bytes.
func UnmarshalFabricDescriptorStruct(data []byte) (*FabricDescriptorStruct, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		return nil, err
	}
	return DecodeFabricDescriptorStruct(r)
}

// CompressedFabricIDBytes returns the compressed fabric ID for this descriptor.
func (f *FabricDescriptorStruct) CompressedFabricIDBytes() ([CompressedFabricIDSize]byte, error) {
	return CompressedFabricIDFromCert(f.RootPublicKey, f.FabricID)
}

// fabricIDToBytes converts a FabricID to big-endian bytes.
func fabricIDToBytes(id FabricID) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(id))
	return b
}

// nodeIDToBytes converts a NodeID to big-endian bytes.
func nodeIDToBytes(id NodeID) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(id))
	return b
}
