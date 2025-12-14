package credentials

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/backkem/matter/pkg/tlv"
)

// DNAttribute represents a Distinguished Name attribute in a Matter certificate.
// For standard attributes (tags 1-16), Value is a string.
// For Matter-specific attributes (tags 17-23), Value is a uint64.
// Spec Section 6.5.6.1
type DNAttribute struct {
	Tag   uint8       // Context tag (1-23 for UTF8, 129-143 for PrintableString)
	Value interface{} // string or uint64
}

// NewDNString creates a DN attribute with a string value.
func NewDNString(tag uint8, value string) DNAttribute {
	return DNAttribute{Tag: tag, Value: value}
}

// NewDNUint64 creates a DN attribute with a uint64 value (for Matter-specific attributes).
func NewDNUint64(tag uint8, value uint64) DNAttribute {
	return DNAttribute{Tag: tag, Value: value}
}

// IsString returns true if this is a string-valued attribute.
func (d DNAttribute) IsString() bool {
	_, ok := d.Value.(string)
	return ok
}

// IsUint64 returns true if this is a uint64-valued attribute.
func (d DNAttribute) IsUint64() bool {
	_, ok := d.Value.(uint64)
	return ok
}

// StringValue returns the string value, or empty string if not a string.
func (d DNAttribute) StringValue() string {
	if s, ok := d.Value.(string); ok {
		return s
	}
	return ""
}

// Uint64Value returns the uint64 value, or 0 if not a uint64.
func (d DNAttribute) Uint64Value() uint64 {
	if u, ok := d.Value.(uint64); ok {
		return u
	}
	return 0
}

// IsPrintableString returns true if this attribute uses PrintableString encoding.
func (d DNAttribute) IsPrintableString() bool {
	return d.Tag >= TagDNPrintableStringOffset
}

// BaseTag returns the base tag without the PrintableString offset.
func (d DNAttribute) BaseTag() uint8 {
	if d.Tag >= TagDNPrintableStringOffset {
		return d.Tag - TagDNPrintableStringOffset
	}
	return d.Tag
}

// IsMatterSpecific returns true if this is a Matter-specific attribute.
func (d DNAttribute) IsMatterSpecific() bool {
	return IsMatterSpecificTag(d.Tag)
}

// MatterSpecificByteLength returns the byte length for Matter-specific attributes.
// Spec Section 6.1.1, Table 83
func (d DNAttribute) MatterSpecificByteLength() int {
	baseTag := d.BaseTag()
	switch baseTag {
	case TagDNMatterNodeID, TagDNMatterFirmwareSigningID, TagDNMatterICACID,
		TagDNMatterRCACID, TagDNMatterFabricID, TagDNMatterVVSID:
		return 8 // 64-bit
	case TagDNMatterNOCCAT:
		return 4 // 32-bit
	default:
		return 0
	}
}

// String returns a human-readable representation of the DN attribute.
func (d DNAttribute) String() string {
	baseTag := d.BaseTag()
	var name string
	switch baseTag {
	case TagDNCommonName:
		name = "CN"
	case TagDNSurname:
		name = "SN"
	case TagDNSerialNum:
		name = "serialNumber"
	case TagDNCountryName:
		name = "C"
	case TagDNLocalityName:
		name = "L"
	case TagDNStateOrProvinceName:
		name = "ST"
	case TagDNOrgName:
		name = "O"
	case TagDNOrgUnitName:
		name = "OU"
	case TagDNTitle:
		name = "title"
	case TagDNName:
		name = "name"
	case TagDNGivenName:
		name = "GN"
	case TagDNInitials:
		name = "initials"
	case TagDNGenQualifier:
		name = "generationQualifier"
	case TagDNDNQualifier:
		name = "dnQualifier"
	case TagDNPseudonym:
		name = "pseudonym"
	case TagDNDomainComponent:
		name = "DC"
	case TagDNMatterNodeID:
		name = "matter-node-id"
	case TagDNMatterFirmwareSigningID:
		name = "matter-firmware-signing-id"
	case TagDNMatterICACID:
		name = "matter-icac-id"
	case TagDNMatterRCACID:
		name = "matter-rcac-id"
	case TagDNMatterFabricID:
		name = "matter-fabric-id"
	case TagDNMatterNOCCAT:
		name = "matter-noc-cat"
	case TagDNMatterVVSID:
		name = "matter-vvs-id"
	default:
		name = fmt.Sprintf("tag-%d", baseTag)
	}

	if d.IsString() {
		return fmt.Sprintf("%s=%s", name, d.StringValue())
	}
	return fmt.Sprintf("%s=0x%X", name, d.Uint64Value())
}

// EncodeTLV encodes the DN attribute to TLV bytes.
func (d DNAttribute) EncodeTLV(w *tlv.Writer) error {
	tag := tlv.ContextTag(d.Tag)

	if d.IsString() {
		return w.PutString(tag, d.StringValue())
	}

	// Matter-specific uint64 attribute
	u := d.Uint64Value()
	baseTag := d.BaseTag()

	// Use appropriate width based on attribute type
	switch baseTag {
	case TagDNMatterNOCCAT:
		// 32-bit attribute - use minimal encoding
		return w.PutUint(tag, u)
	default:
		// 64-bit attributes - use minimal encoding
		return w.PutUint(tag, u)
	}
}

// DecodeDNAttribute decodes a single DN attribute from a TLV reader.
// The reader must be positioned at the element (after calling Next()).
func DecodeDNAttribute(r *tlv.Reader) (DNAttribute, error) {
	tag := r.Tag()
	if !tag.IsContext() {
		return DNAttribute{}, fmt.Errorf("expected context-specific tag, got %v", tag)
	}

	ctxTag := uint8(tag.TagNumber())
	attr := DNAttribute{Tag: ctxTag}

	elemType := r.Type()

	// Matter-specific attributes are encoded as unsigned integers
	if IsMatterSpecificTag(ctxTag) {
		if !elemType.IsUnsignedInt() {
			return DNAttribute{}, fmt.Errorf("matter-specific attribute must be unsigned integer, got %v", elemType)
		}
		u, err := r.Uint()
		if err != nil {
			return DNAttribute{}, fmt.Errorf("failed to read uint64: %w", err)
		}
		attr.Value = u
		return attr, nil
	}

	// Standard attributes are encoded as UTF-8 strings
	if !elemType.IsUTF8String() {
		return DNAttribute{}, fmt.Errorf("standard DN attribute must be UTF-8 string, got %v", elemType)
	}
	s, err := r.String()
	if err != nil {
		return DNAttribute{}, fmt.Errorf("failed to read string: %w", err)
	}
	attr.Value = s
	return attr, nil
}

// DistinguishedName represents a full Distinguished Name (list of attributes).
type DistinguishedName []DNAttribute

// EncodeTLV encodes the DN as a TLV list.
func (dn DistinguishedName) EncodeTLV(w *tlv.Writer, tag tlv.Tag) error {
	if err := w.StartList(tag); err != nil {
		return err
	}
	for _, attr := range dn {
		if err := attr.EncodeTLV(w); err != nil {
			return err
		}
	}
	return w.EndContainer()
}

// DecodeDistinguishedName decodes a DN from a TLV reader.
// The reader must be positioned at the list element.
func DecodeDistinguishedName(r *tlv.Reader) (DistinguishedName, error) {
	if r.Type() != tlv.ElementTypeList {
		return nil, fmt.Errorf("expected list, got %v", r.Type())
	}

	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	var dn DistinguishedName
	for {
		if err := r.Next(); err != nil {
			return nil, err
		}
		if r.IsEndOfContainer() {
			break
		}

		attr, err := DecodeDNAttribute(r)
		if err != nil {
			return nil, err
		}
		dn = append(dn, attr)
	}

	return dn, nil
}

// String returns a human-readable representation of the DN.
func (dn DistinguishedName) String() string {
	var parts []string
	for _, attr := range dn {
		parts = append(parts, attr.String())
	}
	return strings.Join(parts, ", ")
}

// GetAttribute returns the first attribute with the given base tag, or nil if not found.
func (dn DistinguishedName) GetAttribute(baseTag uint8) *DNAttribute {
	for i := range dn {
		if dn[i].BaseTag() == baseTag {
			return &dn[i]
		}
	}
	return nil
}

// GetAllAttributes returns all attributes with the given base tag.
func (dn DistinguishedName) GetAllAttributes(baseTag uint8) []DNAttribute {
	var attrs []DNAttribute
	for _, attr := range dn {
		if attr.BaseTag() == baseTag {
			attrs = append(attrs, attr)
		}
	}
	return attrs
}

// HasAttribute returns true if the DN contains an attribute with the given base tag.
func (dn DistinguishedName) HasAttribute(baseTag uint8) bool {
	return dn.GetAttribute(baseTag) != nil
}

// GetNodeID returns the matter-node-id value, or 0 if not present.
func (dn DistinguishedName) GetNodeID() uint64 {
	if attr := dn.GetAttribute(TagDNMatterNodeID); attr != nil {
		return attr.Uint64Value()
	}
	return 0
}

// GetFabricID returns the matter-fabric-id value, or 0 if not present.
func (dn DistinguishedName) GetFabricID() uint64 {
	if attr := dn.GetAttribute(TagDNMatterFabricID); attr != nil {
		return attr.Uint64Value()
	}
	return 0
}

// GetRCACID returns the matter-rcac-id value, or 0 if not present.
func (dn DistinguishedName) GetRCACID() uint64 {
	if attr := dn.GetAttribute(TagDNMatterRCACID); attr != nil {
		return attr.Uint64Value()
	}
	return 0
}

// GetICACID returns the matter-icac-id value, or 0 if not present.
func (dn DistinguishedName) GetICACID() uint64 {
	if attr := dn.GetAttribute(TagDNMatterICACID); attr != nil {
		return attr.Uint64Value()
	}
	return 0
}

// GetNOCCATs returns all matter-noc-cat values.
func (dn DistinguishedName) GetNOCCATs() []uint32 {
	attrs := dn.GetAllAttributes(TagDNMatterNOCCAT)
	cats := make([]uint32, len(attrs))
	for i, attr := range attrs {
		cats[i] = uint32(attr.Uint64Value())
	}
	return cats
}

// MatterSpecificToHexString converts a Matter-specific uint64 value to the
// hex string format used in X.509 certificates.
// Spec Section 6.1.1
func MatterSpecificToHexString(value uint64, byteLen int) string {
	// Format as uppercase hex with exactly 2*byteLen characters
	format := fmt.Sprintf("%%0%dX", byteLen*2)
	return fmt.Sprintf(format, value)
}

// HexStringToMatterSpecific parses a hex string from an X.509 certificate
// into a Matter-specific uint64 value.
// Spec Section 6.1.1
func HexStringToMatterSpecific(s string) (uint64, error) {
	// Remove any whitespace
	s = strings.TrimSpace(s)

	// Decode hex string
	data, err := hex.DecodeString(s)
	if err != nil {
		return 0, fmt.Errorf("invalid hex string: %w", err)
	}

	// Convert to uint64 (big-endian / network byte order)
	var value uint64
	for _, b := range data {
		value = (value << 8) | uint64(b)
	}

	return value, nil
}

// MarshalDN encodes a DistinguishedName to standalone TLV bytes.
func MarshalDN(dn DistinguishedName) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := dn.EncodeTLV(w, tlv.Anonymous()); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalDN decodes a DistinguishedName from TLV bytes.
func UnmarshalDN(data []byte) (DistinguishedName, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		return nil, err
	}
	return DecodeDistinguishedName(r)
}
