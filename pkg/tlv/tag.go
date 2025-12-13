package tlv

import (
	"encoding/binary"
	"io"
)

// TagControl represents the tag form as encoded in the upper 3 bits
// of the control octet (Spec A.7.2).
type TagControl int

const (
	TagControlAnonymous         TagControl = 0 // 000 - No tag, 0 octets
	TagControlContext           TagControl = 1 // 001 - Context-specific, 1 octet
	TagControlCommonProfile2    TagControl = 2 // 010 - Common Profile, 2 octets (tag < 65536)
	TagControlCommonProfile4    TagControl = 3 // 011 - Common Profile, 4 octets (tag >= 65536)
	TagControlImplicitProfile2  TagControl = 4 // 100 - Implicit Profile, 2 octets (tag < 65536)
	TagControlImplicitProfile4  TagControl = 5 // 101 - Implicit Profile, 4 octets (tag >= 65536)
	TagControlFullyQualified6   TagControl = 6 // 110 - Fully Qualified, 6 octets (tag < 65536)
	TagControlFullyQualified8   TagControl = 7 // 111 - Fully Qualified, 8 octets (tag >= 65536)
)

// String returns the string representation of the tag control.
func (tc TagControl) String() string {
	switch tc {
	case TagControlAnonymous:
		return "Anonymous"
	case TagControlContext:
		return "Context"
	case TagControlCommonProfile2:
		return "CommonProfile2"
	case TagControlCommonProfile4:
		return "CommonProfile4"
	case TagControlImplicitProfile2:
		return "ImplicitProfile2"
	case TagControlImplicitProfile4:
		return "ImplicitProfile4"
	case TagControlFullyQualified6:
		return "FullyQualified6"
	case TagControlFullyQualified8:
		return "FullyQualified8"
	default:
		return "Unknown"
	}
}

// Size returns the size in bytes of the tag field for this control type.
func (tc TagControl) Size() int {
	switch tc {
	case TagControlAnonymous:
		return 0
	case TagControlContext:
		return 1
	case TagControlCommonProfile2, TagControlImplicitProfile2:
		return 2
	case TagControlCommonProfile4, TagControlImplicitProfile4:
		return 4
	case TagControlFullyQualified6:
		return 6
	case TagControlFullyQualified8:
		return 8
	default:
		return 0
	}
}

// Tag represents a TLV tag (Spec A.2).
// Tags can be anonymous, context-specific, or profile-specific.
type Tag struct {
	control       TagControl
	vendorID      uint16 // Only for fully-qualified tags
	profileNumber uint16 // Only for fully-qualified tags
	tagNumber     uint32 // 8-bit for context, up to 32-bit for others
}

// Anonymous returns a new anonymous tag.
func Anonymous() Tag {
	return Tag{control: TagControlAnonymous}
}

// ContextTag returns a new context-specific tag with the given tag number (0-255).
func ContextTag(tagNum uint8) Tag {
	return Tag{
		control:   TagControlContext,
		tagNumber: uint32(tagNum),
	}
}

// CommonProfileTag returns a new common profile tag with the given tag number.
func CommonProfileTag(tagNum uint32) Tag {
	ctrl := TagControlCommonProfile2
	if tagNum >= 65536 {
		ctrl = TagControlCommonProfile4
	}
	return Tag{
		control:   ctrl,
		tagNumber: tagNum,
	}
}

// ImplicitProfileTag returns a new implicit profile tag with the given tag number.
func ImplicitProfileTag(tagNum uint32) Tag {
	ctrl := TagControlImplicitProfile2
	if tagNum >= 65536 {
		ctrl = TagControlImplicitProfile4
	}
	return Tag{
		control:   ctrl,
		tagNumber: tagNum,
	}
}

// FullyQualifiedTag returns a new fully-qualified profile-specific tag.
func FullyQualifiedTag(vendorID, profileNum uint16, tagNum uint32) Tag {
	ctrl := TagControlFullyQualified6
	if tagNum >= 65536 {
		ctrl = TagControlFullyQualified8
	}
	return Tag{
		control:       ctrl,
		vendorID:      vendorID,
		profileNumber: profileNum,
		tagNumber:     tagNum,
	}
}

// Control returns the tag control form.
func (t Tag) Control() TagControl {
	return t.control
}

// IsAnonymous returns true if this is an anonymous tag.
func (t Tag) IsAnonymous() bool {
	return t.control == TagControlAnonymous
}

// IsContext returns true if this is a context-specific tag.
func (t Tag) IsContext() bool {
	return t.control == TagControlContext
}

// IsProfileSpecific returns true if this is a profile-specific tag
// (common profile, implicit profile, or fully qualified).
func (t Tag) IsProfileSpecific() bool {
	return t.control >= TagControlCommonProfile2
}

// VendorID returns the vendor ID for fully-qualified tags.
// Returns 0 for other tag types.
func (t Tag) VendorID() uint16 {
	return t.vendorID
}

// ProfileNumber returns the profile number for fully-qualified tags.
// Returns 0 for other tag types.
func (t Tag) ProfileNumber() uint16 {
	return t.profileNumber
}

// TagNumber returns the tag number.
// For context-specific tags, this is 0-255.
// For profile-specific tags, this can be up to 32 bits.
func (t Tag) TagNumber() uint32 {
	return t.tagNumber
}

// Size returns the encoded size in bytes of this tag.
func (t Tag) Size() int {
	return t.control.Size()
}

// WriteTo writes the tag to the given writer in little-endian order (Spec A.8).
func (t Tag) WriteTo(w io.Writer) (int64, error) {
	var buf [8]byte

	switch t.control {
	case TagControlAnonymous:
		return 0, nil

	case TagControlContext:
		buf[0] = byte(t.tagNumber)
		n, err := w.Write(buf[:1])
		return int64(n), err

	case TagControlCommonProfile2, TagControlImplicitProfile2:
		binary.LittleEndian.PutUint16(buf[:2], uint16(t.tagNumber))
		n, err := w.Write(buf[:2])
		return int64(n), err

	case TagControlCommonProfile4, TagControlImplicitProfile4:
		binary.LittleEndian.PutUint32(buf[:4], t.tagNumber)
		n, err := w.Write(buf[:4])
		return int64(n), err

	case TagControlFullyQualified6:
		binary.LittleEndian.PutUint16(buf[0:2], t.vendorID)
		binary.LittleEndian.PutUint16(buf[2:4], t.profileNumber)
		binary.LittleEndian.PutUint16(buf[4:6], uint16(t.tagNumber))
		n, err := w.Write(buf[:6])
		return int64(n), err

	case TagControlFullyQualified8:
		binary.LittleEndian.PutUint16(buf[0:2], t.vendorID)
		binary.LittleEndian.PutUint16(buf[2:4], t.profileNumber)
		binary.LittleEndian.PutUint32(buf[4:8], t.tagNumber)
		n, err := w.Write(buf[:8])
		return int64(n), err
	}

	return 0, nil
}

// ReadTag reads a tag from the given reader based on the tag control.
func ReadTag(r io.Reader, ctrl TagControl) (Tag, error) {
	tag := Tag{control: ctrl}
	var buf [8]byte

	switch ctrl {
	case TagControlAnonymous:
		return tag, nil

	case TagControlContext:
		if _, err := io.ReadFull(r, buf[:1]); err != nil {
			return tag, err
		}
		tag.tagNumber = uint32(buf[0])

	case TagControlCommonProfile2, TagControlImplicitProfile2:
		if _, err := io.ReadFull(r, buf[:2]); err != nil {
			return tag, err
		}
		tag.tagNumber = uint32(binary.LittleEndian.Uint16(buf[:2]))

	case TagControlCommonProfile4, TagControlImplicitProfile4:
		if _, err := io.ReadFull(r, buf[:4]); err != nil {
			return tag, err
		}
		tag.tagNumber = binary.LittleEndian.Uint32(buf[:4])

	case TagControlFullyQualified6:
		if _, err := io.ReadFull(r, buf[:6]); err != nil {
			return tag, err
		}
		tag.vendorID = binary.LittleEndian.Uint16(buf[0:2])
		tag.profileNumber = binary.LittleEndian.Uint16(buf[2:4])
		tag.tagNumber = uint32(binary.LittleEndian.Uint16(buf[4:6]))

	case TagControlFullyQualified8:
		if _, err := io.ReadFull(r, buf[:8]); err != nil {
			return tag, err
		}
		tag.vendorID = binary.LittleEndian.Uint16(buf[0:2])
		tag.profileNumber = binary.LittleEndian.Uint16(buf[2:4])
		tag.tagNumber = binary.LittleEndian.Uint32(buf[4:8])
	}

	return tag, nil
}
