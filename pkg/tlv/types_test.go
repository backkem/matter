package tlv

import "testing"

func TestElementType_String(t *testing.T) {
	testCases := []struct {
		elemType ElementType
		expected string
	}{
		{ElementTypeInt8, "Int8"},
		{ElementTypeInt16, "Int16"},
		{ElementTypeInt32, "Int32"},
		{ElementTypeInt64, "Int64"},
		{ElementTypeUInt8, "UInt8"},
		{ElementTypeUInt16, "UInt16"},
		{ElementTypeUInt32, "UInt32"},
		{ElementTypeUInt64, "UInt64"},
		{ElementTypeFalse, "False"},
		{ElementTypeTrue, "True"},
		{ElementTypeFloat32, "Float32"},
		{ElementTypeFloat64, "Float64"},
		{ElementTypeUTF8_1, "UTF8_1"},
		{ElementTypeUTF8_2, "UTF8_2"},
		{ElementTypeUTF8_4, "UTF8_4"},
		{ElementTypeUTF8_8, "UTF8_8"},
		{ElementTypeBytes1, "Bytes1"},
		{ElementTypeBytes2, "Bytes2"},
		{ElementTypeBytes4, "Bytes4"},
		{ElementTypeBytes8, "Bytes8"},
		{ElementTypeNull, "Null"},
		{ElementTypeStruct, "Struct"},
		{ElementTypeArray, "Array"},
		{ElementTypeList, "List"},
		{ElementTypeEnd, "EndOfContainer"},
		{ElementType(99), "Unknown"},
		{ElementType(-1), "Unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			got := tc.elemType.String()
			if got != tc.expected {
				t.Errorf("ElementType(%d).String() = %q, want %q", tc.elemType, got, tc.expected)
			}
		})
	}
}

func TestElementType_IsSignedInt(t *testing.T) {
	signed := []ElementType{ElementTypeInt8, ElementTypeInt16, ElementTypeInt32, ElementTypeInt64}
	notSigned := []ElementType{
		ElementTypeUInt8, ElementTypeUInt16, ElementTypeUInt32, ElementTypeUInt64,
		ElementTypeFalse, ElementTypeTrue, ElementTypeFloat32, ElementTypeFloat64,
		ElementTypeUTF8_1, ElementTypeBytes1, ElementTypeNull, ElementTypeStruct,
	}

	for _, et := range signed {
		if !et.IsSignedInt() {
			t.Errorf("%v.IsSignedInt() = false, want true", et)
		}
	}
	for _, et := range notSigned {
		if et.IsSignedInt() {
			t.Errorf("%v.IsSignedInt() = true, want false", et)
		}
	}
}

func TestElementType_IsUnsignedInt(t *testing.T) {
	unsigned := []ElementType{ElementTypeUInt8, ElementTypeUInt16, ElementTypeUInt32, ElementTypeUInt64}
	notUnsigned := []ElementType{
		ElementTypeInt8, ElementTypeInt16, ElementTypeInt32, ElementTypeInt64,
		ElementTypeFalse, ElementTypeTrue, ElementTypeFloat32, ElementTypeFloat64,
		ElementTypeUTF8_1, ElementTypeBytes1, ElementTypeNull, ElementTypeStruct,
	}

	for _, et := range unsigned {
		if !et.IsUnsignedInt() {
			t.Errorf("%v.IsUnsignedInt() = false, want true", et)
		}
	}
	for _, et := range notUnsigned {
		if et.IsUnsignedInt() {
			t.Errorf("%v.IsUnsignedInt() = true, want false", et)
		}
	}
}

func TestElementType_IsInt(t *testing.T) {
	ints := []ElementType{
		ElementTypeInt8, ElementTypeInt16, ElementTypeInt32, ElementTypeInt64,
		ElementTypeUInt8, ElementTypeUInt16, ElementTypeUInt32, ElementTypeUInt64,
	}
	notInts := []ElementType{
		ElementTypeFalse, ElementTypeTrue, ElementTypeFloat32, ElementTypeFloat64,
		ElementTypeUTF8_1, ElementTypeBytes1, ElementTypeNull, ElementTypeStruct,
	}

	for _, et := range ints {
		if !et.IsInt() {
			t.Errorf("%v.IsInt() = false, want true", et)
		}
	}
	for _, et := range notInts {
		if et.IsInt() {
			t.Errorf("%v.IsInt() = true, want false", et)
		}
	}
}

func TestElementType_IsBool(t *testing.T) {
	bools := []ElementType{ElementTypeFalse, ElementTypeTrue}
	notBools := []ElementType{
		ElementTypeInt8, ElementTypeUInt8, ElementTypeFloat32,
		ElementTypeUTF8_1, ElementTypeBytes1, ElementTypeNull, ElementTypeStruct,
	}

	for _, et := range bools {
		if !et.IsBool() {
			t.Errorf("%v.IsBool() = false, want true", et)
		}
	}
	for _, et := range notBools {
		if et.IsBool() {
			t.Errorf("%v.IsBool() = true, want false", et)
		}
	}
}

func TestElementType_IsFloat(t *testing.T) {
	floats := []ElementType{ElementTypeFloat32, ElementTypeFloat64}
	notFloats := []ElementType{
		ElementTypeInt8, ElementTypeUInt8, ElementTypeFalse,
		ElementTypeUTF8_1, ElementTypeBytes1, ElementTypeNull, ElementTypeStruct,
	}

	for _, et := range floats {
		if !et.IsFloat() {
			t.Errorf("%v.IsFloat() = false, want true", et)
		}
	}
	for _, et := range notFloats {
		if et.IsFloat() {
			t.Errorf("%v.IsFloat() = true, want false", et)
		}
	}
}

func TestElementType_IsUTF8String(t *testing.T) {
	utf8s := []ElementType{ElementTypeUTF8_1, ElementTypeUTF8_2, ElementTypeUTF8_4, ElementTypeUTF8_8}
	notUTF8s := []ElementType{
		ElementTypeInt8, ElementTypeUInt8, ElementTypeFalse, ElementTypeFloat32,
		ElementTypeBytes1, ElementTypeBytes2, ElementTypeNull, ElementTypeStruct,
	}

	for _, et := range utf8s {
		if !et.IsUTF8String() {
			t.Errorf("%v.IsUTF8String() = false, want true", et)
		}
	}
	for _, et := range notUTF8s {
		if et.IsUTF8String() {
			t.Errorf("%v.IsUTF8String() = true, want false", et)
		}
	}
}

func TestElementType_IsBytes(t *testing.T) {
	bytess := []ElementType{ElementTypeBytes1, ElementTypeBytes2, ElementTypeBytes4, ElementTypeBytes8}
	notBytes := []ElementType{
		ElementTypeInt8, ElementTypeUInt8, ElementTypeFalse, ElementTypeFloat32,
		ElementTypeUTF8_1, ElementTypeUTF8_2, ElementTypeNull, ElementTypeStruct,
	}

	for _, et := range bytess {
		if !et.IsBytes() {
			t.Errorf("%v.IsBytes() = false, want true", et)
		}
	}
	for _, et := range notBytes {
		if et.IsBytes() {
			t.Errorf("%v.IsBytes() = true, want false", et)
		}
	}
}

func TestElementType_IsString(t *testing.T) {
	strings := []ElementType{
		ElementTypeUTF8_1, ElementTypeUTF8_2, ElementTypeUTF8_4, ElementTypeUTF8_8,
		ElementTypeBytes1, ElementTypeBytes2, ElementTypeBytes4, ElementTypeBytes8,
	}
	notStrings := []ElementType{
		ElementTypeInt8, ElementTypeUInt8, ElementTypeFalse, ElementTypeFloat32,
		ElementTypeNull, ElementTypeStruct, ElementTypeArray, ElementTypeList,
	}

	for _, et := range strings {
		if !et.IsString() {
			t.Errorf("%v.IsString() = false, want true", et)
		}
	}
	for _, et := range notStrings {
		if et.IsString() {
			t.Errorf("%v.IsString() = true, want false", et)
		}
	}
}

func TestElementType_IsContainer(t *testing.T) {
	containers := []ElementType{ElementTypeStruct, ElementTypeArray, ElementTypeList}
	notContainers := []ElementType{
		ElementTypeInt8, ElementTypeUInt8, ElementTypeFalse, ElementTypeFloat32,
		ElementTypeUTF8_1, ElementTypeBytes1, ElementTypeNull, ElementTypeEnd,
	}

	for _, et := range containers {
		if !et.IsContainer() {
			t.Errorf("%v.IsContainer() = false, want true", et)
		}
	}
	for _, et := range notContainers {
		if et.IsContainer() {
			t.Errorf("%v.IsContainer() = true, want false", et)
		}
	}
}

func TestElementType_ValueSize(t *testing.T) {
	testCases := []struct {
		elemType ElementType
		expected int
	}{
		{ElementTypeInt8, 1},
		{ElementTypeUInt8, 1},
		{ElementTypeInt16, 2},
		{ElementTypeUInt16, 2},
		{ElementTypeInt32, 4},
		{ElementTypeUInt32, 4},
		{ElementTypeFloat32, 4},
		{ElementTypeInt64, 8},
		{ElementTypeUInt64, 8},
		{ElementTypeFloat64, 8},
		{ElementTypeFalse, 0},
		{ElementTypeTrue, 0},
		{ElementTypeNull, 0},
		{ElementTypeStruct, 0},
		{ElementTypeArray, 0},
		{ElementTypeList, 0},
		{ElementTypeEnd, 0},
		{ElementTypeUTF8_1, 0}, // Variable length
		{ElementTypeBytes1, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.elemType.String(), func(t *testing.T) {
			got := tc.elemType.ValueSize()
			if got != tc.expected {
				t.Errorf("%v.ValueSize() = %d, want %d", tc.elemType, got, tc.expected)
			}
		})
	}
}

func TestElementType_LengthFieldSize(t *testing.T) {
	testCases := []struct {
		elemType ElementType
		expected int
	}{
		{ElementTypeUTF8_1, 1},
		{ElementTypeUTF8_2, 2},
		{ElementTypeUTF8_4, 4},
		{ElementTypeUTF8_8, 8},
		{ElementTypeBytes1, 1},
		{ElementTypeBytes2, 2},
		{ElementTypeBytes4, 4},
		{ElementTypeBytes8, 8},
		{ElementTypeInt8, 0},
		{ElementTypeUInt8, 0},
		{ElementTypeFalse, 0},
		{ElementTypeNull, 0},
		{ElementTypeStruct, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.elemType.String(), func(t *testing.T) {
			got := tc.elemType.LengthFieldSize()
			if got != tc.expected {
				t.Errorf("%v.LengthFieldSize() = %d, want %d", tc.elemType, got, tc.expected)
			}
		})
	}
}

func TestTagControl_String(t *testing.T) {
	testCases := []struct {
		ctrl     TagControl
		expected string
	}{
		{TagControlAnonymous, "Anonymous"},
		{TagControlContext, "Context"},
		{TagControlCommonProfile2, "CommonProfile2"},
		{TagControlCommonProfile4, "CommonProfile4"},
		{TagControlImplicitProfile2, "ImplicitProfile2"},
		{TagControlImplicitProfile4, "ImplicitProfile4"},
		{TagControlFullyQualified6, "FullyQualified6"},
		{TagControlFullyQualified8, "FullyQualified8"},
		{TagControl(99), "Unknown"},
		{TagControl(-1), "Unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			got := tc.ctrl.String()
			if got != tc.expected {
				t.Errorf("TagControl(%d).String() = %q, want %q", tc.ctrl, got, tc.expected)
			}
		})
	}
}

func TestTagControl_Size(t *testing.T) {
	testCases := []struct {
		ctrl     TagControl
		expected int
	}{
		{TagControlAnonymous, 0},
		{TagControlContext, 1},
		{TagControlCommonProfile2, 2},
		{TagControlCommonProfile4, 4},
		{TagControlImplicitProfile2, 2},
		{TagControlImplicitProfile4, 4},
		{TagControlFullyQualified6, 6},
		{TagControlFullyQualified8, 8},
		{TagControl(99), 0},
	}

	for _, tc := range testCases {
		t.Run(tc.ctrl.String(), func(t *testing.T) {
			got := tc.ctrl.Size()
			if got != tc.expected {
				t.Errorf("%v.Size() = %d, want %d", tc.ctrl, got, tc.expected)
			}
		})
	}
}

func TestTag_Constructors(t *testing.T) {
	t.Run("Anonymous", func(t *testing.T) {
		tag := Anonymous()
		if !tag.IsAnonymous() {
			t.Error("Anonymous().IsAnonymous() = false")
		}
		if tag.Control() != TagControlAnonymous {
			t.Errorf("Control() = %v, want Anonymous", tag.Control())
		}
	})

	t.Run("ContextTag", func(t *testing.T) {
		for _, num := range []uint8{0, 1, 127, 255} {
			tag := ContextTag(num)
			if !tag.IsContext() {
				t.Errorf("ContextTag(%d).IsContext() = false", num)
			}
			if tag.TagNumber() != uint32(num) {
				t.Errorf("TagNumber() = %d, want %d", tag.TagNumber(), num)
			}
		}
	})

	t.Run("CommonProfileTag_2byte", func(t *testing.T) {
		tag := CommonProfileTag(1)
		if tag.Control() != TagControlCommonProfile2 {
			t.Errorf("Control() = %v, want CommonProfile2", tag.Control())
		}
		if tag.TagNumber() != 1 {
			t.Errorf("TagNumber() = %d, want 1", tag.TagNumber())
		}
	})

	t.Run("CommonProfileTag_4byte", func(t *testing.T) {
		tag := CommonProfileTag(65536)
		if tag.Control() != TagControlCommonProfile4 {
			t.Errorf("Control() = %v, want CommonProfile4", tag.Control())
		}
		if tag.TagNumber() != 65536 {
			t.Errorf("TagNumber() = %d, want 65536", tag.TagNumber())
		}
	})

	t.Run("ImplicitProfileTag_2byte", func(t *testing.T) {
		tag := ImplicitProfileTag(100)
		if tag.Control() != TagControlImplicitProfile2 {
			t.Errorf("Control() = %v, want ImplicitProfile2", tag.Control())
		}
		if tag.TagNumber() != 100 {
			t.Errorf("TagNumber() = %d, want 100", tag.TagNumber())
		}
	})

	t.Run("ImplicitProfileTag_4byte", func(t *testing.T) {
		tag := ImplicitProfileTag(100000)
		if tag.Control() != TagControlImplicitProfile4 {
			t.Errorf("Control() = %v, want ImplicitProfile4", tag.Control())
		}
		if tag.TagNumber() != 100000 {
			t.Errorf("TagNumber() = %d, want 100000", tag.TagNumber())
		}
	})

	t.Run("FullyQualifiedTag_6byte", func(t *testing.T) {
		tag := FullyQualifiedTag(0xFFF1, 0xDEED, 1)
		if tag.Control() != TagControlFullyQualified6 {
			t.Errorf("Control() = %v, want FullyQualified6", tag.Control())
		}
		if tag.VendorID() != 0xFFF1 {
			t.Errorf("VendorID() = 0x%04X, want 0xFFF1", tag.VendorID())
		}
		if tag.ProfileNumber() != 0xDEED {
			t.Errorf("ProfileNumber() = 0x%04X, want 0xDEED", tag.ProfileNumber())
		}
		if tag.TagNumber() != 1 {
			t.Errorf("TagNumber() = %d, want 1", tag.TagNumber())
		}
	})

	t.Run("FullyQualifiedTag_8byte", func(t *testing.T) {
		tag := FullyQualifiedTag(0xFFF1, 0xDEED, 0xAA55FEED)
		if tag.Control() != TagControlFullyQualified8 {
			t.Errorf("Control() = %v, want FullyQualified8", tag.Control())
		}
		if tag.TagNumber() != 0xAA55FEED {
			t.Errorf("TagNumber() = 0x%08X, want 0xAA55FEED", tag.TagNumber())
		}
	})
}

func TestTag_IsProfileSpecific(t *testing.T) {
	profileSpecific := []Tag{
		CommonProfileTag(1),
		CommonProfileTag(100000),
		ImplicitProfileTag(1),
		ImplicitProfileTag(100000),
		FullyQualifiedTag(1, 2, 3),
		FullyQualifiedTag(1, 2, 100000),
	}
	notProfileSpecific := []Tag{
		Anonymous(),
		ContextTag(0),
		ContextTag(255),
	}

	for _, tag := range profileSpecific {
		if !tag.IsProfileSpecific() {
			t.Errorf("Tag with control %v should be profile specific", tag.Control())
		}
	}
	for _, tag := range notProfileSpecific {
		if tag.IsProfileSpecific() {
			t.Errorf("Tag with control %v should not be profile specific", tag.Control())
		}
	}
}

func TestTag_Size(t *testing.T) {
	testCases := []struct {
		name     string
		tag      Tag
		expected int
	}{
		{"anonymous", Anonymous(), 0},
		{"context", ContextTag(0), 1},
		{"common_2", CommonProfileTag(1), 2},
		{"common_4", CommonProfileTag(100000), 4},
		{"implicit_2", ImplicitProfileTag(1), 2},
		{"implicit_4", ImplicitProfileTag(100000), 4},
		{"fq_6", FullyQualifiedTag(1, 2, 3), 6},
		{"fq_8", FullyQualifiedTag(1, 2, 100000), 8},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.tag.Size()
			if got != tc.expected {
				t.Errorf("Size() = %d, want %d", got, tc.expected)
			}
		})
	}
}

func TestControlOctet(t *testing.T) {
	testCases := []struct {
		ctrl     byte
		elemType ElementType
		tagCtrl  TagControl
	}{
		{0x00, ElementTypeInt8, TagControlAnonymous},
		{0x04, ElementTypeUInt8, TagControlAnonymous},
		{0x08, ElementTypeFalse, TagControlAnonymous},
		{0x09, ElementTypeTrue, TagControlAnonymous},
		{0x14, ElementTypeNull, TagControlAnonymous},
		{0x15, ElementTypeStruct, TagControlAnonymous},
		{0x16, ElementTypeArray, TagControlAnonymous},
		{0x17, ElementTypeList, TagControlAnonymous},
		{0x18, ElementTypeEnd, TagControlAnonymous},
		{0x20, ElementTypeInt8, TagControlContext},
		{0x24, ElementTypeUInt8, TagControlContext},
		{0x44, ElementTypeUInt8, TagControlCommonProfile2},
		{0x64, ElementTypeUInt8, TagControlCommonProfile4},
		{0x84, ElementTypeUInt8, TagControlImplicitProfile2},
		{0xa4, ElementTypeUInt8, TagControlImplicitProfile4},
		{0xc4, ElementTypeUInt8, TagControlFullyQualified6},
		{0xe4, ElementTypeUInt8, TagControlFullyQualified8},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			// Test parsing
			gotElem, gotTag := ParseControlOctet(tc.ctrl)
			if gotElem != tc.elemType {
				t.Errorf("ParseControlOctet(0x%02x): elemType = %v, want %v", tc.ctrl, gotElem, tc.elemType)
			}
			if gotTag != tc.tagCtrl {
				t.Errorf("ParseControlOctet(0x%02x): tagCtrl = %v, want %v", tc.ctrl, gotTag, tc.tagCtrl)
			}

			// Test building
			built := BuildControlOctet(tc.elemType, tc.tagCtrl)
			if built != tc.ctrl {
				t.Errorf("BuildControlOctet(%v, %v) = 0x%02x, want 0x%02x", tc.elemType, tc.tagCtrl, built, tc.ctrl)
			}
		})
	}
}
