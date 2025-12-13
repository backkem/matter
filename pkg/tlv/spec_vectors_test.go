package tlv

import (
	"bytes"
	"math"
	"testing"
)

// Test vectors from Matter 1.5 Specification Appendix A.12

// Table 125: Sample encoding of primitive types (all anonymous)
var table125Vectors = []struct {
	name     string
	encoding []byte
	check    func(t *testing.T, r *Reader)
}{
	{
		name:     "Boolean false",
		encoding: []byte{0x08},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeFalse {
				t.Errorf("expected False, got %v", r.Type())
			}
			v, err := r.Bool()
			if err != nil {
				t.Fatalf("Bool() error: %v", err)
			}
			if v != false {
				t.Errorf("expected false, got %v", v)
			}
		},
	},
	{
		name:     "Boolean true",
		encoding: []byte{0x09},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeTrue {
				t.Errorf("expected True, got %v", r.Type())
			}
			v, err := r.Bool()
			if err != nil {
				t.Fatalf("Bool() error: %v", err)
			}
			if v != true {
				t.Errorf("expected true, got %v", v)
			}
		},
	},
	{
		name:     "Signed Integer, 1-octet, value 42",
		encoding: []byte{0x00, 0x2a},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeInt8 {
				t.Errorf("expected Int8, got %v", r.Type())
			}
			v, err := r.Int()
			if err != nil {
				t.Fatalf("Int() error: %v", err)
			}
			if v != 42 {
				t.Errorf("expected 42, got %v", v)
			}
		},
	},
	{
		name:     "Signed Integer, 1-octet, value -17",
		encoding: []byte{0x00, 0xef},
		check: func(t *testing.T, r *Reader) {
			v, err := r.Int()
			if err != nil {
				t.Fatalf("Int() error: %v", err)
			}
			if v != -17 {
				t.Errorf("expected -17, got %v", v)
			}
		},
	},
	{
		name:     "Unsigned Integer, 1-octet, value 42U",
		encoding: []byte{0x04, 0x2a},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeUInt8 {
				t.Errorf("expected UInt8, got %v", r.Type())
			}
			v, err := r.Uint()
			if err != nil {
				t.Fatalf("Uint() error: %v", err)
			}
			if v != 42 {
				t.Errorf("expected 42, got %v", v)
			}
		},
	},
	{
		name:     "Signed Integer, 2-octet, value 42",
		encoding: []byte{0x01, 0x2a, 0x00},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeInt16 {
				t.Errorf("expected Int16, got %v", r.Type())
			}
			v, err := r.Int()
			if err != nil {
				t.Fatalf("Int() error: %v", err)
			}
			if v != 42 {
				t.Errorf("expected 42, got %v", v)
			}
		},
	},
	{
		name:     "Signed Integer, 4-octet, value -170000",
		encoding: []byte{0x02, 0xf0, 0x67, 0xfd, 0xff},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeInt32 {
				t.Errorf("expected Int32, got %v", r.Type())
			}
			v, err := r.Int()
			if err != nil {
				t.Fatalf("Int() error: %v", err)
			}
			if v != -170000 {
				t.Errorf("expected -170000, got %v", v)
			}
		},
	},
	{
		name:     "Signed Integer, 8-octet, value 40000000000",
		encoding: []byte{0x03, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeInt64 {
				t.Errorf("expected Int64, got %v", r.Type())
			}
			v, err := r.Int()
			if err != nil {
				t.Fatalf("Int() error: %v", err)
			}
			if v != 40000000000 {
				t.Errorf("expected 40000000000, got %v", v)
			}
		},
	},
	{
		name:     "UTF-8 String, 1-octet length, Hello!",
		encoding: []byte{0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeUTF8_1 {
				t.Errorf("expected UTF8_1, got %v", r.Type())
			}
			v, err := r.String()
			if err != nil {
				t.Fatalf("String() error: %v", err)
			}
			if v != "Hello!" {
				t.Errorf("expected 'Hello!', got %q", v)
			}
		},
	},
	{
		name:     "UTF-8 String, 1-octet length, Tschüs (with umlaut)",
		encoding: []byte{0x0c, 0x07, 0x54, 0x73, 0x63, 0x68, 0xc3, 0xbc, 0x73},
		check: func(t *testing.T, r *Reader) {
			v, err := r.String()
			if err != nil {
				t.Fatalf("String() error: %v", err)
			}
			if v != "Tschüs" {
				t.Errorf("expected 'Tschüs', got %q", v)
			}
		},
	},
	{
		name:     "Octet String, 1-octet length, octets 00 01 02 03 04",
		encoding: []byte{0x10, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeBytes1 {
				t.Errorf("expected Bytes1, got %v", r.Type())
			}
			v, err := r.Bytes()
			if err != nil {
				t.Fatalf("Bytes() error: %v", err)
			}
			expected := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
			if !bytes.Equal(v, expected) {
				t.Errorf("expected %v, got %v", expected, v)
			}
		},
	},
	{
		name:     "Null",
		encoding: []byte{0x14},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeNull {
				t.Errorf("expected Null, got %v", r.Type())
			}
			err := r.Null()
			if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		},
	},
	{
		name:     "Single precision floating point 0.0",
		encoding: []byte{0x0a, 0x00, 0x00, 0x00, 0x00},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeFloat32 {
				t.Errorf("expected Float32, got %v", r.Type())
			}
			v, err := r.Float32()
			if err != nil {
				t.Fatalf("Float32() error: %v", err)
			}
			if v != 0.0 {
				t.Errorf("expected 0.0, got %v", v)
			}
		},
	},
	{
		name:     "Single precision floating point (1.0 / 3.0)",
		encoding: []byte{0x0a, 0xab, 0xaa, 0xaa, 0x3e},
		check: func(t *testing.T, r *Reader) {
			v, err := r.Float32()
			if err != nil {
				t.Fatalf("Float32() error: %v", err)
			}
			expected := float32(1.0 / 3.0)
			if v != expected {
				t.Errorf("expected %v, got %v", expected, v)
			}
		},
	},
	{
		name:     "Single precision floating point 17.9",
		encoding: []byte{0x0a, 0x33, 0x33, 0x8f, 0x41},
		check: func(t *testing.T, r *Reader) {
			v, err := r.Float32()
			if err != nil {
				t.Fatalf("Float32() error: %v", err)
			}
			expected := float32(17.9)
			if v != expected {
				t.Errorf("expected %v, got %v", expected, v)
			}
		},
	},
	{
		name:     "Single precision floating point infinity",
		encoding: []byte{0x0a, 0x00, 0x00, 0x80, 0x7f},
		check: func(t *testing.T, r *Reader) {
			v, err := r.Float32()
			if err != nil {
				t.Fatalf("Float32() error: %v", err)
			}
			if !math.IsInf(float64(v), 1) {
				t.Errorf("expected +Inf, got %v", v)
			}
		},
	},
	{
		name:     "Single precision floating point negative infinity",
		encoding: []byte{0x0a, 0x00, 0x00, 0x80, 0xff},
		check: func(t *testing.T, r *Reader) {
			v, err := r.Float32()
			if err != nil {
				t.Fatalf("Float32() error: %v", err)
			}
			if !math.IsInf(float64(v), -1) {
				t.Errorf("expected -Inf, got %v", v)
			}
		},
	},
	{
		name:     "Double precision floating point 0.0",
		encoding: []byte{0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeFloat64 {
				t.Errorf("expected Float64, got %v", r.Type())
			}
			v, err := r.Float64()
			if err != nil {
				t.Fatalf("Float64() error: %v", err)
			}
			if v != 0.0 {
				t.Errorf("expected 0.0, got %v", v)
			}
		},
	},
	{
		name:     "Double precision floating point (1.0 / 3.0)",
		encoding: []byte{0x0b, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0xd5, 0x3f},
		check: func(t *testing.T, r *Reader) {
			v, err := r.Float64()
			if err != nil {
				t.Fatalf("Float64() error: %v", err)
			}
			expected := 1.0 / 3.0
			if v != expected {
				t.Errorf("expected %v, got %v", expected, v)
			}
		},
	},
	{
		name:     "Double precision floating point 17.9",
		encoding: []byte{0x0b, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6, 0x31, 0x40},
		check: func(t *testing.T, r *Reader) {
			v, err := r.Float64()
			if err != nil {
				t.Fatalf("Float64() error: %v", err)
			}
			expected := 17.9
			if v != expected {
				t.Errorf("expected %v, got %v", expected, v)
			}
		},
	},
	{
		name:     "Double precision floating point infinity",
		encoding: []byte{0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x7f},
		check: func(t *testing.T, r *Reader) {
			v, err := r.Float64()
			if err != nil {
				t.Fatalf("Float64() error: %v", err)
			}
			if !math.IsInf(v, 1) {
				t.Errorf("expected +Inf, got %v", v)
			}
		},
	},
	{
		name:     "Double precision floating point negative infinity",
		encoding: []byte{0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff},
		check: func(t *testing.T, r *Reader) {
			v, err := r.Float64()
			if err != nil {
				t.Fatalf("Float64() error: %v", err)
			}
			if !math.IsInf(v, -1) {
				t.Errorf("expected -Inf, got %v", v)
			}
		},
	},
}

// Table 126: Sample encoding of containers (all anonymous)
var table126Vectors = []struct {
	name     string
	encoding []byte
	check    func(t *testing.T, r *Reader)
}{
	{
		name:     "Empty Structure, {}",
		encoding: []byte{0x15, 0x18},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeStruct {
				t.Errorf("expected Struct, got %v", r.Type())
			}
			if err := r.EnterContainer(); err != nil {
				t.Fatalf("EnterContainer failed: %v", err)
			}
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			if r.Type() != ElementTypeEnd {
				t.Errorf("expected EndOfContainer, got %v", r.Type())
			}
		},
	},
	{
		name:     "Empty Array, []",
		encoding: []byte{0x16, 0x18},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeArray {
				t.Errorf("expected Array, got %v", r.Type())
			}
			if err := r.EnterContainer(); err != nil {
				t.Fatalf("EnterContainer failed: %v", err)
			}
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			if r.Type() != ElementTypeEnd {
				t.Errorf("expected EndOfContainer, got %v", r.Type())
			}
		},
	},
	{
		name:     "Empty List, []",
		encoding: []byte{0x17, 0x18},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeList {
				t.Errorf("expected List, got %v", r.Type())
			}
			if err := r.EnterContainer(); err != nil {
				t.Fatalf("EnterContainer failed: %v", err)
			}
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			if r.Type() != ElementTypeEnd {
				t.Errorf("expected EndOfContainer, got %v", r.Type())
			}
		},
	},
	{
		name:     "Structure, two context specific tags, {0 = 42, 1 = -17}",
		encoding: []byte{0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeStruct {
				t.Errorf("expected Struct, got %v", r.Type())
			}
			if err := r.EnterContainer(); err != nil {
				t.Fatalf("EnterContainer failed: %v", err)
			}

			// First element: context tag 0, value 42
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			if !r.Tag().IsContext() || r.Tag().TagNumber() != 0 {
				t.Errorf("expected context tag 0, got %v", r.Tag())
			}
			v, err := r.Int()
			if err != nil {
				t.Fatalf("Int() error: %v", err)
			}
			if v != 42 {
				t.Errorf("expected 42, got %v", v)
			}

			// Second element: context tag 1, value -17
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			if !r.Tag().IsContext() || r.Tag().TagNumber() != 1 {
				t.Errorf("expected context tag 1, got %v", r.Tag())
			}
			v, err = r.Int()
			if err != nil {
				t.Fatalf("Int() error: %v", err)
			}
			if v != -17 {
				t.Errorf("expected -17, got %v", v)
			}

			// End of container
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			if r.Type() != ElementTypeEnd {
				t.Errorf("expected EndOfContainer, got %v", r.Type())
			}
		},
	},
	{
		name:     "Array, Signed Integer, 1-octet values, [0, 1, 2, 3, 4]",
		encoding: []byte{0x16, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x18},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeArray {
				t.Errorf("expected Array, got %v", r.Type())
			}
			if err := r.EnterContainer(); err != nil {
				t.Fatalf("EnterContainer failed: %v", err)
			}

			expected := []int64{0, 1, 2, 3, 4}
			for i, exp := range expected {
				if err := r.Next(); err != nil {
					t.Fatalf("Next failed at index %d: %v", i, err)
				}
				if !r.Tag().IsAnonymous() {
					t.Errorf("expected anonymous tag at index %d", i)
				}
				v, err := r.Int()
				if err != nil {
					t.Fatalf("Int() error at index %d: %v", i, err)
				}
				if v != exp {
					t.Errorf("at index %d: expected %d, got %v", i, exp, v)
				}
			}

			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			if r.Type() != ElementTypeEnd {
				t.Errorf("expected EndOfContainer, got %v", r.Type())
			}
		},
	},
	{
		name:     "List, mix of anonymous and context tags, [[1, 0 = 42, 2, 3, 0 = -17]]",
		encoding: []byte{0x17, 0x00, 0x01, 0x20, 0x00, 0x2a, 0x00, 0x02, 0x00, 0x03, 0x20, 0x00, 0xef, 0x18},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeList {
				t.Errorf("expected List, got %v", r.Type())
			}
			if err := r.EnterContainer(); err != nil {
				t.Fatalf("EnterContainer failed: %v", err)
			}

			// Element 1: anonymous, value 1
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			if !r.Tag().IsAnonymous() {
				t.Errorf("expected anonymous tag")
			}
			v, err := r.Int()
			if err != nil {
				t.Fatalf("Int() error: %v", err)
			}
			if v != 1 {
				t.Errorf("expected 1, got %v", v)
			}

			// Element 2: context tag 0, value 42
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			if !r.Tag().IsContext() || r.Tag().TagNumber() != 0 {
				t.Errorf("expected context tag 0")
			}
			v, err = r.Int()
			if err != nil {
				t.Fatalf("Int() error: %v", err)
			}
			if v != 42 {
				t.Errorf("expected 42, got %v", v)
			}

			// Element 3: anonymous, value 2
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			v, err = r.Int()
			if err != nil {
				t.Fatalf("Int() error: %v", err)
			}
			if v != 2 {
				t.Errorf("expected 2, got %v", v)
			}

			// Element 4: anonymous, value 3
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			v, err = r.Int()
			if err != nil {
				t.Fatalf("Int() error: %v", err)
			}
			if v != 3 {
				t.Errorf("expected 3, got %v", v)
			}

			// Element 5: context tag 0, value -17
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			if !r.Tag().IsContext() || r.Tag().TagNumber() != 0 {
				t.Errorf("expected context tag 0")
			}
			v, err = r.Int()
			if err != nil {
				t.Fatalf("Int() error: %v", err)
			}
			if v != -17 {
				t.Errorf("expected -17, got %v", v)
			}
		},
	},
	{
		name:     "Array, mix of element types, [42, -170000, {}, 17.9, Hello!]",
		encoding: []byte{0x16, 0x00, 0x2a, 0x02, 0xf0, 0x67, 0xfd, 0xff, 0x15, 0x18, 0x0a, 0x33, 0x33, 0x8f, 0x41, 0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x18},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeArray {
				t.Errorf("expected Array, got %v", r.Type())
			}
			if err := r.EnterContainer(); err != nil {
				t.Fatalf("EnterContainer failed: %v", err)
			}

			// Element 1: int 42
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			v, err := r.Int()
			if err != nil {
				t.Fatalf("Int() error: %v", err)
			}
			if v != 42 {
				t.Errorf("expected 42, got %v", v)
			}

			// Element 2: int -170000
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			v, err = r.Int()
			if err != nil {
				t.Fatalf("Int() error: %v", err)
			}
			if v != -170000 {
				t.Errorf("expected -170000, got %v", v)
			}

			// Element 3: empty struct
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			if r.Type() != ElementTypeStruct {
				t.Errorf("expected Struct, got %v", r.Type())
			}
			if err := r.Skip(); err != nil {
				t.Fatalf("Skip failed: %v", err)
			}

			// Element 4: float 17.9
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			f, err := r.Float32()
			if err != nil {
				t.Fatalf("Float32() error: %v", err)
			}
			if f != float32(17.9) {
				t.Errorf("expected 17.9, got %v", f)
			}

			// Element 5: string "Hello!"
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			s, err := r.String()
			if err != nil {
				t.Fatalf("String() error: %v", err)
			}
			if s != "Hello!" {
				t.Errorf("expected 'Hello!', got %q", s)
			}
		},
	},
}

// Table 127: Sample encoding of different tag types
var table127Vectors = []struct {
	name     string
	encoding []byte
	check    func(t *testing.T, r *Reader)
}{
	{
		name:     "Anonymous tag, Unsigned Integer, 1-octet value, 42U",
		encoding: []byte{0x04, 0x2a},
		check: func(t *testing.T, r *Reader) {
			if !r.Tag().IsAnonymous() {
				t.Errorf("expected anonymous tag, got %v", r.Tag().Control())
			}
			v, err := r.Uint()
			if err != nil {
				t.Fatalf("Uint() error: %v", err)
			}
			if v != 42 {
				t.Errorf("expected 42, got %v", v)
			}
		},
	},
	{
		name:     "Context tag 1, Unsigned Integer, 1-octet value, 1 = 42U",
		encoding: []byte{0x24, 0x01, 0x2a},
		check: func(t *testing.T, r *Reader) {
			if !r.Tag().IsContext() {
				t.Errorf("expected context tag, got %v", r.Tag().Control())
			}
			if r.Tag().TagNumber() != 1 {
				t.Errorf("expected tag number 1, got %v", r.Tag().TagNumber())
			}
			v, err := r.Uint()
			if err != nil {
				t.Fatalf("Uint() error: %v", err)
			}
			if v != 42 {
				t.Errorf("expected 42, got %v", v)
			}
		},
	},
	{
		name:     "Common profile tag 1, Unsigned Integer, 1-octet value, Matter::1 = 42U",
		encoding: []byte{0x44, 0x01, 0x00, 0x2a},
		check: func(t *testing.T, r *Reader) {
			if r.Tag().Control() != TagControlCommonProfile2 {
				t.Errorf("expected CommonProfile2 tag, got %v", r.Tag().Control())
			}
			if r.Tag().TagNumber() != 1 {
				t.Errorf("expected tag number 1, got %v", r.Tag().TagNumber())
			}
			v, err := r.Uint()
			if err != nil {
				t.Fatalf("Uint() error: %v", err)
			}
			if v != 42 {
				t.Errorf("expected 42, got %v", v)
			}
		},
	},
	{
		name:     "Common profile tag 100000, Unsigned Integer, 1-octet value, Matter::100000 = 42U",
		encoding: []byte{0x64, 0xa0, 0x86, 0x01, 0x00, 0x2a},
		check: func(t *testing.T, r *Reader) {
			if r.Tag().Control() != TagControlCommonProfile4 {
				t.Errorf("expected CommonProfile4 tag, got %v", r.Tag().Control())
			}
			if r.Tag().TagNumber() != 100000 {
				t.Errorf("expected tag number 100000, got %v", r.Tag().TagNumber())
			}
			v, err := r.Uint()
			if err != nil {
				t.Fatalf("Uint() error: %v", err)
			}
			if v != 42 {
				t.Errorf("expected 42, got %v", v)
			}
		},
	},
	{
		name:     "Fully qualified tag, VID 0xFFF1, profile 0xDEED, tag 1, 42U",
		encoding: []byte{0xc4, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0x2a},
		check: func(t *testing.T, r *Reader) {
			if r.Tag().Control() != TagControlFullyQualified6 {
				t.Errorf("expected FullyQualified6 tag, got %v", r.Tag().Control())
			}
			if r.Tag().VendorID() != 0xFFF1 {
				t.Errorf("expected VendorID 0xFFF1, got 0x%04X", r.Tag().VendorID())
			}
			if r.Tag().ProfileNumber() != 0xDEED {
				t.Errorf("expected ProfileNumber 0xDEED, got 0x%04X", r.Tag().ProfileNumber())
			}
			if r.Tag().TagNumber() != 1 {
				t.Errorf("expected tag number 1, got %v", r.Tag().TagNumber())
			}
			v, err := r.Uint()
			if err != nil {
				t.Fatalf("Uint() error: %v", err)
			}
			if v != 42 {
				t.Errorf("expected 42, got %v", v)
			}
		},
	},
	{
		name:     "Fully qualified tag, VID 0xFFF1, profile 0xDEED, 4-octet tag 0xAA55FEED, 42U",
		encoding: []byte{0xe4, 0xf1, 0xff, 0xed, 0xde, 0xed, 0xfe, 0x55, 0xaa, 0x2a},
		check: func(t *testing.T, r *Reader) {
			if r.Tag().Control() != TagControlFullyQualified8 {
				t.Errorf("expected FullyQualified8 tag, got %v", r.Tag().Control())
			}
			if r.Tag().VendorID() != 0xFFF1 {
				t.Errorf("expected VendorID 0xFFF1, got 0x%04X", r.Tag().VendorID())
			}
			if r.Tag().ProfileNumber() != 0xDEED {
				t.Errorf("expected ProfileNumber 0xDEED, got 0x%04X", r.Tag().ProfileNumber())
			}
			if r.Tag().TagNumber() != 0xAA55FEED {
				t.Errorf("expected tag number 0xAA55FEED, got 0x%08X", r.Tag().TagNumber())
			}
			v, err := r.Uint()
			if err != nil {
				t.Fatalf("Uint() error: %v", err)
			}
			if v != 42 {
				t.Errorf("expected 42, got %v", v)
			}
		},
	},
	{
		name: "Structure with fully qualified tags",
		// 65521::57069:1 = {65521::57069:43605 = 42U}
		encoding: []byte{0xd5, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0xc4, 0xf1, 0xff, 0xed, 0xde, 0x55, 0xaa, 0x2a, 0x18},
		check: func(t *testing.T, r *Reader) {
			if r.Type() != ElementTypeStruct {
				t.Errorf("expected Struct, got %v", r.Type())
			}
			if r.Tag().VendorID() != 0xFFF1 || r.Tag().ProfileNumber() != 0xDEED || r.Tag().TagNumber() != 1 {
				t.Errorf("unexpected outer tag: VID=0x%04X, Profile=0x%04X, Tag=%d",
					r.Tag().VendorID(), r.Tag().ProfileNumber(), r.Tag().TagNumber())
			}

			if err := r.EnterContainer(); err != nil {
				t.Fatalf("EnterContainer failed: %v", err)
			}

			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			if r.Tag().VendorID() != 0xFFF1 || r.Tag().ProfileNumber() != 0xDEED || r.Tag().TagNumber() != 0xAA55 {
				t.Errorf("unexpected inner tag: VID=0x%04X, Profile=0x%04X, Tag=%d",
					r.Tag().VendorID(), r.Tag().ProfileNumber(), r.Tag().TagNumber())
			}
			v, err := r.Uint()
			if err != nil {
				t.Fatalf("Uint() error: %v", err)
			}
			if v != 42 {
				t.Errorf("expected 42, got %v", v)
			}
		},
	},
}

func TestTable125_PrimitiveTypes(t *testing.T) {
	for _, tc := range table125Vectors {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReader(bytes.NewReader(tc.encoding))
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			tc.check(t, r)
		})
	}
}

func TestTable126_Containers(t *testing.T) {
	for _, tc := range table126Vectors {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReader(bytes.NewReader(tc.encoding))
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			tc.check(t, r)
		})
	}
}

func TestTable127_TagTypes(t *testing.T) {
	for _, tc := range table127Vectors {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReader(bytes.NewReader(tc.encoding))
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			tc.check(t, r)
		})
	}
}
