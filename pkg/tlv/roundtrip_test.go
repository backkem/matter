package tlv

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

// Round-trip tests: write then read back, verifying both value and encoding

func TestRoundTrip_Integers(t *testing.T) {
	testCases := []struct {
		name         string
		value        int64
		expectedType ElementType
		expectedSize int // total encoded size including control byte
	}{
		{"zero", 0, ElementTypeInt8, 2},
		{"positive_small", 42, ElementTypeInt8, 2},
		{"negative_small", -17, ElementTypeInt8, 2},
		{"max_int8", 127, ElementTypeInt8, 2},
		{"min_int8", -128, ElementTypeInt8, 2},
		{"needs_int16_pos", 128, ElementTypeInt16, 3},
		{"needs_int16_neg", -129, ElementTypeInt16, 3},
		{"positive_int16", 1000, ElementTypeInt16, 3},
		{"negative_int16", -1000, ElementTypeInt16, 3},
		{"max_int16", 32767, ElementTypeInt16, 3},
		{"min_int16", -32768, ElementTypeInt16, 3},
		{"needs_int32_pos", 32768, ElementTypeInt32, 5},
		{"needs_int32_neg", -32769, ElementTypeInt32, 5},
		{"positive_int32", 100000, ElementTypeInt32, 5},
		{"negative_int32", -170000, ElementTypeInt32, 5},
		{"max_int32", 2147483647, ElementTypeInt32, 5},
		{"min_int32", -2147483648, ElementTypeInt32, 5},
		{"needs_int64_pos", 2147483648, ElementTypeInt64, 9},
		{"needs_int64_neg", -2147483649, ElementTypeInt64, 9},
		{"positive_int64", 40000000000, ElementTypeInt64, 9},
		{"negative_int64", -40000000000, ElementTypeInt64, 9},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf)
			if err := w.PutInt(Anonymous(), tc.value); err != nil {
				t.Fatalf("PutInt failed: %v", err)
			}

			// Verify encoding size (minimum width selection)
			if buf.Len() != tc.expectedSize {
				t.Errorf("expected encoded size %d, got %d (bytes: %x)",
					tc.expectedSize, buf.Len(), buf.Bytes())
			}

			// Read back and verify
			r := NewReader(bytes.NewReader(buf.Bytes()))
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}

			if r.Type() != tc.expectedType {
				t.Errorf("expected type %v, got %v", tc.expectedType, r.Type())
			}

			v, err := r.Int()
			if err != nil {
				t.Fatalf("Int failed: %v", err)
			}
			if v != tc.value {
				t.Errorf("expected %d, got %d", tc.value, v)
			}
		})
	}
}

func TestRoundTrip_UnsignedIntegers(t *testing.T) {
	testCases := []struct {
		name         string
		value        uint64
		expectedType ElementType
		expectedSize int
	}{
		{"zero", 0, ElementTypeUInt8, 2},
		{"small", 42, ElementTypeUInt8, 2},
		{"max_uint8", 255, ElementTypeUInt8, 2},
		{"needs_uint16", 256, ElementTypeUInt16, 3},
		{"uint16", 1000, ElementTypeUInt16, 3},
		{"max_uint16", 65535, ElementTypeUInt16, 3},
		{"needs_uint32", 65536, ElementTypeUInt32, 5},
		{"uint32", 100000, ElementTypeUInt32, 5},
		{"max_uint32", 4294967295, ElementTypeUInt32, 5},
		{"needs_uint64", 4294967296, ElementTypeUInt64, 9},
		{"uint64", 40000000000, ElementTypeUInt64, 9},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf)
			if err := w.PutUint(Anonymous(), tc.value); err != nil {
				t.Fatalf("PutUint failed: %v", err)
			}

			// Verify encoding size
			if buf.Len() != tc.expectedSize {
				t.Errorf("expected encoded size %d, got %d (bytes: %x)",
					tc.expectedSize, buf.Len(), buf.Bytes())
			}

			r := NewReader(bytes.NewReader(buf.Bytes()))
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}

			if r.Type() != tc.expectedType {
				t.Errorf("expected type %v, got %v", tc.expectedType, r.Type())
			}

			v, err := r.Uint()
			if err != nil {
				t.Fatalf("Uint failed: %v", err)
			}
			if v != tc.value {
				t.Errorf("expected %d, got %d", tc.value, v)
			}
		})
	}
}

func TestRoundTrip_Strings(t *testing.T) {
	testCases := []struct {
		name         string
		value        string
		expectedType ElementType
	}{
		{"empty", "", ElementTypeUTF8_1},
		{"hello", "Hello!", ElementTypeUTF8_1},
		{"utf8_umlaut", "Tschüs", ElementTypeUTF8_1},
		{"utf8_emoji", "Hello \xF0\x9F\x91\x8B", ElementTypeUTF8_1}, // Hello + waving hand emoji
		{"max_1byte_len", strings.Repeat("a", 255), ElementTypeUTF8_1},
		{"needs_2byte_len", strings.Repeat("a", 256), ElementTypeUTF8_2},
		{"long_2byte", strings.Repeat("b", 300), ElementTypeUTF8_2},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf)
			if err := w.PutString(Anonymous(), tc.value); err != nil {
				t.Fatalf("PutString failed: %v", err)
			}

			r := NewReader(bytes.NewReader(buf.Bytes()))
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}

			if r.Type() != tc.expectedType {
				t.Errorf("expected type %v, got %v", tc.expectedType, r.Type())
			}

			v, err := r.String()
			if err != nil {
				t.Fatalf("String failed: %v", err)
			}
			if v != tc.value {
				t.Errorf("expected %q, got %q", tc.value, v)
			}
		})
	}
}

func TestRoundTrip_Bytes(t *testing.T) {
	testCases := []struct {
		name         string
		value        []byte
		expectedType ElementType
	}{
		{"nil", nil, ElementTypeBytes1},
		{"empty", []byte{}, ElementTypeBytes1},
		{"binary", []byte{0x00, 0x01, 0x02, 0xff}, ElementTypeBytes1},
		{"max_1byte_len", make([]byte, 255), ElementTypeBytes1},
		{"needs_2byte_len", make([]byte, 256), ElementTypeBytes2},
		{"long", make([]byte, 300), ElementTypeBytes2},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf)
			if err := w.PutBytes(Anonymous(), tc.value); err != nil {
				t.Fatalf("PutBytes failed: %v", err)
			}

			r := NewReader(bytes.NewReader(buf.Bytes()))
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}

			if r.Type() != tc.expectedType {
				t.Errorf("expected type %v, got %v", tc.expectedType, r.Type())
			}

			v, err := r.Bytes()
			if err != nil {
				t.Fatalf("Bytes failed: %v", err)
			}
			if !bytes.Equal(v, tc.value) {
				t.Errorf("byte content mismatch")
			}
		})
	}
}

func TestRoundTrip_Floats(t *testing.T) {
	t.Run("float32", func(t *testing.T) {
		values := []float32{0.0, 1.0 / 3.0, 17.9, -123.456, float32(math.Inf(1)), float32(math.Inf(-1))}
		for _, expected := range values {
			var buf bytes.Buffer
			w := NewWriter(&buf)
			if err := w.PutFloat32(Anonymous(), expected); err != nil {
				t.Fatalf("PutFloat32(%v) failed: %v", expected, err)
			}

			// Verify encoding size: 1 control + 4 value = 5 bytes
			if buf.Len() != 5 {
				t.Errorf("float32 should encode to 5 bytes, got %d", buf.Len())
			}

			r := NewReader(bytes.NewReader(buf.Bytes()))
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}

			if r.Type() != ElementTypeFloat32 {
				t.Errorf("expected Float32 type, got %v", r.Type())
			}

			v, err := r.Float32()
			if err != nil {
				t.Fatalf("Float32 failed: %v", err)
			}
			if v != expected && !(math.IsNaN(float64(v)) && math.IsNaN(float64(expected))) {
				t.Errorf("expected %v, got %v", expected, v)
			}
		}
	})

	t.Run("float64", func(t *testing.T) {
		values := []float64{0.0, 1.0 / 3.0, 17.9, -123.456789, math.Inf(1), math.Inf(-1)}
		for _, expected := range values {
			var buf bytes.Buffer
			w := NewWriter(&buf)
			if err := w.PutFloat64(Anonymous(), expected); err != nil {
				t.Fatalf("PutFloat64(%v) failed: %v", expected, err)
			}

			// Verify encoding size: 1 control + 8 value = 9 bytes
			if buf.Len() != 9 {
				t.Errorf("float64 should encode to 9 bytes, got %d", buf.Len())
			}

			r := NewReader(bytes.NewReader(buf.Bytes()))
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}

			if r.Type() != ElementTypeFloat64 {
				t.Errorf("expected Float64 type, got %v", r.Type())
			}

			v, err := r.Float64()
			if err != nil {
				t.Fatalf("Float64 failed: %v", err)
			}
			if v != expected {
				t.Errorf("expected %v, got %v", expected, v)
			}
		}
	})

	t.Run("NaN", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		if err := w.PutFloat64(Anonymous(), math.NaN()); err != nil {
			t.Fatalf("PutFloat64(NaN) failed: %v", err)
		}

		r := NewReader(bytes.NewReader(buf.Bytes()))
		if err := r.Next(); err != nil {
			t.Fatalf("Next failed: %v", err)
		}
		v, err := r.Float64()
		if err != nil {
			t.Fatalf("Float64 failed: %v", err)
		}
		if !math.IsNaN(v) {
			t.Errorf("expected NaN, got %v", v)
		}
	})
}

func TestRoundTrip_Booleans(t *testing.T) {
	for _, expected := range []bool{true, false} {
		t.Run(boolName(expected), func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf)
			if err := w.PutBool(Anonymous(), expected); err != nil {
				t.Fatalf("PutBool failed: %v", err)
			}

			// Boolean encodes to single byte (no value field)
			if buf.Len() != 1 {
				t.Errorf("boolean should encode to 1 byte, got %d", buf.Len())
			}

			r := NewReader(bytes.NewReader(buf.Bytes()))
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}

			v, err := r.Bool()
			if err != nil {
				t.Fatalf("Bool failed: %v", err)
			}
			if v != expected {
				t.Errorf("expected %v, got %v", expected, v)
			}
		})
	}
}

func boolName(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func TestRoundTrip_Null(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.PutNull(Anonymous()); err != nil {
		t.Fatalf("PutNull failed: %v", err)
	}

	// Null encodes to single byte
	if buf.Len() != 1 {
		t.Errorf("null should encode to 1 byte, got %d", buf.Len())
	}

	r := NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatalf("Next failed: %v", err)
	}

	if r.Type() != ElementTypeNull {
		t.Errorf("expected Null type, got %v", r.Type())
	}

	if err := r.Null(); err != nil {
		t.Errorf("Null() returned error: %v", err)
	}
}

func TestRoundTrip_Tags(t *testing.T) {
	testCases := []struct {
		name        string
		tag         Tag
		expectedLen int // encoded tag size (not including control byte or value)
	}{
		{"anonymous", Anonymous(), 0},
		{"context_0", ContextTag(0), 1},
		{"context_255", ContextTag(255), 1},
		{"common_1", CommonProfileTag(1), 2},
		{"common_65535", CommonProfileTag(65535), 2},
		{"common_65536", CommonProfileTag(65536), 4},
		{"common_100000", CommonProfileTag(100000), 4},
		{"implicit_1", ImplicitProfileTag(1), 2},
		{"implicit_65536", ImplicitProfileTag(65536), 4},
		{"fully_qualified_small", FullyQualifiedTag(0xFFF1, 0xDEED, 1), 6},
		{"fully_qualified_large", FullyQualifiedTag(0xFFF1, 0xDEED, 0xAA55FEED), 8},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf)
			if err := w.PutUint(tc.tag, 42); err != nil {
				t.Fatalf("PutUint failed: %v", err)
			}

			// Verify tag encoding size: control(1) + tag(tc.expectedLen) + value(1 for uint8)
			expectedTotal := 1 + tc.expectedLen + 1
			if buf.Len() != expectedTotal {
				t.Errorf("expected total size %d, got %d (bytes: %x)",
					expectedTotal, buf.Len(), buf.Bytes())
			}

			r := NewReader(bytes.NewReader(buf.Bytes()))
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}

			gotTag := r.Tag()
			if gotTag.Control() != tc.tag.Control() {
				t.Errorf("control: expected %v, got %v", tc.tag.Control(), gotTag.Control())
			}
			if gotTag.TagNumber() != tc.tag.TagNumber() {
				t.Errorf("tag number: expected %d, got %d", tc.tag.TagNumber(), gotTag.TagNumber())
			}
			if gotTag.VendorID() != tc.tag.VendorID() {
				t.Errorf("vendor ID: expected 0x%04X, got 0x%04X", tc.tag.VendorID(), gotTag.VendorID())
			}
			if gotTag.ProfileNumber() != tc.tag.ProfileNumber() {
				t.Errorf("profile number: expected 0x%04X, got 0x%04X", tc.tag.ProfileNumber(), gotTag.ProfileNumber())
			}
		})
	}
}

func TestRoundTrip_Containers(t *testing.T) {
	t.Run("empty_struct_exact_encoding", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		if err := w.StartStructure(Anonymous()); err != nil {
			t.Fatalf("StartStructure failed: %v", err)
		}
		if err := w.EndContainer(); err != nil {
			t.Fatalf("EndContainer failed: %v", err)
		}

		expected := []byte{0x15, 0x18}
		if !bytes.Equal(buf.Bytes(), expected) {
			t.Errorf("expected %x, got %x", expected, buf.Bytes())
		}
	})

	t.Run("empty_array_exact_encoding", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		if err := w.StartArray(Anonymous()); err != nil {
			t.Fatalf("StartArray failed: %v", err)
		}
		if err := w.EndContainer(); err != nil {
			t.Fatalf("EndContainer failed: %v", err)
		}

		expected := []byte{0x16, 0x18}
		if !bytes.Equal(buf.Bytes(), expected) {
			t.Errorf("expected %x, got %x", expected, buf.Bytes())
		}
	})

	t.Run("empty_list_exact_encoding", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		if err := w.StartList(Anonymous()); err != nil {
			t.Fatalf("StartList failed: %v", err)
		}
		if err := w.EndContainer(); err != nil {
			t.Fatalf("EndContainer failed: %v", err)
		}

		expected := []byte{0x17, 0x18}
		if !bytes.Equal(buf.Bytes(), expected) {
			t.Errorf("expected %x, got %x", expected, buf.Bytes())
		}
	})

	t.Run("struct_with_context_tags_exact_encoding", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		if err := w.StartStructure(Anonymous()); err != nil {
			t.Fatal(err)
		}
		if err := w.PutIntWithWidth(ContextTag(0), 42, 1); err != nil {
			t.Fatal(err)
		}
		if err := w.PutIntWithWidth(ContextTag(1), -17, 1); err != nil {
			t.Fatal(err)
		}
		if err := w.EndContainer(); err != nil {
			t.Fatal(err)
		}

		// From spec Table 126: {0 = 42, 1 = -17}
		expected := []byte{0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18}
		if !bytes.Equal(buf.Bytes(), expected) {
			t.Errorf("expected %x, got %x", expected, buf.Bytes())
		}
	})

	t.Run("nested_struct", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf)

		// {0 = 42, 1 = {2 = "hello"}}
		if err := w.StartStructure(Anonymous()); err != nil {
			t.Fatal(err)
		}
		if err := w.PutInt(ContextTag(0), 42); err != nil {
			t.Fatal(err)
		}
		if err := w.StartStructure(ContextTag(1)); err != nil {
			t.Fatal(err)
		}
		if err := w.PutString(ContextTag(2), "hello"); err != nil {
			t.Fatal(err)
		}
		if err := w.EndContainer(); err != nil {
			t.Fatal(err)
		}
		if err := w.EndContainer(); err != nil {
			t.Fatal(err)
		}

		// Read back and verify structure
		r := NewReader(bytes.NewReader(buf.Bytes()))
		if err := r.Next(); err != nil {
			t.Fatal(err)
		}
		if r.Type() != ElementTypeStruct {
			t.Fatalf("expected Struct, got %v", r.Type())
		}
		if err := r.EnterContainer(); err != nil {
			t.Fatal(err)
		}

		// First element: tag 0, value 42
		if err := r.Next(); err != nil {
			t.Fatal(err)
		}
		if r.Tag().TagNumber() != 0 {
			t.Errorf("expected tag 0, got %v", r.Tag().TagNumber())
		}
		v, err := r.Int()
		if err != nil {
			t.Fatalf("Int() error: %v", err)
		}
		if v != 42 {
			t.Errorf("expected 42, got %v", v)
		}

		// Second element: nested struct with tag 1
		if err := r.Next(); err != nil {
			t.Fatal(err)
		}
		if r.Tag().TagNumber() != 1 {
			t.Errorf("expected tag 1, got %v", r.Tag().TagNumber())
		}
		if r.Type() != ElementTypeStruct {
			t.Fatalf("expected Struct, got %v", r.Type())
		}
		if err := r.EnterContainer(); err != nil {
			t.Fatal(err)
		}

		// Nested element: tag 2, value "hello"
		if err := r.Next(); err != nil {
			t.Fatal(err)
		}
		if r.Tag().TagNumber() != 2 {
			t.Errorf("expected tag 2, got %v", r.Tag().TagNumber())
		}
		s, err := r.String()
		if err != nil {
			t.Fatalf("String() error: %v", err)
		}
		if s != "hello" {
			t.Errorf("expected 'hello', got %q", s)
		}

		// End of inner container
		if err := r.Next(); err != nil {
			t.Fatal(err)
		}
		if r.Type() != ElementTypeEnd {
			t.Errorf("expected EndOfContainer, got %v", r.Type())
		}
	})
}

func TestRoundTrip_IntWithWidth(t *testing.T) {
	testCases := []struct {
		name         string
		value        int64
		width        int
		expectedType ElementType
	}{
		{"int8_42", 42, 1, ElementTypeInt8},
		{"int16_42", 42, 2, ElementTypeInt16},
		{"int32_42", 42, 4, ElementTypeInt32},
		{"int64_42", 42, 8, ElementTypeInt64},
		{"int8_neg", -1, 1, ElementTypeInt8},
		{"int16_neg", -1, 2, ElementTypeInt16},
		{"int32_neg", -1, 4, ElementTypeInt32},
		{"int64_neg", -1, 8, ElementTypeInt64},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf)
			if err := w.PutIntWithWidth(Anonymous(), tc.value, tc.width); err != nil {
				t.Fatalf("PutIntWithWidth failed: %v", err)
			}

			// Verify size: 1 control + width value
			if buf.Len() != 1+tc.width {
				t.Errorf("expected size %d, got %d", 1+tc.width, buf.Len())
			}

			r := NewReader(bytes.NewReader(buf.Bytes()))
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}

			if r.Type() != tc.expectedType {
				t.Errorf("expected type %v, got %v", tc.expectedType, r.Type())
			}

			v, err := r.Int()
			if err != nil {
				t.Fatalf("Int() error: %v", err)
			}
			if v != tc.value {
				t.Errorf("expected %d, got %d", tc.value, v)
			}
		})
	}
}

func TestRoundTrip_UintWithWidth(t *testing.T) {
	testCases := []struct {
		name         string
		value        uint64
		width        int
		expectedType ElementType
	}{
		{"uint8_42", 42, 1, ElementTypeUInt8},
		{"uint16_42", 42, 2, ElementTypeUInt16},
		{"uint32_42", 42, 4, ElementTypeUInt32},
		{"uint64_42", 42, 8, ElementTypeUInt64},
		{"uint8_max", 255, 1, ElementTypeUInt8},
		{"uint16_max", 65535, 2, ElementTypeUInt16},
		{"uint32_max", 4294967295, 4, ElementTypeUInt32},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf)
			if err := w.PutUintWithWidth(Anonymous(), tc.value, tc.width); err != nil {
				t.Fatalf("PutUintWithWidth failed: %v", err)
			}

			// Verify size: 1 control + width value
			if buf.Len() != 1+tc.width {
				t.Errorf("expected size %d, got %d", 1+tc.width, buf.Len())
			}

			r := NewReader(bytes.NewReader(buf.Bytes()))
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}

			if r.Type() != tc.expectedType {
				t.Errorf("expected type %v, got %v", tc.expectedType, r.Type())
			}

			v, err := r.Uint()
			if err != nil {
				t.Fatalf("Uint() error: %v", err)
			}
			if v != tc.value {
				t.Errorf("expected %d, got %d", tc.value, v)
			}
		})
	}
}
