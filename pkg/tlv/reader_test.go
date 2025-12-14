package tlv

import (
	"bytes"
	"io"
	"testing"
)

func TestReader_EOF(t *testing.T) {
	r := NewReader(bytes.NewReader([]byte{}))
	err := r.Next()
	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

func TestReader_ErrNoElement(t *testing.T) {
	r := NewReader(bytes.NewReader([]byte{0x00, 0x2a})) // Int8 42

	// Try to read value before calling Next()
	_, err := r.Int()
	if err != ErrNoElement {
		t.Errorf("Int() before Next(): expected ErrNoElement, got %v", err)
	}

	_, err = r.Uint()
	if err != ErrNoElement {
		t.Errorf("Uint() before Next(): expected ErrNoElement, got %v", err)
	}

	_, err = r.Bool()
	if err != ErrNoElement {
		t.Errorf("Bool() before Next(): expected ErrNoElement, got %v", err)
	}

	_, err = r.Float32()
	if err != ErrNoElement {
		t.Errorf("Float32() before Next(): expected ErrNoElement, got %v", err)
	}

	_, err = r.Float64()
	if err != ErrNoElement {
		t.Errorf("Float64() before Next(): expected ErrNoElement, got %v", err)
	}

	_, err = r.String()
	if err != ErrNoElement {
		t.Errorf("String() before Next(): expected ErrNoElement, got %v", err)
	}

	_, err = r.Bytes()
	if err != ErrNoElement {
		t.Errorf("Bytes() before Next(): expected ErrNoElement, got %v", err)
	}

	err = r.Null()
	if err != ErrNoElement {
		t.Errorf("Null() before Next(): expected ErrNoElement, got %v", err)
	}

	err = r.EnterContainer()
	if err != ErrNoElement {
		t.Errorf("EnterContainer() before Next(): expected ErrNoElement, got %v", err)
	}

	err = r.Skip()
	if err != ErrNoElement {
		t.Errorf("Skip() before Next(): expected ErrNoElement, got %v", err)
	}
}

func TestReader_ErrTypeMismatch(t *testing.T) {
	testCases := []struct {
		name     string
		encoding []byte
		readFunc func(r *Reader) error
	}{
		{
			name:     "Int on UInt",
			encoding: []byte{0x04, 0x2a}, // UInt8 42
			readFunc: func(r *Reader) error {
				_, err := r.Int()
				return err
			},
		},
		{
			name:     "Uint on Int",
			encoding: []byte{0x00, 0x2a}, // Int8 42
			readFunc: func(r *Reader) error {
				_, err := r.Uint()
				return err
			},
		},
		{
			name:     "Bool on Int",
			encoding: []byte{0x00, 0x2a}, // Int8 42
			readFunc: func(r *Reader) error {
				_, err := r.Bool()
				return err
			},
		},
		{
			name:     "Float32 on Int",
			encoding: []byte{0x00, 0x2a}, // Int8 42
			readFunc: func(r *Reader) error {
				_, err := r.Float32()
				return err
			},
		},
		{
			name:     "Float64 on Int",
			encoding: []byte{0x00, 0x2a}, // Int8 42
			readFunc: func(r *Reader) error {
				_, err := r.Float64()
				return err
			},
		},
		{
			name:     "Float32 on Float64",
			encoding: []byte{0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Float64 0.0
			readFunc: func(r *Reader) error {
				_, err := r.Float32()
				return err
			},
		},
		{
			name:     "Float64 on Float32",
			encoding: []byte{0x0a, 0x00, 0x00, 0x00, 0x00}, // Float32 0.0
			readFunc: func(r *Reader) error {
				_, err := r.Float64()
				return err
			},
		},
		{
			name:     "String on Int",
			encoding: []byte{0x00, 0x2a}, // Int8 42
			readFunc: func(r *Reader) error {
				_, err := r.String()
				return err
			},
		},
		{
			name:     "String on Bytes",
			encoding: []byte{0x10, 0x02, 0x00, 0x01}, // Octet string
			readFunc: func(r *Reader) error {
				_, err := r.String()
				return err
			},
		},
		{
			name:     "Bytes on String",
			encoding: []byte{0x0c, 0x02, 0x68, 0x69}, // UTF-8 "hi"
			readFunc: func(r *Reader) error {
				_, err := r.Bytes()
				return err
			},
		},
		{
			name:     "Null on Int",
			encoding: []byte{0x00, 0x2a}, // Int8 42
			readFunc: func(r *Reader) error {
				return r.Null()
			},
		},
		{
			name:     "EnterContainer on Int",
			encoding: []byte{0x00, 0x2a}, // Int8 42
			readFunc: func(r *Reader) error {
				return r.EnterContainer()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReader(bytes.NewReader(tc.encoding))
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			err := tc.readFunc(r)
			if err != ErrTypeMismatch {
				t.Errorf("expected ErrTypeMismatch, got %v", err)
			}
		})
	}
}

func TestReader_ErrValueAlreadyRead(t *testing.T) {
	testCases := []struct {
		name     string
		encoding []byte
		readOnce func(r *Reader) error
		readFunc func(r *Reader) error
	}{
		{
			name:     "Int twice",
			encoding: []byte{0x00, 0x2a},
			readOnce: func(r *Reader) error { _, err := r.Int(); return err },
			readFunc: func(r *Reader) error { _, err := r.Int(); return err },
		},
		{
			name:     "Uint twice",
			encoding: []byte{0x04, 0x2a},
			readOnce: func(r *Reader) error { _, err := r.Uint(); return err },
			readFunc: func(r *Reader) error { _, err := r.Uint(); return err },
		},
		{
			name:     "Bool twice",
			encoding: []byte{0x09},
			readOnce: func(r *Reader) error { _, err := r.Bool(); return err },
			readFunc: func(r *Reader) error { _, err := r.Bool(); return err },
		},
		{
			name:     "Float32 twice",
			encoding: []byte{0x0a, 0x00, 0x00, 0x00, 0x00},
			readOnce: func(r *Reader) error { _, err := r.Float32(); return err },
			readFunc: func(r *Reader) error { _, err := r.Float32(); return err },
		},
		{
			name:     "Float64 twice",
			encoding: []byte{0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			readOnce: func(r *Reader) error { _, err := r.Float64(); return err },
			readFunc: func(r *Reader) error { _, err := r.Float64(); return err },
		},
		{
			name:     "String twice",
			encoding: []byte{0x0c, 0x02, 0x68, 0x69},
			readOnce: func(r *Reader) error { _, err := r.String(); return err },
			readFunc: func(r *Reader) error { _, err := r.String(); return err },
		},
		{
			name:     "Bytes twice",
			encoding: []byte{0x10, 0x02, 0x00, 0x01},
			readOnce: func(r *Reader) error { _, err := r.Bytes(); return err },
			readFunc: func(r *Reader) error { _, err := r.Bytes(); return err },
		},
		{
			name:     "Null twice",
			encoding: []byte{0x14},
			readOnce: func(r *Reader) error { return r.Null() },
			readFunc: func(r *Reader) error { return r.Null() },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReader(bytes.NewReader(tc.encoding))
			if err := r.Next(); err != nil {
				t.Fatalf("Next failed: %v", err)
			}
			// Read once (should succeed)
			if err := tc.readOnce(r); err != nil {
				t.Fatalf("First read failed: %v", err)
			}
			// Read again (should fail)
			err := tc.readFunc(r)
			if err != ErrValueAlreadyRead {
				t.Errorf("expected ErrValueAlreadyRead, got %v", err)
			}
		})
	}
}

func TestReader_ErrNotInContainer(t *testing.T) {
	r := NewReader(bytes.NewReader([]byte{0x00, 0x2a}))
	if err := r.Next(); err != nil {
		t.Fatalf("Next failed: %v", err)
	}

	err := r.ExitContainer()
	if err != ErrNotInContainer {
		t.Errorf("expected ErrNotInContainer, got %v", err)
	}
}

func TestReader_TruncatedInput(t *testing.T) {
	// Tests where error occurs during Next()
	nextErrorCases := []struct {
		name     string
		encoding []byte
	}{
		{"truncated_int16", []byte{0x01, 0x2a}},         // Missing second byte
		{"truncated_int32", []byte{0x02, 0x2a, 0x00}},   // Missing bytes
		{"truncated_int64", []byte{0x03, 0x00, 0x00}},   // Missing bytes
		{"truncated_float32", []byte{0x0a, 0x00, 0x00}}, // Missing bytes
		{"truncated_float64", []byte{0x0b, 0x00, 0x00}}, // Missing bytes
		{"truncated_string_len", []byte{0x0c}},          // Missing length
		{"truncated_context_tag", []byte{0x20}},         // Missing tag byte
		{"truncated_common_tag", []byte{0x44, 0x01}},    // Missing second tag byte
		{"truncated_fq_tag", []byte{0xc4, 0xf1, 0xff}},  // Missing tag bytes
	}

	for _, tc := range nextErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReader(bytes.NewReader(tc.encoding))
			err := r.Next()
			if err == nil {
				t.Error("expected error for truncated input during Next(), got nil")
			}
		})
	}

	// Test where error occurs when reading the value (string data is read lazily)
	t.Run("truncated_string_data", func(t *testing.T) {
		// Length says 5, only 2 bytes of data follow
		encoding := []byte{0x0c, 0x05, 0x68, 0x69}
		r := NewReader(bytes.NewReader(encoding))

		// Next() succeeds because it only reads control + length
		err := r.Next()
		if err != nil {
			t.Fatalf("Next() should succeed, got error: %v", err)
		}

		// String() should fail because data is truncated
		_, err = r.String()
		if err == nil {
			t.Error("expected error for truncated string data during String(), got nil")
		}
	})

	t.Run("truncated_bytes_data", func(t *testing.T) {
		// Length says 5, only 2 bytes of data follow
		encoding := []byte{0x10, 0x05, 0x00, 0x01}
		r := NewReader(bytes.NewReader(encoding))

		err := r.Next()
		if err != nil {
			t.Fatalf("Next() should succeed, got error: %v", err)
		}

		_, err = r.Bytes()
		if err == nil {
			t.Error("expected error for truncated bytes data during Bytes(), got nil")
		}
	})
}

func TestReader_Skip(t *testing.T) {
	t.Run("skip_primitive", func(t *testing.T) {
		// Create: [1, 2, 3]
		var buf bytes.Buffer
		w := NewWriter(&buf)
		if err := w.StartArray(Anonymous()); err != nil {
			t.Fatal(err)
		}
		if err := w.PutInt(Anonymous(), 1); err != nil {
			t.Fatal(err)
		}
		if err := w.PutInt(Anonymous(), 2); err != nil {
			t.Fatal(err)
		}
		if err := w.PutInt(Anonymous(), 3); err != nil {
			t.Fatal(err)
		}
		if err := w.EndContainer(); err != nil {
			t.Fatal(err)
		}

		r := NewReader(bytes.NewReader(buf.Bytes()))
		if err := r.Next(); err != nil {
			t.Fatalf("Next (array) failed: %v", err)
		}
		if err := r.EnterContainer(); err != nil {
			t.Fatal(err)
		}

		// Read first element
		if err := r.Next(); err != nil {
			t.Fatal(err)
		}
		if err := r.Skip(); err != nil {
			t.Fatalf("Skip failed: %v", err)
		}

		// Read second element
		if err := r.Next(); err != nil {
			t.Fatal(err)
		}
		v, err := r.Int()
		if err != nil {
			t.Fatalf("Int() error: %v", err)
		}
		if v != 2 {
			t.Errorf("expected 2, got %v", v)
		}
	})

	t.Run("skip_string", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		if err := w.StartArray(Anonymous()); err != nil {
			t.Fatal(err)
		}
		if err := w.PutString(Anonymous(), "skip me"); err != nil {
			t.Fatal(err)
		}
		if err := w.PutInt(Anonymous(), 42); err != nil {
			t.Fatal(err)
		}
		if err := w.EndContainer(); err != nil {
			t.Fatal(err)
		}

		r := NewReader(bytes.NewReader(buf.Bytes()))
		if err := r.Next(); err != nil {
			t.Fatal(err)
		}
		if err := r.EnterContainer(); err != nil {
			t.Fatal(err)
		}

		// Skip the string
		if err := r.Next(); err != nil {
			t.Fatal(err)
		}
		if r.Type() != ElementTypeUTF8_1 {
			t.Fatalf("expected UTF8 string, got %v", r.Type())
		}
		if err := r.Skip(); err != nil {
			t.Fatalf("Skip failed: %v", err)
		}

		// Read the int
		if err := r.Next(); err != nil {
			t.Fatal(err)
		}
		v, err := r.Int()
		if err != nil {
			t.Fatalf("Int() error: %v", err)
		}
		if v != 42 {
			t.Errorf("expected 42, got %v", v)
		}
	})

	t.Run("skip_nested_container", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		if err := w.StartArray(Anonymous()); err != nil {
			t.Fatal(err)
		}
		if err := w.PutInt(Anonymous(), 1); err != nil {
			t.Fatal(err)
		}
		// Nested struct with content
		if err := w.StartStructure(Anonymous()); err != nil {
			t.Fatal(err)
		}
		if err := w.PutString(ContextTag(0), "nested string"); err != nil {
			t.Fatal(err)
		}
		if err := w.PutInt(ContextTag(1), 999); err != nil {
			t.Fatal(err)
		}
		// Deeper nesting
		if err := w.StartArray(ContextTag(2)); err != nil {
			t.Fatal(err)
		}
		if err := w.PutInt(Anonymous(), 100); err != nil {
			t.Fatal(err)
		}
		if err := w.PutInt(Anonymous(), 200); err != nil {
			t.Fatal(err)
		}
		if err := w.EndContainer(); err != nil {
			t.Fatal(err)
		}
		if err := w.EndContainer(); err != nil {
			t.Fatal(err)
		}
		if err := w.PutInt(Anonymous(), 3); err != nil {
			t.Fatal(err)
		}
		if err := w.EndContainer(); err != nil {
			t.Fatal(err)
		}

		r := NewReader(bytes.NewReader(buf.Bytes()))
		if err := r.Next(); err != nil {
			t.Fatal(err)
		}
		if err := r.EnterContainer(); err != nil {
			t.Fatal(err)
		}

		// Read 1
		if err := r.Next(); err != nil {
			t.Fatal(err)
		}
		v, err := r.Int()
		if err != nil {
			t.Fatal(err)
		}
		if v != 1 {
			t.Errorf("expected 1, got %v", v)
		}

		// Skip the entire nested struct
		if err := r.Next(); err != nil {
			t.Fatal(err)
		}
		if r.Type() != ElementTypeStruct {
			t.Fatalf("expected Struct, got %v", r.Type())
		}
		if err := r.Skip(); err != nil {
			t.Fatalf("Skip failed: %v", err)
		}

		// Read 3
		if err := r.Next(); err != nil {
			t.Fatal(err)
		}
		v, err = r.Int()
		if err != nil {
			t.Fatal(err)
		}
		if v != 3 {
			t.Errorf("expected 3, got %v", v)
		}
	})
}

func TestReader_ExitContainer(t *testing.T) {
	// Create: {0 = 1, 1 = 2, 2 = 3}
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.StartStructure(Anonymous()); err != nil {
		t.Fatal(err)
	}
	if err := w.PutInt(ContextTag(0), 1); err != nil {
		t.Fatal(err)
	}
	if err := w.PutInt(ContextTag(1), 2); err != nil {
		t.Fatal(err)
	}
	if err := w.PutInt(ContextTag(2), 3); err != nil {
		t.Fatal(err)
	}
	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}

	r := NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatal(err)
	}
	if err := r.EnterContainer(); err != nil {
		t.Fatal(err)
	}

	// Read only first element
	if err := r.Next(); err != nil {
		t.Fatal(err)
	}
	v, err := r.Int()
	if err != nil {
		t.Fatal(err)
	}
	if v != 1 {
		t.Errorf("expected 1, got %v", v)
	}

	// Exit container early (should skip remaining elements)
	if err := r.ExitContainer(); err != nil {
		t.Fatalf("ExitContainer failed: %v", err)
	}

	// Verify we're at the right depth
	if r.ContainerDepth() != 0 {
		t.Errorf("expected depth 0 after ExitContainer, got %d", r.ContainerDepth())
	}
}

// TestReader_ExitContainerWithSiblings tests that after exiting a nested container,
// we can correctly read sibling elements that follow. This tests the fix for a bug
// where ExitContainer would consume too many elements when the user had already
// iterated to the EndOfContainer marker.
func TestReader_ExitContainerWithSiblings(t *testing.T) {
	// Create: {1 = 1111, 2 = {1 = 2222}, 3 = 3333}
	// The key scenario: after entering and exiting the nested struct (tag 2),
	// we should be able to read the sibling element (tag 3).
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if err := w.StartStructure(Anonymous()); err != nil {
		t.Fatal(err)
	}
	if err := w.PutUint(ContextTag(1), 1111); err != nil {
		t.Fatal(err)
	}
	// Nested struct
	if err := w.StartStructure(ContextTag(2)); err != nil {
		t.Fatal(err)
	}
	if err := w.PutUint(ContextTag(1), 2222); err != nil {
		t.Fatal(err)
	}
	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}
	// Sibling after nested struct
	if err := w.PutUint(ContextTag(3), 3333); err != nil {
		t.Fatal(err)
	}
	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}

	r := NewReader(bytes.NewReader(buf.Bytes()))

	// Enter outer struct
	if err := r.Next(); err != nil {
		t.Fatal(err)
	}
	if err := r.EnterContainer(); err != nil {
		t.Fatal(err)
	}

	// Read first field (tag 1)
	if err := r.Next(); err != nil {
		t.Fatal(err)
	}
	v, err := r.Uint()
	if err != nil {
		t.Fatal(err)
	}
	if v != 1111 {
		t.Errorf("tag 1: expected 1111, got %d", v)
	}

	// Read nested struct (tag 2)
	if err := r.Next(); err != nil {
		t.Fatal(err)
	}
	if r.Type() != ElementTypeStruct {
		t.Fatalf("expected struct, got %v", r.Type())
	}
	if r.Tag().TagNumber() != 2 {
		t.Fatalf("expected tag 2, got %d", r.Tag().TagNumber())
	}

	// Enter nested struct and iterate to end
	if err := r.EnterContainer(); err != nil {
		t.Fatal(err)
	}
	for {
		if err := r.Next(); err != nil {
			t.Fatalf("error iterating nested struct: %v", err)
		}
		if r.Type() == ElementTypeEnd {
			break
		}
		// Skip values
	}

	// Exit nested struct - this is where the bug was
	if err := r.ExitContainer(); err != nil {
		t.Fatalf("ExitContainer failed: %v", err)
	}

	// Now read the sibling field (tag 3) - this would fail before the fix
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read sibling after ExitContainer: %v", err)
	}
	if r.Type() == ElementTypeEnd {
		t.Fatal("got EndOfContainer instead of sibling element")
	}
	if r.Tag().TagNumber() != 3 {
		t.Fatalf("expected tag 3, got %d", r.Tag().TagNumber())
	}
	v, err = r.Uint()
	if err != nil {
		t.Fatal(err)
	}
	if v != 3333 {
		t.Errorf("tag 3: expected 3333, got %d", v)
	}

	// Should now hit end of outer container
	if err := r.Next(); err != nil {
		t.Fatal(err)
	}
	if r.Type() != ElementTypeEnd {
		t.Errorf("expected EndOfContainer, got %v", r.Type())
	}
}

func TestReader_ContainerDepth(t *testing.T) {
	// Create nested structure: {0 = [1, 2]}
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.StartStructure(Anonymous()); err != nil {
		t.Fatal(err)
	}
	if err := w.StartArray(ContextTag(0)); err != nil {
		t.Fatal(err)
	}
	if err := w.PutInt(Anonymous(), 1); err != nil {
		t.Fatal(err)
	}
	if err := w.PutInt(Anonymous(), 2); err != nil {
		t.Fatal(err)
	}
	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}
	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}

	r := NewReader(bytes.NewReader(buf.Bytes()))

	if r.ContainerDepth() != 0 {
		t.Errorf("initial depth: expected 0, got %d", r.ContainerDepth())
	}

	if err := r.Next(); err != nil {
		t.Fatal(err)
	}
	if err := r.EnterContainer(); err != nil {
		t.Fatal(err)
	}
	if r.ContainerDepth() != 1 {
		t.Errorf("after enter struct: expected 1, got %d", r.ContainerDepth())
	}

	if err := r.Next(); err != nil {
		t.Fatal(err)
	}
	if err := r.EnterContainer(); err != nil {
		t.Fatal(err)
	}
	if r.ContainerDepth() != 2 {
		t.Errorf("after enter array: expected 2, got %d", r.ContainerDepth())
	}

	if err := r.ExitContainer(); err != nil {
		t.Fatal(err)
	}
	if r.ContainerDepth() != 1 {
		t.Errorf("after exit array: expected 1, got %d", r.ContainerDepth())
	}

	if err := r.ExitContainer(); err != nil {
		t.Fatal(err)
	}
	if r.ContainerDepth() != 0 {
		t.Errorf("after exit struct: expected 0, got %d", r.ContainerDepth())
	}
}

func TestReader_IsEndOfContainer(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.StartStructure(Anonymous()); err != nil {
		t.Fatal(err)
	}
	if err := w.PutInt(ContextTag(0), 42); err != nil {
		t.Fatal(err)
	}
	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}

	r := NewReader(bytes.NewReader(buf.Bytes()))
	if err := r.Next(); err != nil {
		t.Fatal(err)
	}
	if r.IsEndOfContainer() {
		t.Error("struct should not be end of container")
	}

	if err := r.EnterContainer(); err != nil {
		t.Fatal(err)
	}

	if err := r.Next(); err != nil {
		t.Fatal(err)
	}
	if r.IsEndOfContainer() {
		t.Error("element 0 should not be end of container")
	}

	if err := r.Next(); err != nil {
		t.Fatal(err)
	}
	if !r.IsEndOfContainer() {
		t.Error("expected end of container")
	}
}

func TestReader_HasElement(t *testing.T) {
	r := NewReader(bytes.NewReader([]byte{0x00, 0x2a}))

	if r.HasElement() {
		t.Error("HasElement should be false before Next()")
	}

	if err := r.Next(); err != nil {
		t.Fatal(err)
	}

	if !r.HasElement() {
		t.Error("HasElement should be true after Next()")
	}
}
