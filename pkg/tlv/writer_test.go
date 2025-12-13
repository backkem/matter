package tlv

import (
	"bytes"
	"errors"
	"testing"
)

func TestWriter_ContainerDepth(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if w.ContainerDepth() != 0 {
		t.Errorf("expected depth 0, got %d", w.ContainerDepth())
	}

	if err := w.StartStructure(Anonymous()); err != nil {
		t.Fatal(err)
	}
	if w.ContainerDepth() != 1 {
		t.Errorf("expected depth 1, got %d", w.ContainerDepth())
	}

	if err := w.StartArray(ContextTag(0)); err != nil {
		t.Fatal(err)
	}
	if w.ContainerDepth() != 2 {
		t.Errorf("expected depth 2, got %d", w.ContainerDepth())
	}

	if err := w.StartList(ContextTag(1)); err != nil {
		t.Fatal(err)
	}
	if w.ContainerDepth() != 3 {
		t.Errorf("expected depth 3, got %d", w.ContainerDepth())
	}

	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}
	if w.ContainerDepth() != 2 {
		t.Errorf("expected depth 2, got %d", w.ContainerDepth())
	}

	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}
	if w.ContainerDepth() != 1 {
		t.Errorf("expected depth 1, got %d", w.ContainerDepth())
	}

	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}
	if w.ContainerDepth() != 0 {
		t.Errorf("expected depth 0, got %d", w.ContainerDepth())
	}
}

func TestWriter_ErrNotInContainer(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	err := w.EndContainer()
	if err != ErrNotInContainer {
		t.Errorf("expected ErrNotInContainer, got %v", err)
	}
}

func TestWriter_ErrInvalidUTF8(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	// Invalid UTF-8 sequence
	invalidUTF8 := string([]byte{0xff, 0xfe, 0xfd})
	err := w.PutString(Anonymous(), invalidUTF8)
	if err != ErrInvalidUTF8 {
		t.Errorf("expected ErrInvalidUTF8, got %v", err)
	}
}

func TestWriter_InvalidWidth(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	err := w.PutIntWithWidth(Anonymous(), 42, 3) // Invalid width
	if err != ErrInvalidElementType {
		t.Errorf("PutIntWithWidth(width=3): expected ErrInvalidElementType, got %v", err)
	}

	err = w.PutIntWithWidth(Anonymous(), 42, 0)
	if err != ErrInvalidElementType {
		t.Errorf("PutIntWithWidth(width=0): expected ErrInvalidElementType, got %v", err)
	}

	err = w.PutUintWithWidth(Anonymous(), 42, 5)
	if err != ErrInvalidElementType {
		t.Errorf("PutUintWithWidth(width=5): expected ErrInvalidElementType, got %v", err)
	}
}

// failWriter is an io.Writer that fails after n bytes
type failWriter struct {
	n       int
	written int
}

func (w *failWriter) Write(p []byte) (int, error) {
	remaining := w.n - w.written
	if remaining <= 0 {
		return 0, errors.New("write failed")
	}
	if len(p) <= remaining {
		w.written += len(p)
		return len(p), nil
	}
	w.written += remaining
	return remaining, errors.New("write failed")
}

func TestWriter_WriteErrors(t *testing.T) {
	t.Run("fail_on_control_byte", func(t *testing.T) {
		w := NewWriter(&failWriter{n: 0})
		err := w.PutInt(Anonymous(), 42)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("fail_on_tag", func(t *testing.T) {
		w := NewWriter(&failWriter{n: 1}) // Allow control byte, fail on tag
		err := w.PutInt(ContextTag(0), 42)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("fail_on_value", func(t *testing.T) {
		w := NewWriter(&failWriter{n: 2}) // Allow control + tag, fail on value
		err := w.PutInt(ContextTag(0), 42)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("fail_on_string_length", func(t *testing.T) {
		w := NewWriter(&failWriter{n: 1}) // Allow control, fail on length
		err := w.PutString(Anonymous(), "hello")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("fail_on_string_data", func(t *testing.T) {
		w := NewWriter(&failWriter{n: 2}) // Allow control + length, fail on data
		err := w.PutString(Anonymous(), "hello")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("fail_on_end_container", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		if err := w.StartStructure(Anonymous()); err != nil {
			t.Fatal(err)
		}

		// Replace writer with failing one
		w.w = &failWriter{n: 0}
		err := w.EndContainer()
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func TestWriter_AllContainerTypes(t *testing.T) {
	t.Run("structure", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf)

		if err := w.StartStructure(Anonymous()); err != nil {
			t.Fatalf("StartStructure failed: %v", err)
		}
		if err := w.PutInt(ContextTag(0), 42); err != nil {
			t.Fatalf("PutInt failed: %v", err)
		}
		if err := w.EndContainer(); err != nil {
			t.Fatalf("EndContainer failed: %v", err)
		}

		// Verify first byte is struct
		if buf.Bytes()[0] != 0x15 {
			t.Errorf("expected struct control byte 0x15, got 0x%02x", buf.Bytes()[0])
		}
	})

	t.Run("array", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf)

		if err := w.StartArray(Anonymous()); err != nil {
			t.Fatalf("StartArray failed: %v", err)
		}
		if err := w.PutInt(Anonymous(), 42); err != nil {
			t.Fatalf("PutInt failed: %v", err)
		}
		if err := w.EndContainer(); err != nil {
			t.Fatalf("EndContainer failed: %v", err)
		}

		// Verify first byte is array
		if buf.Bytes()[0] != 0x16 {
			t.Errorf("expected array control byte 0x16, got 0x%02x", buf.Bytes()[0])
		}
	})

	t.Run("list", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf)

		if err := w.StartList(Anonymous()); err != nil {
			t.Fatalf("StartList failed: %v", err)
		}
		if err := w.PutInt(Anonymous(), 42); err != nil {
			t.Fatalf("PutInt failed: %v", err)
		}
		if err := w.EndContainer(); err != nil {
			t.Fatalf("EndContainer failed: %v", err)
		}

		// Verify first byte is list
		if buf.Bytes()[0] != 0x17 {
			t.Errorf("expected list control byte 0x17, got 0x%02x", buf.Bytes()[0])
		}
	})
}

func TestWriter_TagEncoding(t *testing.T) {
	testCases := []struct {
		name          string
		tag           Tag
		expectedCtrl  byte // Expected upper 3 bits of control byte
		expectedBytes []byte
	}{
		{
			name:          "anonymous",
			tag:           Anonymous(),
			expectedCtrl:  0x00,
			expectedBytes: []byte{0x04, 0x2a}, // Control + value only
		},
		{
			name:          "context_0",
			tag:           ContextTag(0),
			expectedCtrl:  0x20,
			expectedBytes: []byte{0x24, 0x00, 0x2a}, // Control + tag + value
		},
		{
			name:          "context_255",
			tag:           ContextTag(255),
			expectedCtrl:  0x20,
			expectedBytes: []byte{0x24, 0xff, 0x2a},
		},
		{
			name:          "common_profile_2byte",
			tag:           CommonProfileTag(1),
			expectedCtrl:  0x40,
			expectedBytes: []byte{0x44, 0x01, 0x00, 0x2a},
		},
		{
			name:          "common_profile_4byte",
			tag:           CommonProfileTag(100000),
			expectedCtrl:  0x60,
			expectedBytes: []byte{0x64, 0xa0, 0x86, 0x01, 0x00, 0x2a},
		},
		{
			name:          "implicit_profile_2byte",
			tag:           ImplicitProfileTag(1),
			expectedCtrl:  0x80,
			expectedBytes: []byte{0x84, 0x01, 0x00, 0x2a},
		},
		{
			name:          "implicit_profile_4byte",
			tag:           ImplicitProfileTag(100000),
			expectedCtrl:  0xa0,
			expectedBytes: []byte{0xa4, 0xa0, 0x86, 0x01, 0x00, 0x2a},
		},
		{
			name:          "fully_qualified_6byte",
			tag:           FullyQualifiedTag(0xFFF1, 0xDEED, 1),
			expectedCtrl:  0xc0,
			expectedBytes: []byte{0xc4, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0x2a},
		},
		{
			name:          "fully_qualified_8byte",
			tag:           FullyQualifiedTag(0xFFF1, 0xDEED, 0xAA55FEED),
			expectedCtrl:  0xe0,
			expectedBytes: []byte{0xe4, 0xf1, 0xff, 0xed, 0xde, 0xed, 0xfe, 0x55, 0xaa, 0x2a},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf)
			if err := w.PutUint(tc.tag, 42); err != nil {
				t.Fatalf("PutUint failed: %v", err)
			}

			if !bytes.Equal(buf.Bytes(), tc.expectedBytes) {
				t.Errorf("expected %x, got %x", tc.expectedBytes, buf.Bytes())
			}

			// Verify tag control bits
			ctrl := buf.Bytes()[0] & 0xe0
			if ctrl != tc.expectedCtrl {
				t.Errorf("expected control bits 0x%02x, got 0x%02x", tc.expectedCtrl, ctrl)
			}
		})
	}
}

func TestWriter_EmptyStrings(t *testing.T) {
	t.Run("empty_utf8_string", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		if err := w.PutString(Anonymous(), ""); err != nil {
			t.Fatalf("PutString failed: %v", err)
		}

		// Empty string: control(0x0c) + length(0x00)
		expected := []byte{0x0c, 0x00}
		if !bytes.Equal(buf.Bytes(), expected) {
			t.Errorf("expected %x, got %x", expected, buf.Bytes())
		}
	})

	t.Run("empty_byte_string", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		if err := w.PutBytes(Anonymous(), nil); err != nil {
			t.Fatalf("PutBytes(nil) failed: %v", err)
		}

		// Empty bytes: control(0x10) + length(0x00)
		expected := []byte{0x10, 0x00}
		if !bytes.Equal(buf.Bytes(), expected) {
			t.Errorf("expected %x, got %x", expected, buf.Bytes())
		}
	})

	t.Run("empty_byte_slice", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		if err := w.PutBytes(Anonymous(), []byte{}); err != nil {
			t.Fatalf("PutBytes([]) failed: %v", err)
		}

		expected := []byte{0x10, 0x00}
		if !bytes.Equal(buf.Bytes(), expected) {
			t.Errorf("expected %x, got %x", expected, buf.Bytes())
		}
	})
}
