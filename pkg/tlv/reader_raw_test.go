package tlv

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestReader_RawBytes_Structure(t *testing.T) {
	// Create a structure: {0: 60, 1: 0}
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.StartStructure(Anonymous()); err != nil {
		t.Fatal(err)
	}
	if err := w.PutUint(ContextTag(0), 60); err != nil {
		t.Fatal(err)
	}
	if err := w.PutUint(ContextTag(1), 0); err != nil {
		t.Fatal(err)
	}
	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}

	original := buf.Bytes()
	t.Logf("Original TLV: %s", hex.EncodeToString(original))

	// Read with RawBytes
	r := NewReader(bytes.NewReader(original))
	if err := r.Next(); err != nil {
		t.Fatalf("Next() failed: %v", err)
	}

	raw, err := r.RawBytes()
	if err != nil {
		t.Fatalf("RawBytes() failed: %v", err)
	}
	t.Logf("RawBytes result: %s", hex.EncodeToString(raw))

	// Re-encode with PutRaw using context tag 1
	var buf2 bytes.Buffer
	w2 := NewWriter(&buf2)
	if err := w2.PutRaw(ContextTag(1), raw); err != nil {
		t.Fatalf("PutRaw() failed: %v", err)
	}

	result := buf2.Bytes()
	t.Logf("PutRaw result: %s", hex.EncodeToString(result))

	// Verify we can decode it back
	r2 := NewReader(bytes.NewReader(result))
	if err := r2.Next(); err != nil {
		t.Fatalf("Next() on result failed: %v", err)
	}

	if r2.Type() != ElementTypeStruct {
		t.Errorf("Expected structure, got %v", r2.Type())
	}

	if !r2.Tag().IsContext() || r2.Tag().TagNumber() != 1 {
		t.Errorf("Expected context tag 1, got %v", r2.Tag())
	}

	// Enter and verify contents
	if err := r2.EnterContainer(); err != nil {
		t.Fatalf("EnterContainer() failed: %v", err)
	}

	// Field 0
	if err := r2.Next(); err != nil {
		t.Fatalf("Next() field 0 failed: %v", err)
	}
	if !r2.Tag().IsContext() || r2.Tag().TagNumber() != 0 {
		t.Errorf("Expected context tag 0, got %v", r2.Tag())
	}
	val0, err := r2.Uint()
	if err != nil {
		t.Fatalf("Uint() field 0 failed: %v", err)
	}
	if val0 != 60 {
		t.Errorf("Expected field 0 = 60, got %d", val0)
	}

	// Field 1
	if err := r2.Next(); err != nil {
		t.Fatalf("Next() field 1 failed: %v", err)
	}
	if !r2.Tag().IsContext() || r2.Tag().TagNumber() != 1 {
		t.Errorf("Expected context tag 1, got %v", r2.Tag())
	}
	val1, err := r2.Uint()
	if err != nil {
		t.Fatalf("Uint() field 1 failed: %v", err)
	}
	if val1 != 0 {
		t.Errorf("Expected field 1 = 0, got %d", val1)
	}

	if err := r2.ExitContainer(); err != nil {
		t.Fatalf("ExitContainer() failed: %v", err)
	}
}

func TestReader_RawBytes_NestedStructure(t *testing.T) {
	// Create nested structure: {0: {0: 1, 1: 2}, 1: 3}
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.StartStructure(Anonymous()); err != nil {
		t.Fatal(err)
	}
	if err := w.StartStructure(ContextTag(0)); err != nil {
		t.Fatal(err)
	}
	if err := w.PutUint(ContextTag(0), 1); err != nil {
		t.Fatal(err)
	}
	if err := w.PutUint(ContextTag(1), 2); err != nil {
		t.Fatal(err)
	}
	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}
	if err := w.PutUint(ContextTag(1), 3); err != nil {
		t.Fatal(err)
	}
	if err := w.EndContainer(); err != nil {
		t.Fatal(err)
	}

	original := buf.Bytes()

	// Read and re-encode with RawBytes
	r := NewReader(bytes.NewReader(original))
	if err := r.Next(); err != nil {
		t.Fatalf("Next() failed: %v", err)
	}

	raw, err := r.RawBytes()
	if err != nil {
		t.Fatalf("RawBytes() failed: %v", err)
	}

	// Re-encode
	var buf2 bytes.Buffer
	w2 := NewWriter(&buf2)
	if err := w2.PutRaw(ContextTag(2), raw); err != nil {
		t.Fatalf("PutRaw() failed: %v", err)
	}

	// Verify structure is preserved
	r2 := NewReader(bytes.NewReader(buf2.Bytes()))
	if err := r2.Next(); err != nil {
		t.Fatalf("Next() failed: %v", err)
	}
	if err := r2.EnterContainer(); err != nil {
		t.Fatalf("EnterContainer() failed: %v", err)
	}

	// Nested structure at tag 0
	if err := r2.Next(); err != nil {
		t.Fatalf("Next() nested failed: %v", err)
	}
	if r2.Type() != ElementTypeStruct {
		t.Errorf("Expected nested structure, got %v", r2.Type())
	}
}
