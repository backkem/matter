package clusters

import (
	"testing"

	"github.com/backkem/matter/pkg/tlv"
)

// testResponse implements TLVMarshaler for testing.
type testResponse struct {
	Code    uint8
	Message string
}

func (r *testResponse) MarshalTLV(w *tlv.Writer) error {
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}
	if err := w.PutUint(tlv.ContextTag(0), uint64(r.Code)); err != nil {
		return err
	}
	if err := w.PutString(tlv.ContextTag(1), r.Message); err != nil {
		return err
	}
	return w.EndContainer()
}

// testRequest implements TLVUnmarshaler for testing.
type testRequest struct {
	Value uint32
	Name  string
}

func (r *testRequest) UnmarshalTLV(rd *tlv.Reader) error {
	// Read structure
	if err := rd.Next(); err != nil {
		return err
	}
	if err := rd.EnterContainer(); err != nil {
		return err
	}

	for {
		if err := rd.Next(); err != nil {
			return err
		}
		if rd.Type() == tlv.ElementTypeEnd {
			break
		}

		tag := rd.Tag().TagNumber()
		switch tag {
		case 0:
			v, err := rd.Uint()
			if err != nil {
				return err
			}
			r.Value = uint32(v)
		case 1:
			s, err := rd.String()
			if err != nil {
				return err
			}
			r.Name = s
		}
	}

	return rd.ExitContainer()
}

func TestCommandEncoder(t *testing.T) {
	enc := NewCommandEncoder()

	if err := enc.StartResponse(); err != nil {
		t.Fatalf("StartResponse() error = %v", err)
	}

	w := enc.Writer()
	if err := w.PutUint(tlv.ContextTag(0), 42); err != nil {
		t.Fatalf("PutUint() error = %v", err)
	}
	if err := w.PutString(tlv.ContextTag(1), "test"); err != nil {
		t.Fatalf("PutString() error = %v", err)
	}

	data, err := enc.Finish()
	if err != nil {
		t.Fatalf("Finish() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("encoded data is empty")
	}
}

func TestCommandEncoder_Reset(t *testing.T) {
	enc := NewCommandEncoder()

	// First encode
	_ = enc.StartResponse()
	_ = enc.Writer().PutUint(tlv.ContextTag(0), 1)
	_, _ = enc.Finish()

	// Reset and encode again
	enc.Reset()
	if err := enc.StartResponse(); err != nil {
		t.Fatalf("StartResponse() after Reset() error = %v", err)
	}
	if err := enc.Writer().PutUint(tlv.ContextTag(0), 2); err != nil {
		t.Fatalf("PutUint() after Reset() error = %v", err)
	}
	data, err := enc.Finish()
	if err != nil {
		t.Fatalf("Finish() after Reset() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("encoded data is empty after reset")
	}
}

func TestEncodeResponse(t *testing.T) {
	resp := &testResponse{
		Code:    0,
		Message: "OK",
	}

	data, err := EncodeResponse(resp)
	if err != nil {
		t.Fatalf("EncodeResponse() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("encoded data is empty")
	}
}

func TestEncodeResponse_Nil(t *testing.T) {
	data, err := EncodeResponse(nil)
	if err != nil {
		t.Fatalf("EncodeResponse(nil) error = %v", err)
	}
	if data != nil {
		t.Errorf("EncodeResponse(nil) = %v, want nil", data)
	}
}

func TestDecodeRequest(t *testing.T) {
	// Create encoded request data
	enc := NewCommandEncoder()
	_ = enc.StartResponse()
	_ = enc.Writer().PutUint(tlv.ContextTag(0), 123)
	_ = enc.Writer().PutString(tlv.ContextTag(1), "hello")
	data, _ := enc.Finish()

	req := &testRequest{}
	err := DecodeRequest(data, req)
	if err != nil {
		t.Fatalf("DecodeRequest() error = %v", err)
	}

	if req.Value != 123 {
		t.Errorf("Value = %d, want 123", req.Value)
	}
	if req.Name != "hello" {
		t.Errorf("Name = %q, want %q", req.Name, "hello")
	}
}

func TestDecodeRequest_Empty(t *testing.T) {
	req := &testRequest{}
	err := DecodeRequest(nil, req)
	if err != nil {
		t.Errorf("DecodeRequest(nil) error = %v, want nil", err)
	}

	err = DecodeRequest([]byte{}, req)
	if err != nil {
		t.Errorf("DecodeRequest([]) error = %v, want nil", err)
	}
}

func TestEmptyResponse(t *testing.T) {
	data := EmptyResponse()
	if data != nil {
		t.Errorf("EmptyResponse() = %v, want nil", data)
	}
}

func TestCommandDecoder(t *testing.T) {
	// Create some TLV data
	enc := NewCommandEncoder()
	_ = enc.StartResponse()
	_ = enc.Writer().PutUint(tlv.ContextTag(0), 42)
	data, _ := enc.Finish()

	dec := NewCommandDecoder(data)
	r := dec.Reader()

	if err := r.Next(); err != nil {
		t.Fatalf("Next() error = %v", err)
	}
	if r.Type() != tlv.ElementTypeStruct {
		t.Errorf("Type = %v, want Struct", r.Type())
	}
}
