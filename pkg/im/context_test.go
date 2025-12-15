package im

import (
	"testing"

	"github.com/backkem/matter/pkg/acl"
	"github.com/backkem/matter/pkg/fabric"
)

func TestNewRequestContext(t *testing.T) {
	subject := acl.SubjectDescriptor{
		FabricIndex: 1,
		Subject:     12345,
		AuthMode:    acl.AuthModeCASE,
	}

	ctx := NewRequestContext(nil, subject)

	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if ctx.Exchange != nil {
		t.Error("expected nil Exchange")
	}
	if ctx.Subject != subject {
		t.Error("subject mismatch")
	}
}

func TestRequestContext_FabricIndex(t *testing.T) {
	tests := []struct {
		name        string
		fabricIndex fabric.FabricIndex
	}{
		{"zero", 0},
		{"one", 1},
		{"max", 254},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &RequestContext{
				Subject: acl.SubjectDescriptor{
					FabricIndex: tt.fabricIndex,
				},
			}
			if got := ctx.FabricIndex(); got != tt.fabricIndex {
				t.Errorf("FabricIndex() = %d, want %d", got, tt.fabricIndex)
			}
		})
	}
}

func TestRequestContext_SourceNodeID(t *testing.T) {
	tests := []struct {
		name   string
		nodeID uint64
	}{
		{"zero", 0},
		{"typical", 0x1234567890ABCDEF},
		{"max", 0xFFFFFFFFFFFFFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &RequestContext{
				Subject: acl.SubjectDescriptor{
					Subject: tt.nodeID,
				},
			}
			if got := ctx.SourceNodeID(); got != tt.nodeID {
				t.Errorf("SourceNodeID() = %d, want %d", got, tt.nodeID)
			}
		})
	}
}

func TestRequestContext_IsCommissioning(t *testing.T) {
	tests := []struct {
		name            string
		isCommissioning bool
	}{
		{"commissioning", true},
		{"not commissioning", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &RequestContext{
				Subject: acl.SubjectDescriptor{
					IsCommissioning: tt.isCommissioning,
				},
			}
			if got := ctx.IsCommissioning(); got != tt.isCommissioning {
				t.Errorf("IsCommissioning() = %v, want %v", got, tt.isCommissioning)
			}
		})
	}
}

func TestRequestContext_AuthMode(t *testing.T) {
	tests := []struct {
		name     string
		authMode acl.AuthMode
	}{
		{"PASE", acl.AuthModePASE},
		{"CASE", acl.AuthModeCASE},
		{"Group", acl.AuthModeGroup},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &RequestContext{
				Subject: acl.SubjectDescriptor{
					AuthMode: tt.authMode,
				},
			}
			if got := ctx.AuthMode(); got != tt.authMode {
				t.Errorf("AuthMode() = %v, want %v", got, tt.authMode)
			}
		})
	}
}

func TestRequestContext_FullSubject(t *testing.T) {
	// Test with a fully populated subject
	subject := acl.SubjectDescriptor{
		FabricIndex:     2,
		Subject:         0x123456789ABC,
		AuthMode:        acl.AuthModeCASE,
		IsCommissioning: false,
		CATs:            acl.CATValues{0x1001_0001, 0x2002_0002, 0},
	}

	ctx := NewRequestContext(nil, subject)

	if ctx.FabricIndex() != 2 {
		t.Errorf("FabricIndex() = %d, want 2", ctx.FabricIndex())
	}
	if ctx.SourceNodeID() != 0x123456789ABC {
		t.Errorf("SourceNodeID() = %x, want %x", ctx.SourceNodeID(), 0x123456789ABC)
	}
	if ctx.AuthMode() != acl.AuthModeCASE {
		t.Errorf("AuthMode() = %v, want CASE", ctx.AuthMode())
	}
	if ctx.IsCommissioning() {
		t.Error("IsCommissioning() should be false")
	}

	// CATs should be accessible via Subject
	if ctx.Subject.CATs[0] != 0x1001_0001 {
		t.Errorf("CAT[0] = %x, want %x", ctx.Subject.CATs[0], 0x1001_0001)
	}
}
