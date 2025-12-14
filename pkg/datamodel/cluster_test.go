package datamodel

import (
	"bytes"
	"context"
	"testing"

	"github.com/backkem/matter/pkg/tlv"
)

func TestClusterBase_New(t *testing.T) {
	cb := NewClusterBase(ClusterOnOff, 1, 4)

	if cb.ID() != ClusterOnOff {
		t.Errorf("ID() = %v, want OnOff", cb.ID())
	}

	if cb.EndpointID() != 1 {
		t.Errorf("EndpointID() = %v, want 1", cb.EndpointID())
	}

	if cb.ClusterRevision() != 4 {
		t.Errorf("ClusterRevision() = %v, want 4", cb.ClusterRevision())
	}

	if cb.FeatureMap() != 0 {
		t.Errorf("FeatureMap() = %v, want 0", cb.FeatureMap())
	}

	// DataVersion should be randomly initialized (non-deterministic)
	// Just verify it exists
	_ = cb.DataVersion()
}

func TestClusterBase_SetFeatureMap(t *testing.T) {
	cb := NewClusterBase(ClusterOnOff, 0, 1)

	cb.SetFeatureMap(0x0001)

	if cb.FeatureMap() != 0x0001 {
		t.Errorf("FeatureMap() = 0x%04X, want 0x0001", cb.FeatureMap())
	}
}

func TestClusterBase_DataVersion(t *testing.T) {
	cb := NewClusterBase(ClusterOnOff, 0, 1)

	initial := cb.DataVersion()

	cb.IncrementDataVersion()

	if cb.DataVersion() != initial+1 {
		t.Errorf("After increment: DataVersion() = %v, want %v", cb.DataVersion(), initial+1)
	}

	cb.SetDataVersion(100)
	if cb.DataVersion() != 100 {
		t.Errorf("After set: DataVersion() = %v, want 100", cb.DataVersion())
	}
}

func TestClusterBase_Path(t *testing.T) {
	cb := NewClusterBase(ClusterOnOff, 2, 1)

	path := cb.Path()
	if path.Endpoint != 2 {
		t.Errorf("Path().Endpoint = %v, want 2", path.Endpoint)
	}
	if path.Cluster != ClusterOnOff {
		t.Errorf("Path().Cluster = %v, want OnOff", path.Cluster)
	}
}

func TestClusterBase_AttributePath(t *testing.T) {
	cb := NewClusterBase(ClusterOnOff, 2, 1)

	path := cb.AttributePath(5)

	if path.Endpoint != 2 {
		t.Errorf("AttributePath.Endpoint = %v, want 2", path.Endpoint)
	}
	if path.Cluster != ClusterOnOff {
		t.Errorf("AttributePath.Cluster = %v, want OnOff", path.Cluster)
	}
	if path.Attribute != 5 {
		t.Errorf("AttributePath.Attribute = %v, want 5", path.Attribute)
	}
}

func TestClusterBase_CommandPath(t *testing.T) {
	cb := NewClusterBase(ClusterOnOff, 2, 1)

	path := cb.CommandPath(3)

	if path.Endpoint != 2 {
		t.Errorf("CommandPath.Endpoint = %v, want 2", path.Endpoint)
	}
	if path.Cluster != ClusterOnOff {
		t.Errorf("CommandPath.Cluster = %v, want OnOff", path.Cluster)
	}
	if path.Command != 3 {
		t.Errorf("CommandPath.Command = %v, want 3", path.Command)
	}
}

func TestClusterBase_ReadGlobalAttribute(t *testing.T) {
	cb := NewClusterBase(ClusterOnOff, 0, 4)
	cb.SetFeatureMap(0x0003)

	attrList := []AttributeEntry{
		{ID: 0},
		{ID: 1},
	}
	attrList = MergeAttributeLists(attrList)

	cmdList := []CommandEntry{
		{ID: 0},
		{ID: 1},
	}
	genCmdList := []CommandID{2, 3}

	ctx := context.Background()

	t.Run("ClusterRevision", func(t *testing.T) {
		var buf bytes.Buffer
		w := tlv.NewWriter(&buf)

		handled, err := cb.ReadGlobalAttribute(ctx, GlobalAttrClusterRevision, w, attrList, cmdList, genCmdList)
		if err != nil {
			t.Fatalf("ReadGlobalAttribute failed: %v", err)
		}
		if !handled {
			t.Error("ClusterRevision should be handled")
		}

		// Verify TLV output
		r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
		if err := r.Next(); err != nil {
			t.Fatalf("TLV read failed: %v", err)
		}
		v, err := r.Uint()
		if err != nil {
			t.Fatalf("Failed to read uint: %v", err)
		}
		if v != 4 {
			t.Errorf("ClusterRevision value = %v, want 4", v)
		}
	})

	t.Run("FeatureMap", func(t *testing.T) {
		var buf bytes.Buffer
		w := tlv.NewWriter(&buf)

		handled, err := cb.ReadGlobalAttribute(ctx, GlobalAttrFeatureMap, w, attrList, cmdList, genCmdList)
		if err != nil {
			t.Fatalf("ReadGlobalAttribute failed: %v", err)
		}
		if !handled {
			t.Error("FeatureMap should be handled")
		}

		r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
		if err := r.Next(); err != nil {
			t.Fatalf("TLV read failed: %v", err)
		}
		v, err := r.Uint()
		if err != nil {
			t.Fatalf("Failed to read uint: %v", err)
		}
		if v != 0x0003 {
			t.Errorf("FeatureMap value = 0x%04X, want 0x0003", v)
		}
	})

	t.Run("AttributeList", func(t *testing.T) {
		var buf bytes.Buffer
		w := tlv.NewWriter(&buf)

		handled, err := cb.ReadGlobalAttribute(ctx, GlobalAttrAttributeList, w, attrList, cmdList, genCmdList)
		if err != nil {
			t.Fatalf("ReadGlobalAttribute failed: %v", err)
		}
		if !handled {
			t.Error("AttributeList should be handled")
		}

		// Parse the array
		r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
		if err := r.Next(); err != nil {
			t.Fatalf("TLV read failed: %v", err)
		}
		if r.Type() != tlv.ElementTypeArray {
			t.Errorf("Expected array, got %v", r.Type())
		}

		if err := r.EnterContainer(); err != nil {
			t.Fatalf("EnterContainer failed: %v", err)
		}

		var ids []uint64
		for {
			if err := r.Next(); err != nil || r.IsEndOfContainer() {
				break
			}
			v, _ := r.Uint()
			ids = append(ids, v)
		}

		// Should have cluster attrs (0, 1) + globals
		if len(ids) != len(attrList) {
			t.Errorf("AttributeList len = %v, want %v", len(ids), len(attrList))
		}
	})

	t.Run("AcceptedCommandList", func(t *testing.T) {
		var buf bytes.Buffer
		w := tlv.NewWriter(&buf)

		handled, err := cb.ReadGlobalAttribute(ctx, GlobalAttrAcceptedCommandList, w, attrList, cmdList, genCmdList)
		if err != nil {
			t.Fatalf("ReadGlobalAttribute failed: %v", err)
		}
		if !handled {
			t.Error("AcceptedCommandList should be handled")
		}
	})

	t.Run("GeneratedCommandList", func(t *testing.T) {
		var buf bytes.Buffer
		w := tlv.NewWriter(&buf)

		handled, err := cb.ReadGlobalAttribute(ctx, GlobalAttrGeneratedCommandList, w, attrList, cmdList, genCmdList)
		if err != nil {
			t.Fatalf("ReadGlobalAttribute failed: %v", err)
		}
		if !handled {
			t.Error("GeneratedCommandList should be handled")
		}
	})

	t.Run("NonGlobal", func(t *testing.T) {
		var buf bytes.Buffer
		w := tlv.NewWriter(&buf)

		handled, err := cb.ReadGlobalAttribute(ctx, 0, w, attrList, cmdList, genCmdList)
		if err != nil {
			t.Fatalf("ReadGlobalAttribute failed: %v", err)
		}
		if handled {
			t.Error("Non-global attribute should not be handled")
		}
	})
}

func TestClusterBase_GlobalAttributeList(t *testing.T) {
	cb := NewClusterBase(ClusterOnOff, 0, 1)

	globals := cb.GlobalAttributeList()

	if len(globals) != 5 {
		t.Errorf("len(GlobalAttributeList()) = %v, want 5", len(globals))
	}
}
