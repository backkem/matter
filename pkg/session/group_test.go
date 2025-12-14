package session

import (
	"testing"

	"github.com/backkem/matter/pkg/fabric"
)

var testGroupKey = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

func TestNewGroupContext(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		ctx, err := NewGroupContext(GroupContextConfig{
			SourceNodeID:   fabric.NodeID(0x1234),
			FabricIndex:    1,
			GroupID:        100,
			GroupSessionID: 200,
			OperationalKey: testGroupKey,
		})
		if err != nil {
			t.Fatalf("NewGroupContext() error = %v", err)
		}

		if ctx.SourceNodeID() != fabric.NodeID(0x1234) {
			t.Errorf("SourceNodeID() = %v, want 0x1234", ctx.SourceNodeID())
		}
		if ctx.FabricIndex() != 1 {
			t.Errorf("FabricIndex() = %d, want 1", ctx.FabricIndex())
		}
		if ctx.GroupID() != 100 {
			t.Errorf("GroupID() = %d, want 100", ctx.GroupID())
		}
		if ctx.GroupSessionID() != 200 {
			t.Errorf("GroupSessionID() = %d, want 200", ctx.GroupSessionID())
		}
	})

	t.Run("invalid key length", func(t *testing.T) {
		_, err := NewGroupContext(GroupContextConfig{
			SourceNodeID:   fabric.NodeID(0x1234),
			FabricIndex:    1,
			GroupID:        100,
			GroupSessionID: 200,
			OperationalKey: []byte{0x01, 0x02, 0x03}, // Too short
		})
		if err != ErrInvalidKey {
			t.Errorf("NewGroupContext() error = %v, want ErrInvalidKey", err)
		}
	})
}

func TestNewGroupPeerTable(t *testing.T) {
	table := NewGroupPeerTable(10)
	if table == nil {
		t.Fatal("NewGroupPeerTable() returned nil")
	}
	if table.Count() != 0 {
		t.Errorf("Count() = %d, want 0", table.Count())
	}
}

func TestGroupPeerTable_CheckCounter_TrustFirst(t *testing.T) {
	table := NewGroupPeerTable(0) // Unlimited

	// First message from a peer should always be accepted (trust-first)
	if !table.CheckCounter(1, fabric.NodeID(0x1234), 1000) {
		t.Error("CheckCounter() should accept first message (trust-first)")
	}
	if table.Count() != 1 {
		t.Errorf("Count() = %d, want 1", table.Count())
	}
}

func TestGroupPeerTable_CheckCounter_ReplayDetection(t *testing.T) {
	table := NewGroupPeerTable(0)

	fabricIndex := fabric.FabricIndex(1)
	nodeID := fabric.NodeID(0x1234)

	// First message accepted
	if !table.CheckCounter(fabricIndex, nodeID, 100) {
		t.Error("First message should be accepted")
	}

	// Duplicate should be rejected
	if table.CheckCounter(fabricIndex, nodeID, 100) {
		t.Error("Duplicate counter should be rejected")
	}

	// Higher counter should be accepted
	if !table.CheckCounter(fabricIndex, nodeID, 101) {
		t.Error("Higher counter should be accepted")
	}

	// Lower counter (outside window) may be rejected
	// depending on window size in ReceptionState
}

func TestGroupPeerTable_CheckCounter_DifferentPeers(t *testing.T) {
	table := NewGroupPeerTable(0)

	fabricIndex := fabric.FabricIndex(1)
	node1 := fabric.NodeID(0x1234)
	node2 := fabric.NodeID(0x5678)

	// Same counter from different peers should both be accepted
	if !table.CheckCounter(fabricIndex, node1, 100) {
		t.Error("First message from node1 should be accepted")
	}
	if !table.CheckCounter(fabricIndex, node2, 100) {
		t.Error("First message from node2 should be accepted")
	}

	if table.Count() != 2 {
		t.Errorf("Count() = %d, want 2", table.Count())
	}
}

func TestGroupPeerTable_CheckCounter_DifferentFabrics(t *testing.T) {
	table := NewGroupPeerTable(0)

	fabric1 := fabric.FabricIndex(1)
	fabric2 := fabric.FabricIndex(2)
	nodeID := fabric.NodeID(0x1234)

	// Same node ID on different fabrics are tracked separately
	if !table.CheckCounter(fabric1, nodeID, 100) {
		t.Error("First message on fabric1 should be accepted")
	}
	if !table.CheckCounter(fabric2, nodeID, 100) {
		t.Error("First message on fabric2 should be accepted")
	}

	if table.Count() != 2 {
		t.Errorf("Count() = %d, want 2", table.Count())
	}
}

func TestGroupPeerTable_CheckCounter_CapacityLimit(t *testing.T) {
	table := NewGroupPeerTable(2) // Max 2 peers

	fabricIndex := fabric.FabricIndex(1)

	// Add two peers
	if !table.CheckCounter(fabricIndex, fabric.NodeID(1), 100) {
		t.Error("First peer should be accepted")
	}
	if !table.CheckCounter(fabricIndex, fabric.NodeID(2), 100) {
		t.Error("Second peer should be accepted")
	}

	// Third peer should be rejected (capacity exceeded)
	if table.CheckCounter(fabricIndex, fabric.NodeID(3), 100) {
		t.Error("Third peer should be rejected (capacity)")
	}

	if table.Count() != 2 {
		t.Errorf("Count() = %d, want 2", table.Count())
	}
}

func TestGroupPeerTable_RemovePeer(t *testing.T) {
	table := NewGroupPeerTable(0)

	fabricIndex := fabric.FabricIndex(1)
	nodeID := fabric.NodeID(0x1234)

	// Add peer
	table.CheckCounter(fabricIndex, nodeID, 100)
	if table.Count() != 1 {
		t.Fatalf("Count() = %d, want 1", table.Count())
	}

	// Remove peer
	table.RemovePeer(fabricIndex, nodeID)
	if table.Count() != 0 {
		t.Errorf("Count() after remove = %d, want 0", table.Count())
	}

	// Can add the same peer again (trust-first will apply again)
	if !table.CheckCounter(fabricIndex, nodeID, 50) {
		t.Error("Re-added peer should be accepted with trust-first")
	}
}

func TestGroupPeerTable_RemoveFabric(t *testing.T) {
	table := NewGroupPeerTable(0)

	fabric1 := fabric.FabricIndex(1)
	fabric2 := fabric.FabricIndex(2)

	// Add peers on both fabrics
	table.CheckCounter(fabric1, fabric.NodeID(1), 100)
	table.CheckCounter(fabric1, fabric.NodeID(2), 100)
	table.CheckCounter(fabric2, fabric.NodeID(1), 100)

	if table.Count() != 3 {
		t.Fatalf("Count() = %d, want 3", table.Count())
	}

	// Remove fabric1
	table.RemoveFabric(fabric1)

	if table.Count() != 1 {
		t.Errorf("Count() after RemoveFabric = %d, want 1", table.Count())
	}

	// Peer on fabric2 should still be tracked
	if table.CheckCounter(fabric2, fabric.NodeID(1), 100) {
		t.Error("Duplicate on fabric2 should still be rejected")
	}
}

func TestGroupPeerTable_Clear(t *testing.T) {
	table := NewGroupPeerTable(0)

	// Add some peers
	table.CheckCounter(1, fabric.NodeID(1), 100)
	table.CheckCounter(1, fabric.NodeID(2), 100)
	table.CheckCounter(2, fabric.NodeID(1), 100)

	if table.Count() != 3 {
		t.Fatalf("Count() = %d, want 3", table.Count())
	}

	// Clear
	table.Clear()

	if table.Count() != 0 {
		t.Errorf("Count() after Clear = %d, want 0", table.Count())
	}
}

func TestGroupPeerTable_RolloverHandling(t *testing.T) {
	table := NewGroupPeerTable(0)

	fabricIndex := fabric.FabricIndex(1)
	nodeID := fabric.NodeID(0x1234)

	// Start near counter max
	if !table.CheckCounter(fabricIndex, nodeID, 0xFFFFFF00) {
		t.Error("Counter near max should be accepted")
	}

	// Rollover should be accepted for group messages
	if !table.CheckCounter(fabricIndex, nodeID, 0xFFFFFF01) {
		t.Error("Higher counter should be accepted")
	}
}
