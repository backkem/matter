package session

import (
	"testing"

	"github.com/backkem/matter/pkg/fabric"
)

func TestNewManager(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		m := NewManager(ManagerConfig{})

		if m.SecureSessionCount() != 0 {
			t.Errorf("SecureSessionCount() = %d, want 0", m.SecureSessionCount())
		}
		if m.IsSecureTableFull() {
			t.Error("IsSecureTableFull() should be false")
		}
		if m.GroupPeerCount() != 0 {
			t.Errorf("GroupPeerCount() = %d, want 0", m.GroupPeerCount())
		}
	})

	t.Run("custom config", func(t *testing.T) {
		m := NewManager(ManagerConfig{
			MaxSessions:   50,
			MaxGroupPeers: 100,
		})

		// Fill to verify limits (indirect test)
		if m == nil {
			t.Fatal("NewManager() returned nil")
		}
	})
}

func TestManager_AllocateSessionID(t *testing.T) {
	m := NewManager(ManagerConfig{MaxSessions: 10})

	id1, err := m.AllocateSessionID()
	if err != nil {
		t.Fatalf("AllocateSessionID() error = %v", err)
	}
	if id1 == 0 {
		t.Error("AllocateSessionID() returned 0")
	}

	id2, err := m.AllocateSessionID()
	if err != nil {
		t.Fatalf("AllocateSessionID() error = %v", err)
	}
	if id2 == id1 {
		t.Error("AllocateSessionID() returned duplicate ID")
	}
}

func TestManager_AddRemoveSecureContext(t *testing.T) {
	m := NewManager(ManagerConfig{MaxSessions: 10})

	ctx := createTestSecureContext(123)

	// Add
	err := m.AddSecureContext(ctx)
	if err != nil {
		t.Fatalf("AddSecureContext() error = %v", err)
	}
	if m.SecureSessionCount() != 1 {
		t.Errorf("SecureSessionCount() = %d, want 1", m.SecureSessionCount())
	}

	// Find
	found := m.FindSecureContext(123)
	if found == nil {
		t.Error("FindSecureContext() returned nil")
	}

	// Remove
	m.RemoveSecureContext(123)
	if m.SecureSessionCount() != 0 {
		t.Errorf("SecureSessionCount() after remove = %d, want 0", m.SecureSessionCount())
	}
}

func TestManager_FindSecureContextByPeer(t *testing.T) {
	m := NewManager(ManagerConfig{MaxSessions: 10})

	ctx1 := createTestSecureContextWithPeer(1, fabric.FabricIndex(1), fabric.NodeID(0x1234))
	ctx2 := createTestSecureContextWithPeer(2, fabric.FabricIndex(1), fabric.NodeID(0x1234))
	ctx3 := createTestSecureContextWithPeer(3, fabric.FabricIndex(1), fabric.NodeID(0x5678))

	m.AddSecureContext(ctx1)
	m.AddSecureContext(ctx2)
	m.AddSecureContext(ctx3)

	found := m.FindSecureContextByPeer(fabric.FabricIndex(1), fabric.NodeID(0x1234))
	if len(found) != 2 {
		t.Errorf("FindSecureContextByPeer() returned %d sessions, want 2", len(found))
	}
}

func TestManager_FindSecureContextByFabric(t *testing.T) {
	m := NewManager(ManagerConfig{MaxSessions: 10})

	ctx1 := createTestSecureContextWithPeer(1, fabric.FabricIndex(1), fabric.NodeID(0x1234))
	ctx2 := createTestSecureContextWithPeer(2, fabric.FabricIndex(1), fabric.NodeID(0x5678))
	ctx3 := createTestSecureContextWithPeer(3, fabric.FabricIndex(2), fabric.NodeID(0x1234))

	m.AddSecureContext(ctx1)
	m.AddSecureContext(ctx2)
	m.AddSecureContext(ctx3)

	found := m.FindSecureContextByFabric(fabric.FabricIndex(1))
	if len(found) != 2 {
		t.Errorf("FindSecureContextByFabric() returned %d sessions, want 2", len(found))
	}
}

func TestManager_GlobalCounter(t *testing.T) {
	m := NewManager(ManagerConfig{})

	gc := m.GlobalCounter()
	if gc == nil {
		t.Fatal("GlobalCounter() returned nil")
	}

	c1, err := m.NextGlobalCounter()
	if err != nil {
		t.Fatalf("NextGlobalCounter() error = %v", err)
	}

	c2, err := m.NextGlobalCounter()
	if err != nil {
		t.Fatalf("NextGlobalCounter() error = %v", err)
	}

	if c2 != c1+1 {
		t.Errorf("NextGlobalCounter() = %d, want %d", c2, c1+1)
	}
}

func TestManager_CheckGroupCounter(t *testing.T) {
	m := NewManager(ManagerConfig{MaxGroupPeers: 10})

	fabricIndex := fabric.FabricIndex(1)
	nodeID := fabric.NodeID(0x1234)

	// First message accepted (trust-first)
	if !m.CheckGroupCounter(fabricIndex, nodeID, 100) {
		t.Error("CheckGroupCounter() should accept first message")
	}

	// Duplicate rejected
	if m.CheckGroupCounter(fabricIndex, nodeID, 100) {
		t.Error("CheckGroupCounter() should reject duplicate")
	}

	// Higher counter accepted
	if !m.CheckGroupCounter(fabricIndex, nodeID, 101) {
		t.Error("CheckGroupCounter() should accept higher counter")
	}

	if m.GroupPeerCount() != 1 {
		t.Errorf("GroupPeerCount() = %d, want 1", m.GroupPeerCount())
	}
}

func TestManager_RemoveGroupPeer(t *testing.T) {
	m := NewManager(ManagerConfig{})

	fabricIndex := fabric.FabricIndex(1)
	nodeID := fabric.NodeID(0x1234)

	m.CheckGroupCounter(fabricIndex, nodeID, 100)
	if m.GroupPeerCount() != 1 {
		t.Fatalf("GroupPeerCount() = %d, want 1", m.GroupPeerCount())
	}

	m.RemoveGroupPeer(fabricIndex, nodeID)
	if m.GroupPeerCount() != 0 {
		t.Errorf("GroupPeerCount() after remove = %d, want 0", m.GroupPeerCount())
	}
}

func TestManager_RemoveFabric(t *testing.T) {
	m := NewManager(ManagerConfig{MaxSessions: 10})

	// Add sessions on different fabrics
	ctx1 := createTestSecureContextWithPeer(1, fabric.FabricIndex(1), fabric.NodeID(0x1234))
	ctx2 := createTestSecureContextWithPeer(2, fabric.FabricIndex(1), fabric.NodeID(0x5678))
	ctx3 := createTestSecureContextWithPeer(3, fabric.FabricIndex(2), fabric.NodeID(0x1234))

	m.AddSecureContext(ctx1)
	m.AddSecureContext(ctx2)
	m.AddSecureContext(ctx3)

	// Add group peers on different fabrics
	m.CheckGroupCounter(fabric.FabricIndex(1), fabric.NodeID(0x1111), 100)
	m.CheckGroupCounter(fabric.FabricIndex(1), fabric.NodeID(0x2222), 100)
	m.CheckGroupCounter(fabric.FabricIndex(2), fabric.NodeID(0x1111), 100)

	// Remove fabric 1
	m.RemoveFabric(fabric.FabricIndex(1))

	// Should have 1 session and 1 group peer left (fabric 2)
	if m.SecureSessionCount() != 1 {
		t.Errorf("SecureSessionCount() after RemoveFabric = %d, want 1", m.SecureSessionCount())
	}
	if m.GroupPeerCount() != 1 {
		t.Errorf("GroupPeerCount() after RemoveFabric = %d, want 1", m.GroupPeerCount())
	}
}

func TestManager_RemovePeer(t *testing.T) {
	m := NewManager(ManagerConfig{MaxSessions: 10})

	fabricIndex := fabric.FabricIndex(1)
	peerNodeID := fabric.NodeID(0x1234)
	otherNodeID := fabric.NodeID(0x5678)

	// Add sessions
	ctx1 := createTestSecureContextWithPeer(1, fabricIndex, peerNodeID)
	ctx2 := createTestSecureContextWithPeer(2, fabricIndex, peerNodeID)
	ctx3 := createTestSecureContextWithPeer(3, fabricIndex, otherNodeID)

	m.AddSecureContext(ctx1)
	m.AddSecureContext(ctx2)
	m.AddSecureContext(ctx3)

	// Add group peer tracking
	m.CheckGroupCounter(fabricIndex, peerNodeID, 100)
	m.CheckGroupCounter(fabricIndex, otherNodeID, 100)

	// Remove peer
	m.RemovePeer(fabricIndex, peerNodeID)

	if m.SecureSessionCount() != 1 {
		t.Errorf("SecureSessionCount() after RemovePeer = %d, want 1", m.SecureSessionCount())
	}
	if m.GroupPeerCount() != 1 {
		t.Errorf("GroupPeerCount() after RemovePeer = %d, want 1", m.GroupPeerCount())
	}
}

func TestManager_Clear(t *testing.T) {
	m := NewManager(ManagerConfig{MaxSessions: 10})

	// Add sessions
	ctx1 := createTestSecureContext(1)
	ctx2 := createTestSecureContext(2)
	m.AddSecureContext(ctx1)
	m.AddSecureContext(ctx2)

	// Add group peers
	m.CheckGroupCounter(fabric.FabricIndex(1), fabric.NodeID(0x1234), 100)

	// Use global counter
	m.NextGlobalCounter()

	// Clear
	m.Clear()

	if m.SecureSessionCount() != 0 {
		t.Errorf("SecureSessionCount() after Clear = %d, want 0", m.SecureSessionCount())
	}
	if m.GroupPeerCount() != 0 {
		t.Errorf("GroupPeerCount() after Clear = %d, want 0", m.GroupPeerCount())
	}
}

func TestManager_ForEachSecureSession(t *testing.T) {
	m := NewManager(ManagerConfig{MaxSessions: 10})

	for i := uint16(1); i <= 3; i++ {
		ctx := createTestSecureContext(i)
		m.AddSecureContext(ctx)
	}

	count := 0
	m.ForEachSecureSession(func(ctx *SecureContext) bool {
		count++
		return true
	})

	if count != 3 {
		t.Errorf("ForEachSecureSession visited %d sessions, want 3", count)
	}
}

func TestManager_IsSecureTableFull(t *testing.T) {
	m := NewManager(ManagerConfig{MaxSessions: 2})

	if m.IsSecureTableFull() {
		t.Error("Empty table should not be full")
	}

	m.AddSecureContext(createTestSecureContext(1))
	if m.IsSecureTableFull() {
		t.Error("Table with 1/2 should not be full")
	}

	m.AddSecureContext(createTestSecureContext(2))
	if !m.IsSecureTableFull() {
		t.Error("Table with 2/2 should be full")
	}
}

func TestManager_KeyZeroizationOnRemove(t *testing.T) {
	m := NewManager(ManagerConfig{MaxSessions: 10})

	ctx := createTestSecureContext(123)
	m.AddSecureContext(ctx)

	// Remove should zeroize keys
	m.RemoveSecureContext(123)

	// Check that the context's keys were zeroed
	for _, b := range ctx.i2rKey {
		if b != 0 {
			t.Error("i2rKey should be zeroed after RemoveSecureContext")
			break
		}
	}
}
