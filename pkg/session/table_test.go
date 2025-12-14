package session

import (
	"testing"

	"github.com/backkem/matter/pkg/fabric"
)

func TestNewTable(t *testing.T) {
	t.Run("default max sessions", func(t *testing.T) {
		table := NewTable(0)
		if table.MaxSessions() != DefaultMaxSessions {
			t.Errorf("MaxSessions() = %d, want %d", table.MaxSessions(), DefaultMaxSessions)
		}
	})

	t.Run("custom max sessions", func(t *testing.T) {
		table := NewTable(100)
		if table.MaxSessions() != 100 {
			t.Errorf("MaxSessions() = %d, want 100", table.MaxSessions())
		}
	})

	t.Run("initial state", func(t *testing.T) {
		table := NewTable(10)
		if table.Count() != 0 {
			t.Errorf("Count() = %d, want 0", table.Count())
		}
		if table.IsFull() {
			t.Error("IsFull() should be false for empty table")
		}
	})
}

func TestTable_AllocateID(t *testing.T) {
	t.Run("allocates unique IDs", func(t *testing.T) {
		table := NewTable(100)
		ids := make(map[uint16]bool)

		for i := 0; i < 10; i++ {
			id, err := table.AllocateID()
			if err != nil {
				t.Fatalf("AllocateID() error = %v", err)
			}
			if id == 0 {
				t.Error("AllocateID() returned 0, which is invalid")
			}
			if ids[id] {
				t.Errorf("AllocateID() returned duplicate ID: %d", id)
			}
			ids[id] = true
		}
	})

	t.Run("returns error when table full", func(t *testing.T) {
		table := NewTable(2)

		// Fill the table
		for i := 0; i < 2; i++ {
			id, _ := table.AllocateID()
			ctx := createTestSecureContext(id)
			table.Add(ctx)
		}

		// Next allocation should fail
		_, err := table.AllocateID()
		if err != ErrSessionTableFull {
			t.Errorf("AllocateID() error = %v, want ErrSessionTableFull", err)
		}
	})

	t.Run("reuses freed IDs", func(t *testing.T) {
		table := NewTable(2)

		// Allocate and add
		id1, _ := table.AllocateID()
		ctx1 := createTestSecureContext(id1)
		table.Add(ctx1)

		id2, _ := table.AllocateID()
		ctx2 := createTestSecureContext(id2)
		table.Add(ctx2)

		// Remove first
		table.Remove(id1)

		// Should be able to allocate again
		id3, err := table.AllocateID()
		if err != nil {
			t.Fatalf("AllocateID() after remove error = %v", err)
		}
		if id3 == 0 {
			t.Error("AllocateID() returned 0")
		}
	})
}

func TestTable_Add(t *testing.T) {
	t.Run("adds session successfully", func(t *testing.T) {
		table := NewTable(10)
		ctx := createTestSecureContext(123)

		err := table.Add(ctx)
		if err != nil {
			t.Fatalf("Add() error = %v", err)
		}
		if table.Count() != 1 {
			t.Errorf("Count() = %d, want 1", table.Count())
		}
	})

	t.Run("rejects nil context", func(t *testing.T) {
		table := NewTable(10)
		err := table.Add(nil)
		if err != ErrInvalidSessionID {
			t.Errorf("Add(nil) error = %v, want ErrInvalidSessionID", err)
		}
	})

	t.Run("rejects duplicate session ID", func(t *testing.T) {
		table := NewTable(10)
		ctx1 := createTestSecureContext(123)
		ctx2 := createTestSecureContext(123) // Same ID

		table.Add(ctx1)
		err := table.Add(ctx2)
		if err != ErrDuplicateSession {
			t.Errorf("Add() duplicate error = %v, want ErrDuplicateSession", err)
		}
	})

	t.Run("rejects when table full", func(t *testing.T) {
		table := NewTable(1)
		ctx1 := createTestSecureContext(1)
		ctx2 := createTestSecureContext(2)

		table.Add(ctx1)
		err := table.Add(ctx2)
		if err != ErrSessionTableFull {
			t.Errorf("Add() when full error = %v, want ErrSessionTableFull", err)
		}
	})
}

func TestTable_FindByLocalID(t *testing.T) {
	table := NewTable(10)
	ctx := createTestSecureContext(123)
	table.Add(ctx)

	t.Run("finds existing session", func(t *testing.T) {
		found := table.FindByLocalID(123)
		if found == nil {
			t.Fatal("FindByLocalID() returned nil")
		}
		if found.LocalSessionID() != 123 {
			t.Errorf("Found session ID = %d, want 123", found.LocalSessionID())
		}
	})

	t.Run("returns nil for non-existent", func(t *testing.T) {
		found := table.FindByLocalID(999)
		if found != nil {
			t.Error("FindByLocalID() should return nil for non-existent ID")
		}
	})
}

func TestTable_FindByPeer(t *testing.T) {
	table := NewTable(10)

	// Add sessions with different peers
	ctx1 := createTestSecureContextWithPeer(1, fabric.FabricIndex(1), fabric.NodeID(0x1234))
	ctx2 := createTestSecureContextWithPeer(2, fabric.FabricIndex(1), fabric.NodeID(0x1234))
	ctx3 := createTestSecureContextWithPeer(3, fabric.FabricIndex(1), fabric.NodeID(0x5678))
	ctx4 := createTestSecureContextWithPeer(4, fabric.FabricIndex(2), fabric.NodeID(0x1234))

	table.Add(ctx1)
	table.Add(ctx2)
	table.Add(ctx3)
	table.Add(ctx4)

	t.Run("finds sessions by peer", func(t *testing.T) {
		found := table.FindByPeer(fabric.FabricIndex(1), fabric.NodeID(0x1234))
		if len(found) != 2 {
			t.Errorf("FindByPeer() returned %d sessions, want 2", len(found))
		}
	})

	t.Run("returns empty for non-existent peer", func(t *testing.T) {
		found := table.FindByPeer(fabric.FabricIndex(1), fabric.NodeID(0x9999))
		if len(found) != 0 {
			t.Errorf("FindByPeer() returned %d sessions, want 0", len(found))
		}
	})
}

func TestTable_FindByFabric(t *testing.T) {
	table := NewTable(10)

	ctx1 := createTestSecureContextWithPeer(1, fabric.FabricIndex(1), fabric.NodeID(0x1234))
	ctx2 := createTestSecureContextWithPeer(2, fabric.FabricIndex(1), fabric.NodeID(0x5678))
	ctx3 := createTestSecureContextWithPeer(3, fabric.FabricIndex(2), fabric.NodeID(0x1234))

	table.Add(ctx1)
	table.Add(ctx2)
	table.Add(ctx3)

	found := table.FindByFabric(fabric.FabricIndex(1))
	if len(found) != 2 {
		t.Errorf("FindByFabric() returned %d sessions, want 2", len(found))
	}
}

func TestTable_Remove(t *testing.T) {
	table := NewTable(10)
	ctx := createTestSecureContext(123)
	table.Add(ctx)

	table.Remove(123)

	if table.Count() != 0 {
		t.Errorf("Count() after Remove = %d, want 0", table.Count())
	}
	if table.FindByLocalID(123) != nil {
		t.Error("Session should not be found after Remove")
	}

	// Removing non-existent should not error
	table.Remove(999) // Should not panic
}

func TestTable_RemoveByFabric(t *testing.T) {
	table := NewTable(10)

	ctx1 := createTestSecureContextWithPeer(1, fabric.FabricIndex(1), fabric.NodeID(0x1234))
	ctx2 := createTestSecureContextWithPeer(2, fabric.FabricIndex(1), fabric.NodeID(0x5678))
	ctx3 := createTestSecureContextWithPeer(3, fabric.FabricIndex(2), fabric.NodeID(0x1234))

	table.Add(ctx1)
	table.Add(ctx2)
	table.Add(ctx3)

	removed := table.RemoveByFabric(fabric.FabricIndex(1))
	if removed != 2 {
		t.Errorf("RemoveByFabric() removed %d, want 2", removed)
	}
	if table.Count() != 1 {
		t.Errorf("Count() after RemoveByFabric = %d, want 1", table.Count())
	}
}

func TestTable_RemoveByPeer(t *testing.T) {
	table := NewTable(10)

	ctx1 := createTestSecureContextWithPeer(1, fabric.FabricIndex(1), fabric.NodeID(0x1234))
	ctx2 := createTestSecureContextWithPeer(2, fabric.FabricIndex(1), fabric.NodeID(0x1234))
	ctx3 := createTestSecureContextWithPeer(3, fabric.FabricIndex(1), fabric.NodeID(0x5678))

	table.Add(ctx1)
	table.Add(ctx2)
	table.Add(ctx3)

	removed := table.RemoveByPeer(fabric.FabricIndex(1), fabric.NodeID(0x1234))
	if removed != 2 {
		t.Errorf("RemoveByPeer() removed %d, want 2", removed)
	}
	if table.Count() != 1 {
		t.Errorf("Count() after RemoveByPeer = %d, want 1", table.Count())
	}
}

func TestTable_Clear(t *testing.T) {
	table := NewTable(10)

	for i := uint16(1); i <= 5; i++ {
		ctx := createTestSecureContext(i)
		table.Add(ctx)
	}

	table.Clear()

	if table.Count() != 0 {
		t.Errorf("Count() after Clear = %d, want 0", table.Count())
	}
}

func TestTable_ForEach(t *testing.T) {
	table := NewTable(10)

	for i := uint16(1); i <= 3; i++ {
		ctx := createTestSecureContext(i)
		table.Add(ctx)
	}

	var visited []uint16
	table.ForEach(func(ctx *SecureContext) bool {
		visited = append(visited, ctx.LocalSessionID())
		return true
	})

	if len(visited) != 3 {
		t.Errorf("ForEach visited %d sessions, want 3", len(visited))
	}
}

func TestTable_ForEach_EarlyExit(t *testing.T) {
	table := NewTable(10)

	for i := uint16(1); i <= 10; i++ {
		ctx := createTestSecureContext(i)
		table.Add(ctx)
	}

	count := 0
	table.ForEach(func(ctx *SecureContext) bool {
		count++
		return count < 3 // Stop after 3
	})

	if count != 3 {
		t.Errorf("ForEach count = %d, want 3", count)
	}
}

func TestTable_IsFull(t *testing.T) {
	table := NewTable(2)

	if table.IsFull() {
		t.Error("Empty table should not be full")
	}

	table.Add(createTestSecureContext(1))
	if table.IsFull() {
		t.Error("Table with 1/2 sessions should not be full")
	}

	table.Add(createTestSecureContext(2))
	if !table.IsFull() {
		t.Error("Table with 2/2 sessions should be full")
	}
}

// Helper functions

func createTestSecureContext(localSessionID uint16) *SecureContext {
	ctx, _ := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypePASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: localSessionID,
		PeerSessionID:  localSessionID + 1000,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
	})
	return ctx
}

func createTestSecureContextWithPeer(localSessionID uint16, fabricIndex fabric.FabricIndex, peerNodeID fabric.NodeID) *SecureContext {
	ctx, _ := NewSecureContext(SecureContextConfig{
		SessionType:    SessionTypeCASE,
		Role:           SessionRoleInitiator,
		LocalSessionID: localSessionID,
		PeerSessionID:  localSessionID + 1000,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
		FabricIndex:    fabricIndex,
		PeerNodeID:     peerNodeID,
	})
	return ctx
}
