package exchange

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestAckTableAddAndGet(t *testing.T) {
	table := NewAckTable()

	key := exchangeKey{
		localSessionID: 1,
		exchangeID:     100,
		role:           ExchangeRoleResponder,
	}

	// Add entry
	displaced := table.Add(key, 12345, nil)
	if displaced != nil {
		t.Error("should not displace on first add")
	}

	// Get entry
	entry, ok := table.Get(key)
	if !ok {
		t.Fatal("entry should exist")
	}
	if entry.MessageCounter != 12345 {
		t.Errorf("counter = %d, want 12345", entry.MessageCounter)
	}
	if entry.StandaloneAckSent {
		t.Error("StandaloneAckSent should be false initially")
	}
}

func TestAckTableDisplacement(t *testing.T) {
	table := NewAckTable()

	key := exchangeKey{
		localSessionID: 1,
		exchangeID:     100,
		role:           ExchangeRoleResponder,
	}

	// Add first entry
	table.Add(key, 100, nil)

	// Add second entry - should displace first
	displaced := table.Add(key, 200, nil)
	if displaced == nil {
		t.Fatal("should return displaced entry")
	}
	if displaced.MessageCounter != 100 {
		t.Errorf("displaced counter = %d, want 100", displaced.MessageCounter)
	}

	// Current entry should be the new one
	entry, _ := table.Get(key)
	if entry.MessageCounter != 200 {
		t.Errorf("current counter = %d, want 200", entry.MessageCounter)
	}
}

func TestAckTableDisplacementAfterStandaloneAck(t *testing.T) {
	table := NewAckTable()

	key := exchangeKey{
		localSessionID: 1,
		exchangeID:     100,
		role:           ExchangeRoleResponder,
	}

	// Add entry and mark standalone ACK sent
	table.Add(key, 100, nil)
	table.MarkStandaloneAckSent(key)

	// Add second entry - should NOT return displaced (standalone already sent)
	displaced := table.Add(key, 200, nil)
	if displaced != nil {
		t.Error("should not return entry when StandaloneAckSent=true")
	}
}

func TestAckTableMarkAcked(t *testing.T) {
	table := NewAckTable()

	key := exchangeKey{
		localSessionID: 1,
		exchangeID:     100,
		role:           ExchangeRoleResponder,
	}

	table.Add(key, 12345, nil)

	// Mark as acked (piggybacked)
	counter := table.MarkAcked(key)
	if counter != 12345 {
		t.Errorf("acked counter = %d, want 12345", counter)
	}

	// Entry should be removed
	_, ok := table.Get(key)
	if ok {
		t.Error("entry should be removed after MarkAcked")
	}
}

func TestAckTableRemove(t *testing.T) {
	table := NewAckTable()

	key := exchangeKey{
		localSessionID: 1,
		exchangeID:     100,
		role:           ExchangeRoleResponder,
	}

	table.Add(key, 12345, nil)

	// Remove
	table.Remove(key)

	// Should be gone
	_, ok := table.Get(key)
	if ok {
		t.Error("entry should be removed")
	}
}

func TestAckTableTimeout(t *testing.T) {
	table := NewAckTable()

	key := exchangeKey{
		localSessionID: 1,
		exchangeID:     100,
		role:           ExchangeRoleResponder,
	}

	var called atomic.Int32
	table.Add(key, 12345, func() {
		called.Add(1)
	})

	// Wait for timeout (200ms + buffer)
	time.Sleep(250 * time.Millisecond)

	if called.Load() != 1 {
		t.Errorf("callback called %d times, want 1", called.Load())
	}

	// Entry should still exist but with StandaloneAckSent=true
	entry, ok := table.Get(key)
	if !ok {
		t.Fatal("entry should still exist after timeout")
	}
	if !entry.StandaloneAckSent {
		t.Error("StandaloneAckSent should be true after timeout")
	}
}

func TestAckTableHasPendingAck(t *testing.T) {
	table := NewAckTable()

	key := exchangeKey{
		localSessionID: 1,
		exchangeID:     100,
		role:           ExchangeRoleResponder,
	}

	// No entry
	if table.HasPendingAck(key) {
		t.Error("should not have pending ACK initially")
	}

	// Add entry
	table.Add(key, 12345, nil)
	if !table.HasPendingAck(key) {
		t.Error("should have pending ACK after add")
	}

	// Mark standalone sent
	table.MarkStandaloneAckSent(key)
	if table.HasPendingAck(key) {
		t.Error("should not have pending ACK after standalone sent")
	}
}

func TestAckTableCount(t *testing.T) {
	table := NewAckTable()

	if table.Count() != 0 {
		t.Errorf("initial count = %d, want 0", table.Count())
	}

	key1 := exchangeKey{localSessionID: 1, exchangeID: 100, role: ExchangeRoleResponder}
	key2 := exchangeKey{localSessionID: 1, exchangeID: 200, role: ExchangeRoleResponder}

	table.Add(key1, 1, nil)
	if table.Count() != 1 {
		t.Errorf("count = %d, want 1", table.Count())
	}

	table.Add(key2, 2, nil)
	if table.Count() != 2 {
		t.Errorf("count = %d, want 2", table.Count())
	}

	table.Remove(key1)
	if table.Count() != 1 {
		t.Errorf("count = %d, want 1", table.Count())
	}
}

func TestAckTableClear(t *testing.T) {
	table := NewAckTable()

	key1 := exchangeKey{localSessionID: 1, exchangeID: 100, role: ExchangeRoleResponder}
	key2 := exchangeKey{localSessionID: 1, exchangeID: 200, role: ExchangeRoleResponder}

	table.Add(key1, 1, nil)
	table.Add(key2, 2, nil)

	table.Clear()

	if table.Count() != 0 {
		t.Errorf("count after clear = %d, want 0", table.Count())
	}
}
