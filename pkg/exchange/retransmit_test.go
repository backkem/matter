package exchange

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/backkem/matter/pkg/transport"
)

func makeTestPeerAddress() transport.PeerAddress {
	return transport.PeerAddress{
		TransportType: transport.TransportTypeUDP,
		Addr:          &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5540},
	}
}

func TestRetransmitTableAddAndGet(t *testing.T) {
	table := NewRetransmitTable()

	key := exchangeKey{
		localSessionID: 1,
		exchangeID:     100,
		role:           ExchangeRoleInitiator,
	}

	message := []byte("test message")
	peerAddr := makeTestPeerAddress()
	baseInterval := 300 * time.Millisecond

	err := table.Add(key, 12345, message, peerAddr, baseInterval, nil)
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Get by counter
	entry, ok := table.GetByCounter(12345)
	if !ok {
		t.Fatal("entry should exist by counter")
	}
	if entry.MessageCounter != 12345 {
		t.Errorf("counter = %d, want 12345", entry.MessageCounter)
	}
	if entry.SendCount != 1 {
		t.Errorf("send count = %d, want 1", entry.SendCount)
	}

	// Get by exchange
	entry2, ok := table.GetByExchange(key)
	if !ok {
		t.Fatal("entry should exist by exchange")
	}
	if entry2 != entry {
		t.Error("should be same entry")
	}
}

func TestRetransmitTableDuplicateAdd(t *testing.T) {
	table := NewRetransmitTable()

	key := exchangeKey{
		localSessionID: 1,
		exchangeID:     100,
		role:           ExchangeRoleInitiator,
	}

	peerAddr := makeTestPeerAddress()
	baseInterval := 300 * time.Millisecond

	// First add succeeds
	err := table.Add(key, 100, []byte("msg1"), peerAddr, baseInterval, nil)
	if err != nil {
		t.Fatalf("first Add failed: %v", err)
	}

	// Second add on same exchange fails (flow control)
	err = table.Add(key, 200, []byte("msg2"), peerAddr, baseInterval, nil)
	if err != ErrPendingRetransmit {
		t.Errorf("second Add error = %v, want ErrPendingRetransmit", err)
	}
}

func TestRetransmitTableAck(t *testing.T) {
	table := NewRetransmitTable()

	key := exchangeKey{
		localSessionID: 1,
		exchangeID:     100,
		role:           ExchangeRoleInitiator,
	}

	peerAddr := makeTestPeerAddress()
	baseInterval := 300 * time.Millisecond

	table.Add(key, 12345, []byte("test"), peerAddr, baseInterval, nil)

	// Acknowledge
	entry := table.Ack(12345)
	if entry == nil {
		t.Fatal("Ack should return entry")
	}
	if entry.MessageCounter != 12345 {
		t.Errorf("acked counter = %d, want 12345", entry.MessageCounter)
	}

	// Entry should be removed
	_, ok := table.GetByCounter(12345)
	if ok {
		t.Error("entry should be removed after Ack")
	}

	_, ok = table.GetByExchange(key)
	if ok {
		t.Error("entry should be removed from exchange index")
	}
}

func TestRetransmitTableTimeout(t *testing.T) {
	table := NewRetransmitTable()

	key := exchangeKey{
		localSessionID: 1,
		exchangeID:     100,
		role:           ExchangeRoleInitiator,
	}

	peerAddr := makeTestPeerAddress()
	baseInterval := 100 * time.Millisecond // Short for test

	var called atomic.Int32
	var calledEntry *RetransmitEntry

	table.Add(key, 12345, []byte("test"), peerAddr, baseInterval, func(entry *RetransmitEntry) {
		called.Add(1)
		calledEntry = entry
	})

	// Wait for timeout (100ms * 1.1 * 1.25 = ~138ms max, use 200ms buffer)
	time.Sleep(200 * time.Millisecond)

	if called.Load() != 1 {
		t.Errorf("callback called %d times, want 1", called.Load())
	}
	if calledEntry == nil {
		t.Fatal("callback should receive entry")
	}
	if calledEntry.MessageCounter != 12345 {
		t.Errorf("callback entry counter = %d, want 12345", calledEntry.MessageCounter)
	}
}

func TestRetransmitTableScheduleRetransmit(t *testing.T) {
	table := NewRetransmitTable()

	key := exchangeKey{
		localSessionID: 1,
		exchangeID:     100,
		role:           ExchangeRoleInitiator,
	}

	peerAddr := makeTestPeerAddress()
	baseInterval := 300 * time.Millisecond

	table.Add(key, 12345, []byte("test"), peerAddr, baseInterval, nil)

	// Schedule retransmit (simulating timeout)
	ok := table.ScheduleRetransmit(12345, baseInterval)
	if !ok {
		t.Error("first retransmit should succeed")
	}

	entry, _ := table.GetByCounter(12345)
	if entry.SendCount != 2 {
		t.Errorf("send count = %d, want 2", entry.SendCount)
	}

	// Continue until max
	for i := 2; i < MRPMaxTransmissions-1; i++ {
		ok = table.ScheduleRetransmit(12345, baseInterval)
		if !ok {
			t.Errorf("retransmit %d should succeed", i)
		}
	}

	entry, _ = table.GetByCounter(12345)
	if entry.SendCount != MRPMaxTransmissions-1 {
		t.Errorf("send count = %d, want %d", entry.SendCount, MRPMaxTransmissions-1)
	}

	// Next one should fail (max reached)
	ok = table.ScheduleRetransmit(12345, baseInterval)
	if ok {
		t.Error("should fail at max retransmissions")
	}

	// Entry should be removed
	_, exists := table.GetByCounter(12345)
	if exists {
		t.Error("entry should be removed after max retransmissions")
	}
}

func TestRetransmitTableHasPending(t *testing.T) {
	table := NewRetransmitTable()

	key := exchangeKey{
		localSessionID: 1,
		exchangeID:     100,
		role:           ExchangeRoleInitiator,
	}

	if table.HasPending(key) {
		t.Error("should not have pending initially")
	}

	peerAddr := makeTestPeerAddress()
	table.Add(key, 12345, []byte("test"), peerAddr, 300*time.Millisecond, nil)

	if !table.HasPending(key) {
		t.Error("should have pending after add")
	}

	table.Ack(12345)

	if table.HasPending(key) {
		t.Error("should not have pending after ack")
	}
}

func TestRetransmitTableRemove(t *testing.T) {
	table := NewRetransmitTable()

	key := exchangeKey{
		localSessionID: 1,
		exchangeID:     100,
		role:           ExchangeRoleInitiator,
	}

	peerAddr := makeTestPeerAddress()
	table.Add(key, 12345, []byte("test"), peerAddr, 300*time.Millisecond, nil)

	table.Remove(key)

	if table.HasPending(key) {
		t.Error("should not have pending after remove")
	}

	_, ok := table.GetByCounter(12345)
	if ok {
		t.Error("entry should be removed by counter")
	}
}

func TestRetransmitTableCount(t *testing.T) {
	table := NewRetransmitTable()

	if table.Count() != 0 {
		t.Errorf("initial count = %d, want 0", table.Count())
	}

	peerAddr := makeTestPeerAddress()
	baseInterval := 300 * time.Millisecond

	key1 := exchangeKey{localSessionID: 1, exchangeID: 100, role: ExchangeRoleInitiator}
	key2 := exchangeKey{localSessionID: 1, exchangeID: 200, role: ExchangeRoleInitiator}

	table.Add(key1, 1, []byte("msg1"), peerAddr, baseInterval, nil)
	if table.Count() != 1 {
		t.Errorf("count = %d, want 1", table.Count())
	}

	table.Add(key2, 2, []byte("msg2"), peerAddr, baseInterval, nil)
	if table.Count() != 2 {
		t.Errorf("count = %d, want 2", table.Count())
	}

	table.Ack(1)
	if table.Count() != 1 {
		t.Errorf("count = %d, want 1", table.Count())
	}
}

func TestRetransmitTableClear(t *testing.T) {
	table := NewRetransmitTable()

	peerAddr := makeTestPeerAddress()
	baseInterval := 300 * time.Millisecond

	key1 := exchangeKey{localSessionID: 1, exchangeID: 100, role: ExchangeRoleInitiator}
	key2 := exchangeKey{localSessionID: 1, exchangeID: 200, role: ExchangeRoleInitiator}

	table.Add(key1, 1, []byte("msg1"), peerAddr, baseInterval, nil)
	table.Add(key2, 2, []byte("msg2"), peerAddr, baseInterval, nil)

	table.Clear()

	if table.Count() != 0 {
		t.Errorf("count after clear = %d, want 0", table.Count())
	}
}
