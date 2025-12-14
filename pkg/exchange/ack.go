package exchange

import (
	"sync"
	"time"
)

// AckEntry represents a pending acknowledgement for a received reliable message.
// Per Spec Section 4.12.6.2, each entry tracks:
//   - Reference to Exchange Context (via exchange key)
//   - Message Counter to acknowledge
//   - StandaloneAckSent flag
//
// There can be only one pending acknowledgement per exchange.
type AckEntry struct {
	// MessageCounter is the counter of the message to acknowledge.
	MessageCounter uint32

	// StandaloneAckSent indicates whether a standalone ACK has been sent.
	// Initially false. Set to true when standalone ACK sent.
	// Per Spec 4.12.5.2.2, if true, the entry remains until:
	//   - Exchange closes, or
	//   - A non-standalone message piggybacks the ACK
	StandaloneAckSent bool

	// Timer for standalone ACK timeout.
	// Fires after MRP_STANDALONE_ACK_TIMEOUT if no piggyback opportunity.
	timer *time.Timer

	// callback is invoked when the timer expires.
	callback func()
}

// Stop cancels the pending ACK timer if running.
func (e *AckEntry) Stop() {
	if e.timer != nil {
		e.timer.Stop()
		e.timer = nil
	}
}

// AckTable manages pending acknowledgements for reliable messages.
// Per Spec 4.12.6.2, maintains one entry per exchange needing ACK.
//
// Thread-safe for concurrent access.
type AckTable struct {
	// entries maps exchange key to pending ACK entry.
	// Only one pending ACK per exchange.
	entries map[exchangeKey]*AckEntry

	mu sync.Mutex
}

// exchangeKey uniquely identifies an exchange for table lookups.
// Matches the spec's {Session Context, Exchange ID, Exchange Role} tuple.
type exchangeKey struct {
	localSessionID uint16
	exchangeID     uint16
	role           ExchangeRole
}

// NewAckTable creates a new acknowledgement table.
func NewAckTable() *AckTable {
	return &AckTable{
		entries: make(map[exchangeKey]*AckEntry),
	}
}

// Add adds or replaces a pending acknowledgement for an exchange.
//
// Per Spec 4.12.5.2.2: If a pending ACK already exists with StandaloneAckSent=false,
// a standalone ACK SHALL be sent immediately for the old entry before replacing.
//
// Parameters:
//   - key: Exchange identifier
//   - messageCounter: Counter of the reliable message to acknowledge
//   - onTimeout: Callback invoked when standalone ACK timeout expires
//
// Returns the previous entry if one existed with StandaloneAckSent=false
// (caller should send immediate standalone ACK for it).
func (t *AckTable) Add(key exchangeKey, messageCounter uint32, onTimeout func()) *AckEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	var displaced *AckEntry

	// Check for existing entry
	if existing, ok := t.entries[key]; ok {
		existing.Stop()
		if !existing.StandaloneAckSent {
			// Caller must send immediate standalone ACK for displaced entry
			displaced = existing
		}
	}

	// Create new entry
	entry := &AckEntry{
		MessageCounter:    messageCounter,
		StandaloneAckSent: false,
		callback:          onTimeout,
	}

	// Start timer
	entry.timer = time.AfterFunc(MRPStandaloneAckTimeout, func() {
		t.mu.Lock()
		// Verify entry still exists and hasn't been superseded
		current, ok := t.entries[key]
		if ok && current == entry && !current.StandaloneAckSent {
			current.StandaloneAckSent = true
		}
		t.mu.Unlock()

		// Invoke callback outside lock
		if entry.callback != nil {
			entry.callback()
		}
	})

	t.entries[key] = entry

	return displaced
}

// Get returns the pending ACK entry for an exchange, if any.
func (t *AckTable) Get(key exchangeKey) (*AckEntry, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.entries[key]
	return entry, ok
}

// MarkAcked marks that a piggybacked ACK was sent (not standalone).
// Per Spec 4.12.5.1.1: Remove entry when piggybacked on non-standalone message.
//
// Returns the message counter that was acknowledged, or 0 if no entry.
func (t *AckTable) MarkAcked(key exchangeKey) uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.entries[key]
	if !ok {
		return 0
	}

	counter := entry.MessageCounter
	entry.Stop()
	delete(t.entries, key)

	return counter
}

// MarkStandaloneAckSent marks that a standalone ACK was sent.
// Per Spec 4.12.5.2.2: Entry remains with StandaloneAckSent=true.
// It will be removed when exchange closes or piggybacked ACK sent.
func (t *AckTable) MarkStandaloneAckSent(key exchangeKey) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if entry, ok := t.entries[key]; ok {
		entry.Stop()
		entry.StandaloneAckSent = true
	}
}

// Remove removes the ACK entry for an exchange.
// Called when exchange closes.
func (t *AckTable) Remove(key exchangeKey) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if entry, ok := t.entries[key]; ok {
		entry.Stop()
		delete(t.entries, key)
	}
}

// HasPendingAck returns true if there's a pending ACK for the exchange
// that hasn't had a standalone ACK sent yet.
func (t *AckTable) HasPendingAck(key exchangeKey) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.entries[key]
	return ok && !entry.StandaloneAckSent
}

// PendingCounter returns the message counter awaiting ACK, if any.
// Returns (counter, true) if pending, (0, false) otherwise.
func (t *AckTable) PendingCounter(key exchangeKey) (uint32, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.entries[key]
	if !ok {
		return 0, false
	}
	return entry.MessageCounter, true
}

// Count returns the number of pending ACK entries.
func (t *AckTable) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// Clear removes all entries. Used for shutdown.
func (t *AckTable) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	for key, entry := range t.entries {
		entry.Stop()
		delete(t.entries, key)
	}
}
