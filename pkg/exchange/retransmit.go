package exchange

import (
	"sync"
	"time"

	"github.com/backkem/matter/pkg/transport"
)

// RetransmitEntry represents a reliable message awaiting acknowledgement.
// Per Spec Section 4.12.6.1, each entry tracks:
//   - Reference to Exchange Context
//   - Message Counter
//   - Fully formed, encoded, encrypted message buffer
//   - Send count
//   - Retransmission timeout
//
// There can be only one pending retransmit per exchange (flow control).
type RetransmitEntry struct {
	// ExchangeKey identifies the exchange this message belongs to.
	ExchangeKey exchangeKey

	// MessageCounter is the counter of the sent message.
	MessageCounter uint32

	// Message is the fully encoded message buffer ready for retransmission.
	Message []byte

	// PeerAddress is the destination for retransmission.
	PeerAddress transport.PeerAddress

	// SendCount is the number of times this message has been sent.
	// Starts at 1 for initial transmission, incremented on each retry.
	SendCount int

	// Timer for retransmission timeout.
	timer *time.Timer

	// callback is invoked when retransmission timer expires.
	callback func()
}

// Stop cancels the retransmission timer if running.
func (e *RetransmitEntry) Stop() {
	if e.timer != nil {
		e.timer.Stop()
		e.timer = nil
	}
}

// RetransmitTable manages pending retransmissions for reliable messages.
// Per Spec 4.12.6.1, maintains entries until acknowledged or max retries.
//
// Thread-safe for concurrent access.
type RetransmitTable struct {
	// entries maps message counter to pending retransmit entry.
	// Also indexed by exchange key for lookup.
	entries map[uint32]*RetransmitEntry

	// byExchange maps exchange key to entry for quick lookup.
	byExchange map[exchangeKey]*RetransmitEntry

	// backoff calculates retransmission timeouts.
	backoff *BackoffCalculator

	mu sync.Mutex
}

// NewRetransmitTable creates a new retransmission table.
func NewRetransmitTable() *RetransmitTable {
	return &RetransmitTable{
		entries:    make(map[uint32]*RetransmitEntry),
		byExchange: make(map[exchangeKey]*RetransmitEntry),
		backoff:    NewBackoffCalculator(nil),
	}
}

// Add adds a message to the retransmission table.
// Called when sending a reliable message (R flag set).
//
// Parameters:
//   - key: Exchange identifier
//   - messageCounter: Counter of the sent message
//   - message: Fully encoded message buffer
//   - peerAddress: Destination address
//   - baseInterval: Session's idle/active interval for backoff
//   - onTimeout: Callback when retransmit timer expires
//
// Returns error if exchange already has a pending retransmit.
func (t *RetransmitTable) Add(
	key exchangeKey,
	messageCounter uint32,
	message []byte,
	peerAddress transport.PeerAddress,
	baseInterval time.Duration,
	onTimeout func(entry *RetransmitEntry),
) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check for existing entry on this exchange
	if _, exists := t.byExchange[key]; exists {
		return ErrPendingRetransmit
	}

	// Create entry
	entry := &RetransmitEntry{
		ExchangeKey:    key,
		MessageCounter: messageCounter,
		Message:        message,
		PeerAddress:    peerAddress,
		SendCount:      1, // Initial transmission
	}

	// Calculate initial backoff
	backoffTime := t.backoff.Calculate(baseInterval, 0)

	// Start timer
	entry.timer = time.AfterFunc(backoffTime, func() {
		if onTimeout != nil {
			onTimeout(entry)
		}
	})
	entry.callback = func() {
		if onTimeout != nil {
			onTimeout(entry)
		}
	}

	t.entries[messageCounter] = entry
	t.byExchange[key] = entry

	return nil
}

// Ack removes an entry when acknowledgement received.
// Returns the entry if found, nil otherwise.
func (t *RetransmitTable) Ack(messageCounter uint32) *RetransmitEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.entries[messageCounter]
	if !ok {
		return nil
	}

	entry.Stop()
	delete(t.entries, messageCounter)
	delete(t.byExchange, entry.ExchangeKey)

	return entry
}

// ScheduleRetransmit updates the entry for retransmission.
// Called from timeout callback to schedule next retry.
//
// Returns:
//   - true if retransmit scheduled successfully
//   - false if max retransmissions exceeded (entry removed)
func (t *RetransmitTable) ScheduleRetransmit(
	messageCounter uint32,
	baseInterval time.Duration,
) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.entries[messageCounter]
	if !ok {
		return false
	}

	entry.SendCount++

	// Check max retransmissions
	if entry.SendCount >= MRPMaxTransmissions {
		// Max retries exceeded - remove entry
		entry.Stop()
		delete(t.entries, messageCounter)
		delete(t.byExchange, entry.ExchangeKey)
		return false
	}

	// Calculate backoff for this attempt
	backoffTime := t.backoff.Calculate(baseInterval, entry.SendCount-1)

	// Restart timer
	entry.Stop()
	entry.timer = time.AfterFunc(backoffTime, entry.callback)

	return true
}

// GetByCounter returns the entry for a message counter.
func (t *RetransmitTable) GetByCounter(messageCounter uint32) (*RetransmitEntry, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.entries[messageCounter]
	return entry, ok
}

// GetByExchange returns the pending entry for an exchange.
func (t *RetransmitTable) GetByExchange(key exchangeKey) (*RetransmitEntry, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.byExchange[key]
	return entry, ok
}

// HasPending returns true if the exchange has a pending retransmit.
func (t *RetransmitTable) HasPending(key exchangeKey) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	_, ok := t.byExchange[key]
	return ok
}

// Remove removes the entry for an exchange.
// Called when exchange closes.
func (t *RetransmitTable) Remove(key exchangeKey) {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.byExchange[key]
	if !ok {
		return
	}

	entry.Stop()
	delete(t.entries, entry.MessageCounter)
	delete(t.byExchange, key)
}

// RemoveByCounter removes an entry by message counter.
func (t *RetransmitTable) RemoveByCounter(messageCounter uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.entries[messageCounter]
	if !ok {
		return
	}

	entry.Stop()
	delete(t.entries, messageCounter)
	delete(t.byExchange, entry.ExchangeKey)
}

// Count returns the number of pending retransmit entries.
func (t *RetransmitTable) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// Clear removes all entries. Used for shutdown.
func (t *RetransmitTable) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	for counter, entry := range t.entries {
		entry.Stop()
		delete(t.entries, counter)
	}
	t.byExchange = make(map[exchangeKey]*RetransmitEntry)
}

// ForEach iterates over all entries.
// The callback should not modify the table.
func (t *RetransmitTable) ForEach(fn func(entry *RetransmitEntry)) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, entry := range t.entries {
		fn(entry)
	}
}
