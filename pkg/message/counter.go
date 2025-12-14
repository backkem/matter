package message

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
)

// MessageCounter manages outgoing message counter values.
// It is safe for concurrent use.
type MessageCounter struct {
	value uint32
	mu    sync.Mutex
}

// NewMessageCounter creates a new message counter initialized with a random value.
// Per Spec 4.6.1.1, counters are initialized to random values in [1, 2^28].
func NewMessageCounter() *MessageCounter {
	return &MessageCounter{
		value: randomCounterInit(),
	}
}

// NewMessageCounterWithValue creates a counter with a specific initial value.
// Used for testing or restoring persisted counters.
func NewMessageCounterWithValue(initial uint32) *MessageCounter {
	return &MessageCounter{
		value: initial,
	}
}

// Next returns the next counter value and increments the internal counter.
// Returns an error if the counter would overflow for session counters.
func (c *MessageCounter) Next() (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	current := c.value
	c.value++

	// Note: Overflow detection is caller's responsibility for session counters.
	// Group counters are allowed to roll over per spec.

	return current, nil
}

// Current returns the current counter value without incrementing.
func (c *MessageCounter) Current() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.value
}

// randomCounterInit generates a random initial counter value.
// Per spec: Crypto_DRBG(len = 28) + 1, giving range [1, 2^28].
func randomCounterInit() uint32 {
	var buf [4]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		// Fallback to 1 if random fails (should never happen)
		return 1
	}

	// Mask to 28 bits and add 1
	value := binary.LittleEndian.Uint32(buf[:])
	value = (value & (CounterInitMax - 1)) + 1

	return value
}

// ReceptionState implements the sliding window bitmap for replay detection.
// This tracks received message counters to detect duplicates.
// See Spec Section 4.6.5.1 for the algorithm.
type ReceptionState struct {
	maxCounter  uint32 // Largest valid counter received
	bitmap      uint32 // Bitmap for window [maxCounter-32, maxCounter-1]
	initialized bool   // Whether any counter has been received
	mu          sync.Mutex
}

// NewReceptionState creates a new reception state with a known max counter.
// The bitmap is initialized to all 1s, meaning only counters > initialMax are accepted.
// This is used when synchronizing with a peer where we know their current counter.
func NewReceptionState(initialMax uint32) *ReceptionState {
	return &ReceptionState{
		maxCounter:  initialMax,
		bitmap:      0xFFFFFFFF, // All bits set = all positions marked as received
		initialized: true,
	}
}

// NewReceptionStateEmpty creates a reception state that will accept any first message.
// The first counter received will initialize the state.
func NewReceptionStateEmpty() *ReceptionState {
	return &ReceptionState{
		maxCounter:  0,
		bitmap:      0,
		initialized: false,
	}
}

// CheckAndAccept checks if a counter is valid (not a replay) and accepts it.
// This is the combined check-and-update operation for encrypted messages.
// Returns true if the message should be processed, false if it's a duplicate.
// See Spec Section 4.6.5.2.1 for unicast and 4.6.5.2.2 for group sessions.
func (r *ReceptionState) CheckAndAccept(counter uint32, allowRollover bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if allowRollover {
		return r.checkAndAcceptWithRollover(counter)
	}
	return r.checkAndAcceptNoRollover(counter)
}

// checkAndAcceptNoRollover handles unicast session counters (no rollover).
// Per Spec 4.6.5.2.1: counters in [maxCounter+1, 2^32-1] are new.
func (r *ReceptionState) checkAndAcceptNoRollover(counter uint32) bool {
	// Handle first message on uninitialized state
	if !r.initialized {
		r.maxCounter = counter
		r.bitmap = 0
		r.initialized = true
		return true
	}

	// Counter ahead of window - definitely new
	if counter > r.maxCounter {
		r.advanceWindow(counter)
		return true
	}

	// Counter equal to max - duplicate
	if counter == r.maxCounter {
		return false
	}

	// Counter within window range?
	windowStart := r.maxCounter - CounterWindowSize
	if r.maxCounter < CounterWindowSize {
		// Window doesn't extend below 0
		windowStart = 0
	}

	if counter >= windowStart {
		// Check bitmap
		offset := r.maxCounter - counter - 1
		if offset < CounterWindowSize {
			mask := uint32(1) << offset
			if r.bitmap&mask != 0 {
				// Already received
				return false
			}
			// Mark as received
			r.bitmap |= mask
			return true
		}
	}

	// Counter is behind window - duplicate
	return false
}

// checkAndAcceptWithRollover handles group session counters (allows rollover).
// Per Spec 4.6.5.2.2: counters are compared with 31-bit signed arithmetic.
func (r *ReceptionState) checkAndAcceptWithRollover(counter uint32) bool {
	// Handle first message on uninitialized state
	if !r.initialized {
		r.maxCounter = counter
		r.bitmap = 0
		r.initialized = true
		return true
	}

	// Use signed 32-bit comparison to handle rollover
	// A counter is "ahead" if (counter - maxCounter) < 2^31 (positive in signed)
	diff := int32(counter - r.maxCounter)

	// Counter is ahead of max (new message)
	if diff > 0 {
		r.advanceWindow(counter)
		return true
	}

	// Counter equals max - duplicate
	if diff == 0 {
		return false
	}

	// Counter is behind max - check if in window
	// diff is negative here, so -diff gives distance behind
	behind := uint32(-diff)

	if behind <= CounterWindowSize {
		offset := behind - 1
		mask := uint32(1) << offset
		if r.bitmap&mask != 0 {
			// Already received
			return false
		}
		// Mark as received
		r.bitmap |= mask
		return true
	}

	// Counter is too far behind - duplicate
	return false
}

// advanceWindow updates maxCounter and shifts the bitmap.
// This function is called only when the caller has already determined the counter
// is ahead (using appropriate rollover-aware or non-rollover arithmetic).
func (r *ReceptionState) advanceWindow(newMax uint32) {
	// Note: We don't check newMax > maxCounter here because this function
	// is used in both rollover and non-rollover contexts. The caller has
	// already verified the counter is "ahead" using the appropriate comparison.

	shift := newMax - r.maxCounter
	if shift > CounterWindowSize {
		// New counter is far ahead (jumped beyond window), reset bitmap
		r.bitmap = 0
	} else {
		// Shift bitmap left and mark the old max position as received.
		// Note: When shift == CounterWindowSize, the left shift clears all bits,
		// then we set bit (shift-1) to mark the old max.
		r.bitmap = (r.bitmap << shift) | (1 << (shift - 1))
	}

	r.maxCounter = newMax
}

// MaxCounter returns the current maximum counter value.
func (r *ReceptionState) MaxCounter() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.maxCounter
}

// CheckUnencrypted checks an unencrypted message counter.
// Per Spec 4.6.5.3, unencrypted messages use more relaxed duplicate detection.
// Messages behind the window are accepted (may be from a rebooted node).
// Unencrypted messages use rollover-aware (signed 32-bit) comparison.
func (r *ReceptionState) CheckUnencrypted(counter uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Handle first message on uninitialized state
	if !r.initialized {
		r.maxCounter = counter
		r.bitmap = 0
		r.initialized = true
		return true
	}

	// Use signed 32-bit comparison to handle rollover
	diff := int32(counter - r.maxCounter)

	// Counter equal to max = duplicate
	if diff == 0 {
		return false
	}

	// Counter is ahead of max (new message)
	if diff > 0 {
		r.advanceWindow(counter)
		return true
	}

	// Counter is behind max - check if in window
	// diff is negative here, so -diff gives distance behind
	behind := uint32(-diff)

	if behind <= CounterWindowSize {
		offset := behind - 1
		mask := uint32(1) << offset
		if r.bitmap&mask != 0 {
			// Already received - reject duplicate
			return false
		}
		// Accept and mark as received
		r.bitmap |= mask
		return true
	}

	// Counter is behind window - for unencrypted, we accept these
	// (may be from a rebooted node with reset counter)
	return true
}

// GlobalCounter represents a global message counter that persists across sessions.
// Used for unencrypted messages and group messages.
type GlobalCounter struct {
	*MessageCounter
}

// NewGlobalCounter creates a new global counter.
func NewGlobalCounter() *GlobalCounter {
	return &GlobalCounter{
		MessageCounter: NewMessageCounter(),
	}
}

// SessionCounter represents a per-session message counter.
// It tracks whether the counter has overflowed (which invalidates the session).
type SessionCounter struct {
	*MessageCounter
	exhausted bool
}

// NewSessionCounter creates a new session counter.
func NewSessionCounter() *SessionCounter {
	return &SessionCounter{
		MessageCounter: NewMessageCounter(),
		exhausted:      false,
	}
}

// NewSessionCounterWithValue creates a session counter with a specific initial value.
// Used for testing or restoring persisted counters.
func NewSessionCounterWithValue(initial uint32) *SessionCounter {
	return &SessionCounter{
		MessageCounter: NewMessageCounterWithValue(initial),
		exhausted:      false,
	}
}

// Next returns the next counter value.
// Returns ErrCounterExhausted if the counter has wrapped (session must be re-established).
func (c *SessionCounter) Next() (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.exhausted {
		return 0, ErrCounterExhausted
	}

	current := c.value
	c.value++

	// Check for wrap-around
	if c.value == 0 {
		c.exhausted = true
	}

	return current, nil
}

// IsExhausted returns true if the counter has wrapped.
func (c *SessionCounter) IsExhausted() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exhausted
}
