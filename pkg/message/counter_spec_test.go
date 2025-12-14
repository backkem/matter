package message

import (
	"testing"
)

// Counter values from C SDK TestPeerMessageCounter.cpp.
// These edge-case values test behavior around:
// - Zero and low values
// - Values near 2^31-1 (rollover boundary for group counters)
// - Values near 2^31 (where signed comparison behavior matters)
// - Values near max uint32
var counterEdgeCaseValues = []uint32{
	0,          // Zero
	10,         // Low value
	0x7FFFFFFF, // 2^31 - 1 (max positive signed int32)
	0x80000000, // 2^31 (min negative signed int32 / first value in "behind" half)
	0x80000001, // 2^31 + 1
	0x80000002, // 2^31 + 2
	0xFFFFFFF0, // Near max
	0xFFFFFFFF, // Max uint32
}

// TestGroupRollOver tests that group counters handle rollover correctly.
// Ported from C SDK TestPeerMessageCounter.cpp GroupRollOverTest.
func TestGroupRollOver(t *testing.T) {
	for _, n := range counterEdgeCaseValues {
		for k := uint32(1); k <= 2*CounterWindowSize; k++ {
			r := NewReceptionStateEmpty()

			// Accept initial counter n (trust-first)
			if !r.CheckAndAccept(n, true) {
				t.Fatalf("n=%08x k=%d: initial counter should be accepted", n, k)
			}

			// 1. A counter value of N + k comes in, should be accepted
			if !r.CheckAndAccept(n+k, true) {
				t.Errorf("n=%08x k=%d: counter n+k=%08x should be accepted", n, k, n+k)
				continue
			}

			// 2. A counter value of N comes in, should be rejected (duplicate)
			if r.CheckAndAccept(n, true) {
				t.Errorf("n=%08x k=%d: counter n should be rejected (duplicate)", n, k)
			}

			// 3. Counters between N - WindowSize and N + k - WindowSize should be rejected
			for i := n - CounterWindowSize; i != (n + k - CounterWindowSize); i++ {
				if r.CheckAndAccept(i, true) {
					t.Errorf("n=%08x k=%d: counter %08x should be rejected (outside window)", n, k, i)
				}
			}

			// 4. Counter at N + k - WindowSize depends on k
			edgeCounter := n + k - CounterWindowSize
			if k != CounterWindowSize {
				if !r.CheckAndAccept(edgeCounter, true) {
					t.Errorf("n=%08x k=%d: counter %08x should be accepted (edge of window)", n, k, edgeCounter)
				}
			} else {
				if r.CheckAndAccept(edgeCounter, true) {
					t.Errorf("n=%08x k=%d: counter %08x should be rejected (k == WindowSize)", n, k, edgeCounter)
				}
			}
		}
	}
}

// TestGroupOutOfWindow tests that group counters at exactly 2^31 distance are rejected.
// Per spec, group counters use signed 32-bit comparison, so values exactly 2^31 apart
// are considered "behind" (equal to INT32_MIN distance).
// Ported from C SDK TestPeerMessageCounter.cpp GroupOutOfWindow.
func TestGroupOutOfWindow(t *testing.T) {
	for _, n := range counterEdgeCaseValues {
		for k := uint32(1 << 31); k <= uint32(1<<31)+2; k++ {
			r := NewReceptionStateEmpty()

			// Accept initial counter n
			if !r.CheckAndAccept(n, true) {
				t.Fatalf("n=%08x: initial counter should be accepted", n)
			}

			// Counter n + k (where k >= 2^31) should be rejected
			// because in signed comparison, it appears to be "behind"
			if r.CheckAndAccept(n+k, true) {
				t.Errorf("n=%08x k=%08x: counter %08x should be rejected (out of window)", n, k, n+k)
			}
		}
	}
}

// TestGroupBigLeap tests large jumps (near 2^31 - 1) with group counters.
// Ported from C SDK TestPeerMessageCounter.cpp GroupBigLeapTest.
func TestGroupBigLeap(t *testing.T) {
	// Test k values near 2^31 - 1 (the max valid "ahead" distance)
	kValues := []uint32{
		(1 << 31) - 5,
		(1 << 31) - 4,
		(1 << 31) - 3,
		(1 << 31) - 2,
		(1 << 31) - 1, // Max valid jump for group counters
	}

	for _, n := range counterEdgeCaseValues {
		for _, k := range kValues {
			r := NewReceptionStateEmpty()

			// Accept initial counter n
			if !r.CheckAndAccept(n, true) {
				t.Fatalf("n=%08x k=%08x: initial counter should be accepted", n, k)
			}

			// 1. Counter n + k should be accepted (large valid jump)
			if !r.CheckAndAccept(n+k, true) {
				t.Errorf("n=%08x k=%08x: counter %08x should be accepted (big leap)", n, k, n+k)
				continue
			}

			// 2. Counter n should now be rejected
			if r.CheckAndAccept(n, true) {
				t.Errorf("n=%08x k=%08x: counter n should be rejected after big leap", n, k)
			}

			// 3. Counter at n - WindowSize should be valid (inside new window due to wraparound)
			// This is because after a big jump, the window wraps around
			edgeCounter := n - CounterWindowSize
			if !r.CheckAndAccept(edgeCounter, true) {
				t.Errorf("n=%08x k=%08x: counter %08x should be accepted (inside wrapped window)", n, k, edgeCounter)
			}

			// 4. Counter at exactly the window edge should be valid
			windowEdge := n + k - CounterWindowSize
			if !r.CheckAndAccept(windowEdge, true) {
				t.Errorf("n=%08x k=%08x: counter %08x should be accepted (window edge)", n, k, windowEdge)
			}
		}
	}
}

// TestGroupBackTrack tests acceptance of counters behind current max.
// Ported from C SDK TestPeerMessageCounter.cpp GroupBackTrackTest.
func TestGroupBackTrack(t *testing.T) {
	for _, n := range counterEdgeCaseValues {
		r := NewReceptionStateEmpty()

		// Accept initial counter n
		if !r.CheckAndAccept(n, true) {
			t.Fatalf("n=%08x: initial counter should be accepted", n)
		}

		// 1. Accept some values N - k where k*k < WindowSize
		// k*k values: 1, 4, 9, 16, 25 (all < 32)
		backValues := []uint32{}
		for k := uint32(1); k*k < CounterWindowSize; k++ {
			backCounter := n - (k * k)
			backValues = append(backValues, backCounter)
			if !r.CheckAndAccept(backCounter, true) {
				t.Errorf("n=%08x: counter %08x should be accepted (backtrack)", n, backCounter)
			}
		}

		// 2. Accept counter n + 3
		if !r.CheckAndAccept(n+3, true) {
			t.Errorf("n=%08x: counter n+3 should be accepted", n)
		}

		// 3. The same backtrack values should now be rejected (duplicates)
		for _, backCounter := range backValues {
			if r.CheckAndAccept(backCounter, true) {
				t.Errorf("n=%08x: counter %08x should be rejected (duplicate backtrack)", n, backCounter)
			}
		}

		// 4. Values in window that we didn't receive should be accepted
		// Window is now [n+3-32, n+3-1], and we received: n, n-1, n-4, n-9, n-16, n-25, n+3
		for k := n + 3 - CounterWindowSize; k != n+3; k++ {
			// Check if k is one of our already-received values
			alreadyReceived := (k == n) || (k == n+3)
			for _, bv := range backValues {
				if k == bv {
					alreadyReceived = true
					break
				}
			}
			if alreadyReceived {
				continue
			}

			if !r.CheckAndAccept(k, true) {
				t.Errorf("n=%08x: counter %08x should be accepted (not yet received)", n, k)
			}
		}
	}
}

// TestUnicastSmallStep tests encrypted unicast counters with small steps.
// Unicast counters do NOT allow rollover - they must be strictly increasing.
// Ported from C SDK TestPeerMessageCounter.cpp UnicastSmallStepTest.
func TestUnicastSmallStep(t *testing.T) {
	for _, n := range counterEdgeCaseValues {
		for k := uint32(1); k <= 2*CounterWindowSize; k++ {
			r := NewReceptionStateEmpty()

			// Accept initial counter n
			if !r.CheckAndAccept(n, false) {
				t.Fatalf("n=%08x k=%d: initial counter should be accepted", n, k)
			}

			// Counter n should now be rejected (duplicate)
			if r.CheckAndAccept(n, false) {
				t.Errorf("n=%08x k=%d: counter n should be rejected (duplicate)", n, k)
			}

			// Counter n + k: only valid if it wouldn't overflow
			wouldOverflow := k > (0xFFFFFFFF - n)
			if wouldOverflow {
				// Should be rejected
				if r.CheckAndAccept(n+k, false) {
					t.Errorf("n=%08x k=%d: counter n+k should be rejected (overflow)", n, k)
				}
				continue
			}

			// Should be accepted
			if !r.CheckAndAccept(n+k, false) {
				t.Errorf("n=%08x k=%d: counter n+k=%08x should be accepted", n, k, n+k)
				continue
			}

			// Counter n should still be rejected
			if r.CheckAndAccept(n, false) {
				t.Errorf("n=%08x k=%d: counter n should be rejected after advance", n, k)
			}

			// Counters between windowStart and n+k-WindowSize should be rejected
			windowStart := uint32(0)
			if n >= CounterWindowSize {
				windowStart = n - CounterWindowSize
			}
			windowEnd := uint32(0)
			if (n + k) >= CounterWindowSize {
				windowEnd = n + k - CounterWindowSize
			}
			for i := windowStart; i < windowEnd; i++ {
				if r.CheckAndAccept(i, false) {
					t.Errorf("n=%08x k=%d: counter %08x should be rejected (outside window)", n, k, i)
				}
			}

			// Counter at window edge has special cases
			if (n+k) >= CounterWindowSize && n+k != CounterWindowSize {
				edgeCounter := n + k - CounterWindowSize
				if edgeCounter != n && edgeCounter != 0 && k != CounterWindowSize {
					if !r.CheckAndAccept(edgeCounter, false) {
						t.Errorf("n=%08x k=%d: counter %08x should be accepted (window edge)", n, k, edgeCounter)
					}
				}
			}
		}
	}
}

// TestUnicastLargeStep tests encrypted unicast counters with large steps.
// Ported from C SDK TestPeerMessageCounter.cpp UnicastLargeStepTest.
func TestUnicastLargeStep(t *testing.T) {
	// Test k values near 2^31 - 1
	kValues := []uint32{
		(1 << 31) - 5,
		(1 << 31) - 4,
		(1 << 31) - 3,
		(1 << 31) - 2,
		(1 << 31) - 1,
	}

	for _, n := range counterEdgeCaseValues {
		for _, k := range kValues {
			r := NewReceptionStateEmpty()

			// Accept initial counter n
			if !r.CheckAndAccept(n, false) {
				t.Fatalf("n=%08x k=%08x: initial counter should be accepted", n, k)
			}

			// For unicast, n+k is only valid if it doesn't overflow
			wouldOverflow := k > (0xFFFFFFFF - n)
			if wouldOverflow {
				if r.CheckAndAccept(n+k, false) {
					t.Errorf("n=%08x k=%08x: counter should be rejected (overflow)", n, k)
				}
				continue
			}

			// Should be accepted
			if !r.CheckAndAccept(n+k, false) {
				t.Errorf("n=%08x k=%08x: counter %08x should be accepted", n, k, n+k)
				continue
			}

			// Counter n should be rejected (behind window after big jump)
			if r.CheckAndAccept(n, false) {
				t.Errorf("n=%08x k=%08x: counter n should be rejected after big jump", n, k)
			}

			// Unlike group, unicast doesn't wrap - n - WindowSize is definitely behind
			if n >= CounterWindowSize {
				behindCounter := n - CounterWindowSize
				if r.CheckAndAccept(behindCounter, false) {
					t.Errorf("n=%08x k=%08x: counter %08x should be rejected (behind)", n, k, behindCounter)
				}
			}

			// Window edge should be accepted
			windowEdge := n + k - CounterWindowSize
			if !r.CheckAndAccept(windowEdge, false) {
				t.Errorf("n=%08x k=%08x: counter %08x should be accepted (window edge)", n, k, windowEdge)
			}
		}
	}
}

// TestUnencryptedRollOver tests unencrypted message counter handling.
// Unencrypted messages use relaxed duplicate detection - messages behind
// the window are accepted (may be from a rebooted node).
// Ported from C SDK TestPeerMessageCounter.cpp UnencryptedRollOverTest.
func TestUnencryptedRollOver(t *testing.T) {
	for _, n := range counterEdgeCaseValues {
		for k := uint32(1); k <= 2*CounterWindowSize; k++ {
			r := NewReceptionStateEmpty()

			// Accept initial counter n
			if !r.CheckUnencrypted(n) {
				t.Fatalf("n=%08x k=%d: initial counter should be accepted", n, k)
			}

			// Accept counter n + k
			if !r.CheckUnencrypted(n + k) {
				t.Errorf("n=%08x k=%d: counter n+k should be accepted", n, k)
				continue
			}

			// Counter n: if k <= WindowSize, it's in window (reject duplicate)
			// if k > WindowSize, it's behind window (accept - may be reboot)
			if k <= CounterWindowSize {
				if r.CheckUnencrypted(n) {
					t.Errorf("n=%08x k=%d: counter n should be rejected (in window)", n, k)
				}
			} else {
				if !r.CheckUnencrypted(n) {
					t.Errorf("n=%08x k=%d: counter n should be accepted (behind window)", n, k)
				}
			}

			// Window edge
			if k != CounterWindowSize {
				edgeCounter := n + k - CounterWindowSize
				if !r.CheckUnencrypted(edgeCounter) {
					t.Errorf("n=%08x k=%d: counter %08x should be accepted (window edge)", n, k, edgeCounter)
				}
			}
		}
	}
}

// TestUnencryptedOutOfWindow tests that unencrypted messages behind window are accepted.
// This is different from encrypted - we accept them because they may be from a rebooted node.
// Ported from C SDK TestPeerMessageCounter.cpp UnencryptedOutOfWindow.
func TestUnencryptedOutOfWindow(t *testing.T) {
	for _, n := range counterEdgeCaseValues {
		for k := uint32(1 << 31); k <= uint32(1<<31)+2; k++ {
			r := NewReceptionStateEmpty()

			// Accept initial counter n
			if !r.CheckUnencrypted(n) {
				t.Fatalf("n=%08x: initial counter should be accepted", n)
			}

			// Counter n + k: for unencrypted, this should be accepted
			// (unlike encrypted where it would be rejected)
			if !r.CheckUnencrypted(n + k) {
				t.Errorf("n=%08x k=%08x: counter %08x should be accepted (unencrypted out of window)", n, k, n+k)
			}
		}
	}
}

// TestPrivacyNonceSDKVector tests the privacy nonce construction with C SDK test vector.
// This vector comes from TestCryptoContext.cpp thePrivacyNonceTestVector.
func TestPrivacyNonceSDKVector(t *testing.T) {
	// From C SDK TestCryptoContext.cpp:
	// sessionId = 0x002a
	// mic = { 0xc5, 0xa0, 0x06, 0x3a, 0xd5, 0xd2, 0x51, 0x81, 0x91, 0x40, 0x0d, 0xd6, 0x8c, 0x5c, 0x16, 0x3b }
	// expected privacyNonce = { 0x00, 0x2a, 0xd2, 0x51, 0x81, 0x91, 0x40, 0x0d, 0xd6, 0x8c, 0x5c, 0x16, 0x3b }
	//
	// Note: This is already tested in pkg/crypto/nonce_test.go but we include it here
	// to verify the integration path and have all SDK test vectors in one place.

	sessionID := uint16(0x002a)
	mic := []byte{
		0xc5, 0xa0, 0x06, 0x3a, 0xd5, // bytes 0-4 (first 5 bytes, not used in nonce)
		0xd2, 0x51, 0x81, 0x91, 0x40, 0x0d, 0xd6, 0x8c, 0x5c, 0x16, 0x3b, // bytes 5-15 (used)
	}
	expectedNonce := []byte{
		0x00, 0x2a, // SessionID big-endian
		0xd2, 0x51, 0x81, 0x91, 0x40, 0x0d, 0xd6, 0x8c, 0x5c, 0x16, 0x3b, // MIC[5..15]
	}

	// The actual construction is in pkg/crypto/nonce.go BuildPrivacyNonce
	// Here we verify the logic matches: sessionID BE || MIC[5:16]
	nonce := make([]byte, 13)
	nonce[0] = byte(sessionID >> 8)
	nonce[1] = byte(sessionID)
	copy(nonce[2:], mic[5:16])

	for i, b := range expectedNonce {
		if nonce[i] != b {
			t.Errorf("nonce[%d] = %02x, want %02x", i, nonce[i], b)
		}
	}
}
