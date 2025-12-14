package message

import (
	"bytes"
	"testing"

	"github.com/backkem/matter/pkg/crypto"
)

// Test vectors from connectedhomeip SDK to ensure spec compliance.
// These vectors validate our implementation against the reference C implementation.

// TestSDKHeaderVectors validates message header encoding against SDK test vectors.
// Source: connectedhomeip/src/transport/raw/tests/TestMessageHeader.cpp:336
func TestSDKHeaderVectors(t *testing.T) {
	tests := []struct {
		name          string
		encoded       []byte
		messageFlags  uint8
		sessionID     uint16
		sessionType   SessionType
		securityFlags uint8
		messageCounter uint32
		isSecure      bool
		groupID       int // -1 means no group
	}{
		{
			name:          "Secure unicast message",
			encoded:       []byte{0x00, 0x88, 0x77, 0x00, 0x44, 0x33, 0x22, 0x11},
			messageFlags:  0x00,
			sessionID:     0x7788,
			sessionType:   SessionTypeUnicast,
			securityFlags: 0x00,
			messageCounter: 0x11223344,
			isSecure:      true,
			groupID:       -1,
		},
		{
			name:          "Secure group message",
			encoded:       []byte{0x02, 0xEE, 0xDD, 0xC1, 0x40, 0x30, 0x20, 0x10, 0x56, 0x34},
			messageFlags:  0x02,
			sessionID:     0xDDEE,
			sessionType:   SessionTypeGroup,
			securityFlags: 0xC1, // P=1, C=1, SessionType=1
			messageCounter: 0x10203040,
			isSecure:      true,
			groupID:       0x3456,
		},
		{
			name:          "Unsecured message",
			encoded:       []byte{0x00, 0x00, 0x00, 0x00, 0x40, 0x30, 0x20, 0x10},
			messageFlags:  0x00,
			sessionID:     0x0000,
			sessionType:   SessionTypeUnicast,
			securityFlags: 0x00,
			messageCounter: 0x10203040,
			isSecure:      false,
			groupID:       -1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name+" encode", func(t *testing.T) {
			// Build header from fields
			header := MessageHeader{
				SessionID:      tc.sessionID,
				MessageCounter: tc.messageCounter,
				SessionType:    tc.sessionType,
			}

			// Decode security flags to set boolean fields
			header.Privacy = (tc.securityFlags & secFlagPrivacy) != 0
			header.Control = (tc.securityFlags & secFlagControl) != 0
			header.Extensions = (tc.securityFlags & secFlagExtensions) != 0

			// Decode message flags
			header.SourcePresent = (tc.messageFlags & flagSourcePresent) != 0
			header.DestinationType = DestinationType(tc.messageFlags & flagDSIZMask)

			if tc.groupID >= 0 {
				header.DestinationGroupID = uint16(tc.groupID)
			}

			// Encode and compare
			encoded := header.Encode()
			if !bytes.Equal(encoded, tc.encoded) {
				t.Errorf("Encode() mismatch:\n  got:  %x\n  want: %x", encoded, tc.encoded)
			}

			// Verify size matches
			if len(encoded) != len(tc.encoded) {
				t.Errorf("Encoded size = %d, want %d", len(encoded), len(tc.encoded))
			}
		})

		t.Run(tc.name+" decode", func(t *testing.T) {
			// Decode the vector
			var header MessageHeader
			n, err := header.Decode(tc.encoded)
			if err != nil {
				t.Fatalf("Decode() error: %v", err)
			}

			if n != len(tc.encoded) {
				t.Errorf("Decoded %d bytes, want %d", n, len(tc.encoded))
			}

			// Verify fields
			if header.SessionID != tc.sessionID {
				t.Errorf("SessionID = %04x, want %04x", header.SessionID, tc.sessionID)
			}

			if header.MessageCounter != tc.messageCounter {
				t.Errorf("MessageCounter = %08x, want %08x", header.MessageCounter, tc.messageCounter)
			}

			if header.SessionType != tc.sessionType {
				t.Errorf("SessionType = %v, want %v", header.SessionType, tc.sessionType)
			}

			if header.IsSecure() != tc.isSecure {
				t.Errorf("IsSecure() = %v, want %v", header.IsSecure(), tc.isSecure)
			}

			if tc.groupID >= 0 {
				if header.DestinationType != DestinationGroupID {
					t.Errorf("DestinationType = %v, want GroupID", header.DestinationType)
				}
				if header.DestinationGroupID != uint16(tc.groupID) {
					t.Errorf("DestinationGroupID = %04x, want %04x", header.DestinationGroupID, tc.groupID)
				}
			}
		})
	}
}

// TestSDKPrivacyNonceVector validates privacy nonce construction.
// Source: connectedhomeip/src/transport/tests/TestCryptoContext.cpp:40
func TestSDKPrivacyNonceVector(t *testing.T) {
	// This is the exact test vector from the SDK
	sessionID := uint16(0x002a)
	mic := []byte{0xc5, 0xa0, 0x06, 0x3a, 0xd5, 0xd2, 0x51, 0x81, 0x91, 0x40, 0x0d, 0xd6, 0x8c, 0x5c, 0x16, 0x3b}
	expectedNonce := []byte{0x00, 0x2a, 0xd2, 0x51, 0x81, 0x91, 0x40, 0x0d, 0xd6, 0x8c, 0x5c, 0x16, 0x3b}

	nonce, err := crypto.BuildPrivacyNonce(sessionID, mic)
	if err != nil {
		t.Fatalf("BuildPrivacyNonce() error: %v", err)
	}

	if !bytes.Equal(nonce, expectedNonce) {
		t.Errorf("Privacy nonce mismatch:\n  got:  %x\n  want: %x", nonce, expectedNonce)
	}
}

// TestSDKCounterRollover validates counter rollover behavior matches SDK.
// Source: connectedhomeip/src/transport/tests/TestPeerMessageCounter.cpp:39
// This implements the GroupRollOverTest logic from the SDK.
func TestSDKCounterRollover(t *testing.T) {
	// Test values from SDK (line 37)
	counterValues := []uint32{0, 10, 0x7FFFFFFF, 0x80000000, 0x80000001, 0x80000002, 0xFFFFFFF0, 0xFFFFFFFF}

	for _, n := range counterValues {
		for k := uint32(1); k <= 2*CounterWindowSize; k++ {
			t.Run("", func(t *testing.T) {
				counter := NewReceptionStateEmpty()

				// 1. Accept initial counter N
				if !counter.CheckAndAccept(n, true) {
					t.Fatalf("Initial counter %d should be accepted", n)
				}

				// 2. Counter N + k should be accepted
				if !counter.CheckAndAccept(n+k, true) {
					t.Fatalf("Counter %d (n+%d) should be accepted", n+k, k)
				}

				// 3. Counter N should now be duplicate
				if counter.CheckAndAccept(n, true) {
					t.Errorf("Counter %d should be rejected (duplicate)", n)
				}

				// 4. Counters between N - WINDOW and N + k - WINDOW (exclusive) should be duplicates
				// Per SDK: range [n - WINDOW, n + k - WINDOW) are duplicates
				// We test a sampling to avoid excessive iterations
				if k > CounterWindowSize {
					testPoint := n + k - CounterWindowSize - 1
					if counter.CheckAndAccept(testPoint, true) {
						t.Errorf("Counter %d should be rejected (outside window)", testPoint)
					}
				}

				// 5. Counter N + k - WINDOW should be valid (unless k == WINDOW)
				windowEdge := n + k - CounterWindowSize
				shouldAccept := k != CounterWindowSize

				accepted := counter.CheckAndAccept(windowEdge, true)
				if accepted != shouldAccept {
					t.Errorf("Counter %d (window edge): accepted=%v, want %v", windowEdge, accepted, shouldAccept)
				}
			})
		}
	}
}

// TestSDKCounterBacktrack validates backtracking behavior.
// Source: connectedhomeip/src/transport/tests/TestPeerMessageCounter.cpp:79
func TestSDKCounterBacktrack(t *testing.T) {
	counterValues := []uint32{0, 10, 0x7FFFFFFF, 0x80000000, 0xFFFFFFF0, 0xFFFFFFFF}

	for _, n := range counterValues {
		t.Run("", func(t *testing.T) {
			counter := NewReceptionStateEmpty()

			// 1. Accept initial counter N
			if !counter.CheckAndAccept(n, true) {
				t.Fatalf("Initial counter should be accepted")
			}

			// 2. Accept set of N - k for k^2 < WINDOW (sparse backtrack)
			backtracks := []uint32{}
			for k := uint32(1); k*k < CounterWindowSize; k++ {
				val := n - (k * k)
				backtracks = append(backtracks, val)
				if !counter.CheckAndAccept(val, true) {
					t.Errorf("Counter %d (n-%d) should be accepted (backtrack)", val, k*k)
				}
			}

			// 3. Accept N + 3
			if !counter.CheckAndAccept(n+3, true) {
				t.Fatalf("Counter n+3 should be accepted")
			}

			// 4. The backtracked values should now be duplicates
			for _, val := range backtracks {
				if counter.CheckAndAccept(val, true) {
					t.Errorf("Counter %d should be rejected (duplicate after window advance)", val)
				}
			}

			// 5. Values in new window (n+3-WINDOW to n+3) that weren't in backtrack set should work
			for k := n + 3 - CounterWindowSize; k != n+3; k++ {
				// Skip values we already received
				isBacktrack := false
				for _, bt := range backtracks {
					if k == bt || k == n {
						isBacktrack = true
						break
					}
				}
				if isBacktrack {
					continue
				}

				if !counter.CheckAndAccept(k, true) {
					t.Errorf("Counter %d should be accepted (in new window)", k)
				}
			}
		})
	}
}

// TestSDKCounterBigLeap validates behavior with large counter jumps.
// Source: connectedhomeip/src/transport/tests/TestPeerMessageCounter.cpp:118
func TestSDKCounterBigLeap(t *testing.T) {
	counterValues := []uint32{0, 10, 0x7FFFFFFF, 0x80000000, 0xFFFFFFF0, 0xFFFFFFFF}

	// Test with k values near 2^31 (maximum valid forward distance)
	kValues := []uint32{
		(1 << 31) - 5,
		(1 << 31) - 4,
		(1 << 31) - 3,
		(1 << 31) - 2,
		(1 << 31) - 1,
	}

	for _, n := range counterValues {
		for _, k := range kValues {
			t.Run("", func(t *testing.T) {
				counter := NewReceptionStateEmpty()

				// 1. Accept N
				if !counter.CheckAndAccept(n, true) {
					t.Fatalf("Initial counter should be accepted")
				}

				// 2. N + k (big leap) should be accepted
				if !counter.CheckAndAccept(n+k, true) {
					t.Fatalf("Counter n+k (big leap) should be accepted")
				}

				// 3. N should be duplicate
				if counter.CheckAndAccept(n, true) {
					t.Errorf("Counter %d should be rejected (duplicate)", n)
				}

				// 4. N - WINDOW should be valid (because of rollover arithmetic)
				// With max at n+k (near 2^31 ahead), n-WINDOW is within 2^31 behind
				if !counter.CheckAndAccept(n-CounterWindowSize, true) {
					t.Errorf("Counter n-WINDOW should be accepted (within signed range)")
				}

				// 5. N + k - WINDOW should be valid
				if !counter.CheckAndAccept(n+k-CounterWindowSize, true) {
					t.Errorf("Counter n+k-WINDOW should be accepted")
				}
			})
		}
	}
}

// TestSDKCounterOutOfWindow validates that counters exactly at 2^31 ahead are rejected.
// Source: connectedhomeip/src/transport/tests/TestPeerMessageCounter.cpp:163
func TestSDKCounterOutOfWindow(t *testing.T) {
	counterValues := []uint32{0, 10, 0x7FFFFFFF, 0x80000000, 0xFFFFFFF0, 0xFFFFFFFF}

	// Test with k values at and beyond 2^31 (invalid forward distance)
	kValues := []uint32{
		1 << 31,
		(1 << 31) + 1,
		(1 << 31) + 2,
	}

	for _, n := range counterValues {
		for _, k := range kValues {
			t.Run("", func(t *testing.T) {
				counter := NewReceptionStateEmpty()

				// Accept N
				if !counter.CheckAndAccept(n, true) {
					t.Fatalf("Initial counter should be accepted")
				}

				// N + k (at or beyond 2^31) should be rejected as duplicate
				// Per spec: only counters in [max+1, max+2^31-1] are valid
				if counter.CheckAndAccept(n+k, true) {
					t.Errorf("Counter %d (n+%d) should be rejected (out of window)", n+k, k)
				}
			})
		}
	}
}

// TestSDKUnicastNoRollover validates unicast counter behavior (no rollover allowed).
// Source: connectedhomeip/src/transport/tests/TestPeerMessageCounter.cpp:180
func TestSDKUnicastNoRollover(t *testing.T) {
	counterValues := []uint32{0, 10, 0x7FFFFFFF, 0x80000000, 0xFFFFFFF0, 0xFFFFFFFF}

	for _, n := range counterValues {
		for k := uint32(1); k <= 2*CounterWindowSize; k++ {
			t.Run("", func(t *testing.T) {
				counter := NewReceptionStateEmpty()

				// Accept initial counter N
				if !counter.CheckAndAccept(n, false) {
					t.Fatalf("Initial counter should be accepted")
				}

				// Counter N should now be duplicate
				if counter.CheckAndAccept(n, false) {
					t.Errorf("Counter %d should be rejected (duplicate)", n)
				}

				// Check if N + k would overflow
				// Per SDK line 205: if (k > UINT32_MAX - n), skip this test
				if k > (0xFFFFFFFF - n) {
					// Would overflow - skip remaining checks
					return
				}

				// N + k should be accepted (no overflow)
				if !counter.CheckAndAccept(n+k, false) {
					t.Fatalf("Counter n+k=%d should be accepted", n+k)
				}

				// N should still be duplicate
				if counter.CheckAndAccept(n, false) {
					t.Errorf("Counter %d should still be rejected", n)
				}

				// Counters in window [n+k-WINDOW, n+k-1] that weren't received should work
				// Test the window edge (per SDK lines 232-244)
				if n+k >= CounterWindowSize {
					windowEdge := n + k - CounterWindowSize
					// Skip if windowEdge == n (already received) or windowEdge == 0 (always treated as seen)
					if windowEdge != n && windowEdge != 0 && k != CounterWindowSize {
						if !counter.CheckAndAccept(windowEdge, false) {
							t.Errorf("Counter %d (window edge) should be accepted", windowEdge)
						}
					}
				}
			})
		}
	}
}

// TestCompleteEncryptionRoundtrip validates end-to-end encryption.
// While we don't have a full SDK vector with encrypted payload, this validates
// that our encryption/decryption is internally consistent and uses the correct
// nonce/AAD construction per spec.
func TestCompleteEncryptionRoundtrip(t *testing.T) {
	// Use a known encryption key
	key := []byte{
		0x5e, 0xde, 0xd2, 0x44, 0xe5, 0x53, 0x2b, 0x3c,
		0xdc, 0x23, 0x40, 0x9d, 0xba, 0xd0, 0x52, 0xd2,
	}

	codec, err := NewCodec(key, UnspecifiedNodeID)
	if err != nil {
		t.Fatalf("NewCodec() error: %v", err)
	}

	// Create a message matching SDK patterns
	header := MessageHeader{
		SessionID:       0x7788,
		SessionType:     SessionTypeUnicast,
		MessageCounter:  0x11223344,
		DestinationType: DestinationNone,
	}

	protocol := ProtocolHeader{
		ProtocolID:     ProtocolSecureChannel,
		ProtocolOpcode: 0x40,
		ExchangeID:     0x1234,
		Initiator:      true,
	}

	payload := []byte("Test Matter message payload")

	// Encode without privacy
	encoded, err := codec.Encode(&header, &protocol, payload, false)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// Verify structure:
	// [Header (8 bytes)][Encrypted Protocol + Payload][MIC (16 bytes)]
	expectedMinSize := MinHeaderSize + len(protocol.Encode()) + len(payload) + MICSize
	if len(encoded) < expectedMinSize {
		t.Errorf("Encoded size = %d, expected at least %d", len(encoded), expectedMinSize)
	}

	// Decode
	decoded, err := codec.Decode(encoded, UnspecifiedNodeID)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	// Verify roundtrip
	if !bytes.Equal(decoded.Payload, payload) {
		t.Errorf("Payload mismatch after roundtrip")
	}

	compareProtocolHeaders(t, &protocol, &decoded.Protocol)
}

// TestPrivacyObfuscationConsistency validates that privacy obfuscation
// produces different wire bytes but decrypts to the same plaintext.
func TestPrivacyObfuscationConsistency(t *testing.T) {
	key := []byte{
		0xa6, 0xf5, 0x30, 0x6b, 0xaf, 0x6d, 0x05, 0x0a,
		0xf2, 0x3b, 0xa4, 0xbd, 0x6b, 0x9d, 0xd9, 0x60,
	}

	codec, _ := NewCodec(key, UnspecifiedNodeID)

	header := MessageHeader{
		SessionID:       0xABCD,
		SessionType:     SessionTypeUnicast,
		MessageCounter:  0x12345678,
		DestinationType: DestinationNone,
	}

	protocol := ProtocolHeader{
		ProtocolID:     ProtocolInteractionModel,
		ProtocolOpcode: 0x05,
		ExchangeID:     0x1111,
	}

	payload := []byte("privacy test")

	// Encode without privacy
	headerCopy1 := header
	encodedNoPrivacy, err := codec.Encode(&headerCopy1, &protocol, payload, false)
	if err != nil {
		t.Fatalf("Encode(noPrivacy) error: %v", err)
	}

	// Encode with privacy
	headerCopy2 := header
	encodedWithPrivacy, err := codec.Encode(&headerCopy2, &protocol, payload, true)
	if err != nil {
		t.Fatalf("Encode(withPrivacy) error: %v", err)
	}

	// Wire bytes should differ (obfuscated counter at minimum)
	if bytes.Equal(encodedNoPrivacy, encodedWithPrivacy) {
		t.Error("Privacy encoding should produce different wire bytes")
	}

	// Both should decrypt to same payload
	decoded1, err := codec.Decode(encodedNoPrivacy, UnspecifiedNodeID)
	if err != nil {
		t.Fatalf("Decode(noPrivacy) error: %v", err)
	}

	decoded2, err := codec.Decode(encodedWithPrivacy, UnspecifiedNodeID)
	if err != nil {
		t.Fatalf("Decode(withPrivacy) error: %v", err)
	}

	if !bytes.Equal(decoded1.Payload, decoded2.Payload) {
		t.Error("Payloads should match after decryption")
	}

	if !bytes.Equal(decoded1.Payload, payload) {
		t.Error("Decrypted payload doesn't match original")
	}
}
