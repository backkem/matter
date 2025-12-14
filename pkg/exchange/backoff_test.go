package exchange

import (
	"testing"
	"time"
)

// mockRandomSource returns a fixed value for deterministic testing.
type mockRandomSource struct {
	value float64
}

func (m mockRandomSource) Float64() float64 {
	return m.value
}

// TestBackoffTable21 verifies backoff calculation against Spec Table 21.
//
// Table 21 uses default parameters with 300ms base interval:
// | Transmission # | Min Jitter (ms) | Max Jitter (ms) |
// |----------------|-----------------|-----------------|
// | 0              | 330             | 413             |
// | 1              | 330             | 413             |
// | 2              | 528             | 660             |
// | 3              | 845             | 1056            |
// | 4              | 1352            | 1690            |
func TestBackoffTable21(t *testing.T) {
	// Table 21 uses 300ms base interval (SESSION_ACTIVE_INTERVAL default)
	baseInterval := 300 * time.Millisecond

	// Expected values from Table 21 (in milliseconds)
	expected := []struct {
		attempt int
		minMs   int
		maxMs   int
	}{
		{0, 330, 413},
		{1, 330, 413},
		{2, 528, 660},
		{3, 845, 1056},
		{4, 1352, 1690},
	}

	calc := NewBackoffCalculator(nil)

	for _, tc := range expected {
		t.Run("", func(t *testing.T) {
			minBackoff := calc.CalculateMin(baseInterval, tc.attempt)
			maxBackoff := calc.CalculateMax(baseInterval, tc.attempt)

			// Allow 1ms tolerance for floating point rounding
			minMs := int(minBackoff.Milliseconds())
			maxMs := int(maxBackoff.Milliseconds())

			// Check minimum matches (tolerance of 1ms for rounding)
			if minMs < tc.minMs-1 || minMs > tc.minMs+1 {
				t.Errorf("attempt %d: min backoff = %dms, want %dms",
					tc.attempt, minMs, tc.minMs)
			}

			// Check maximum matches (tolerance of 1ms for rounding)
			if maxMs < tc.maxMs-1 || maxMs > tc.maxMs+1 {
				t.Errorf("attempt %d: max backoff = %dms, want %dms",
					tc.attempt, maxMs, tc.maxMs)
			}
		})
	}
}

// TestBackoffMinJitter verifies minimum jitter (random=0).
func TestBackoffMinJitter(t *testing.T) {
	baseInterval := 300 * time.Millisecond
	calc := NewBackoffCalculator(mockRandomSource{value: 0.0})

	// With random=0, should get minimum values
	backoff := calc.Calculate(baseInterval, 0)

	// Expected: 300 * 1.1 * 1.6^0 * (1 + 0*0.25) = 330ms
	expectedMs := 330
	gotMs := int(backoff.Milliseconds())

	if gotMs != expectedMs {
		t.Errorf("min jitter backoff = %dms, want %dms", gotMs, expectedMs)
	}
}

// TestBackoffMaxJitter verifies maximum jitter (random=1.0).
func TestBackoffMaxJitter(t *testing.T) {
	baseInterval := 300 * time.Millisecond
	// Note: random.Float64() returns [0, 1), so 0.9999... is the max
	// But for testing purposes, we use 1.0 to match the spec formula
	calc := NewBackoffCalculator(mockRandomSource{value: 1.0})

	// With random=1.0, should get maximum values
	backoff := calc.Calculate(baseInterval, 0)

	// Expected: 300 * 1.1 * 1.6^0 * (1 + 1.0*0.25) = 412.5ms
	expectedMs := 412
	gotMs := int(backoff.Milliseconds())

	if gotMs < expectedMs || gotMs > expectedMs+1 {
		t.Errorf("max jitter backoff = %dms, want ~%dms", gotMs, expectedMs)
	}
}

// TestBackoffExponentialPhase verifies exponential growth after threshold.
func TestBackoffExponentialPhase(t *testing.T) {
	baseInterval := 300 * time.Millisecond
	calc := NewBackoffCalculator(mockRandomSource{value: 0.0})

	// Attempts 0 and 1 should be the same (linear phase)
	b0 := calc.Calculate(baseInterval, 0)
	b1 := calc.Calculate(baseInterval, 1)

	if b0 != b1 {
		t.Errorf("linear phase: attempt 0 (%v) != attempt 1 (%v)", b0, b1)
	}

	// Attempt 2 should be 1.6x larger (exponential phase starts)
	b2 := calc.Calculate(baseInterval, 2)
	ratio := float64(b2) / float64(b1)

	if ratio < 1.59 || ratio > 1.61 {
		t.Errorf("exponential phase: ratio b2/b1 = %v, want ~1.6", ratio)
	}

	// Attempt 3 should be 1.6x larger than attempt 2
	b3 := calc.Calculate(baseInterval, 3)
	ratio = float64(b3) / float64(b2)

	if ratio < 1.59 || ratio > 1.61 {
		t.Errorf("exponential phase: ratio b3/b2 = %v, want ~1.6", ratio)
	}
}

// TestBackoffIdleVsActive verifies different base intervals.
func TestBackoffIdleVsActive(t *testing.T) {
	calc := NewBackoffCalculator(mockRandomSource{value: 0.0})

	// Active interval (faster)
	activeInterval := 300 * time.Millisecond
	activeBackoff := calc.Calculate(activeInterval, 0)

	// Idle interval (slower, typical default is 500ms)
	idleInterval := 500 * time.Millisecond
	idleBackoff := calc.Calculate(idleInterval, 0)

	// Idle should be proportionally larger
	expectedRatio := float64(idleInterval) / float64(activeInterval)
	actualRatio := float64(idleBackoff) / float64(activeBackoff)

	if actualRatio < expectedRatio-0.01 || actualRatio > expectedRatio+0.01 {
		t.Errorf("idle/active ratio = %v, want %v", actualRatio, expectedRatio)
	}
}

// TestBackoffWithRealRandom verifies calculation works with real random source.
func TestBackoffWithRealRandom(t *testing.T) {
	baseInterval := 300 * time.Millisecond
	calc := NewBackoffCalculator(nil) // Uses DefaultRandomSource

	for i := 0; i < 100; i++ {
		backoff := calc.Calculate(baseInterval, 0)

		// Should be within min/max bounds
		minBackoff := calc.CalculateMin(baseInterval, 0)
		maxBackoff := calc.CalculateMax(baseInterval, 0)

		if backoff < minBackoff || backoff > maxBackoff {
			t.Errorf("backoff %v outside bounds [%v, %v]", backoff, minBackoff, maxBackoff)
		}
	}
}

// TestBackoffCumulativeTable21 verifies cumulative times from Table 21.
//
// | Metric    | 0   | 1   | 2    | 3    | 4    |
// | Min Total | 330 | 660 | 1188 | 2033 | 3385 |
// | Max Total | 413 | 825 | 1485 | 2541 | 4231 |
func TestBackoffCumulativeTable21(t *testing.T) {
	baseInterval := 300 * time.Millisecond
	calc := NewBackoffCalculator(nil)

	expectedMinCumulative := []int{330, 660, 1188, 2033, 3385}
	expectedMaxCumulative := []int{413, 825, 1485, 2541, 4231}

	minCumulative := 0
	maxCumulative := 0

	for attempt := 0; attempt < 5; attempt++ {
		minCumulative += int(calc.CalculateMin(baseInterval, attempt).Milliseconds())
		maxCumulative += int(calc.CalculateMax(baseInterval, attempt).Milliseconds())

		// Allow 2ms tolerance for cumulative rounding
		if minCumulative < expectedMinCumulative[attempt]-2 ||
			minCumulative > expectedMinCumulative[attempt]+2 {
			t.Errorf("attempt %d: min cumulative = %dms, want %dms",
				attempt, minCumulative, expectedMinCumulative[attempt])
		}

		if maxCumulative < expectedMaxCumulative[attempt]-2 ||
			maxCumulative > expectedMaxCumulative[attempt]+2 {
			t.Errorf("attempt %d: max cumulative = %dms, want %dms",
				attempt, maxCumulative, expectedMaxCumulative[attempt])
		}
	}
}
