package exchange

import (
	"math"
	"math/rand"
	"time"
)

// RandomSource provides random values for jitter calculation.
// Allows injection of deterministic sources for testing.
type RandomSource interface {
	// Float64 returns a random float64 in [0.0, 1.0).
	Float64() float64
}

// defaultRandomSource uses math/rand for production.
type defaultRandomSource struct{}

func (defaultRandomSource) Float64() float64 {
	return rand.Float64()
}

// DefaultRandomSource is the default random source using math/rand.
var DefaultRandomSource RandomSource = defaultRandomSource{}

// BackoffCalculator computes MRP retransmission backoff times.
//
// The backoff formula from Spec Section 4.12.2.1:
//
//	mrpBackoffTime = i * MRP_BACKOFF_BASE^(max(0, n-MRP_BACKOFF_THRESHOLD))
//	                   * (1.0 + random(0,1) * MRP_BACKOFF_JITTER)
//
// Where:
//   - i = base retry interval (IDLE or ACTIVE) * MRP_BACKOFF_MARGIN
//   - n = number of send attempts before current one (0 for initial)
//
// This creates a two-phase scheme: linear backoff initially (for quick recovery
// from transient drops), transitioning to exponential backoff after threshold
// (for convergence during congestion).
type BackoffCalculator struct {
	random RandomSource
}

// NewBackoffCalculator creates a new backoff calculator with the given random source.
// If random is nil, DefaultRandomSource is used.
func NewBackoffCalculator(random RandomSource) *BackoffCalculator {
	if random == nil {
		random = DefaultRandomSource
	}
	return &BackoffCalculator{random: random}
}

// Calculate computes the backoff time for a retransmission.
//
// Parameters:
//   - baseInterval: The session's idle or active interval (from session.Params)
//   - attemptNumber: Number of previous send attempts (0 for initial transmission)
//
// Returns the backoff duration including jitter.
func (b *BackoffCalculator) Calculate(baseInterval time.Duration, attemptNumber int) time.Duration {
	// Apply margin to base interval
	// i = MRP_BACKOFF_MARGIN * baseInterval
	i := float64(baseInterval) * MRPBackoffMargin

	// Calculate exponential factor
	// exponent = max(0, n - MRP_BACKOFF_THRESHOLD)
	exponent := attemptNumber - MRPBackoffThreshold
	if exponent < 0 {
		exponent = 0
	}

	// base^exponent
	expFactor := math.Pow(MRPBackoffBase, float64(exponent))

	// Apply jitter: (1.0 + random(0,1) * MRP_BACKOFF_JITTER)
	jitterFactor := 1.0 + b.random.Float64()*MRPBackoffJitter

	// Final calculation
	backoffNs := i * expFactor * jitterFactor

	return time.Duration(backoffNs)
}

// CalculateMin computes the minimum backoff time (no jitter).
// Useful for testing and documentation.
func (b *BackoffCalculator) CalculateMin(baseInterval time.Duration, attemptNumber int) time.Duration {
	i := float64(baseInterval) * MRPBackoffMargin

	exponent := attemptNumber - MRPBackoffThreshold
	if exponent < 0 {
		exponent = 0
	}

	expFactor := math.Pow(MRPBackoffBase, float64(exponent))

	// Min jitter factor = 1.0 (random = 0)
	backoffNs := i * expFactor * 1.0

	return time.Duration(backoffNs)
}

// CalculateMax computes the maximum backoff time (full jitter).
// Useful for testing and documentation.
func (b *BackoffCalculator) CalculateMax(baseInterval time.Duration, attemptNumber int) time.Duration {
	i := float64(baseInterval) * MRPBackoffMargin

	exponent := attemptNumber - MRPBackoffThreshold
	if exponent < 0 {
		exponent = 0
	}

	expFactor := math.Pow(MRPBackoffBase, float64(exponent))

	// Max jitter factor = 1.0 + 1.0 * 0.25 = 1.25 (random = 1.0)
	backoffNs := i * expFactor * (1.0 + MRPBackoffJitter)

	return time.Duration(backoffNs)
}
