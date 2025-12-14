package session

import "time"

// MRP (Message Reliability Protocol) parameter defaults from Spec Section 4.12.8.
// These values are used when the peer does not advertise custom parameters.
const (
	// DefaultIdleInterval is the default SESSION_IDLE_INTERVAL (500ms).
	// Used for MRP retry timing when peer is idle.
	DefaultIdleInterval = 500 * time.Millisecond

	// DefaultActiveInterval is the default SESSION_ACTIVE_INTERVAL (300ms).
	// Used for MRP retry timing when peer is active.
	DefaultActiveInterval = 300 * time.Millisecond

	// DefaultActiveThreshold is the default SESSION_ACTIVE_THRESHOLD (4000ms).
	// Determines how long after last activity the peer is considered active.
	DefaultActiveThreshold = 4000 * time.Millisecond

	// MaxIdleInterval is the maximum allowed SESSION_IDLE_INTERVAL (1 hour).
	MaxIdleInterval = time.Hour

	// MaxActiveInterval is the maximum allowed SESSION_ACTIVE_INTERVAL (1 hour).
	MaxActiveInterval = time.Hour

	// MaxActiveThreshold is the maximum allowed SESSION_ACTIVE_THRESHOLD (65.535s).
	MaxActiveThreshold = 65535 * time.Millisecond
)

// Params holds MRP timing parameters for a session.
// These parameters control retransmission timing in the Message Reliability Protocol.
// See Spec Section 4.13.1 (Glossary of Session parameters).
type Params struct {
	// IdleInterval is the SESSION_IDLE_INTERVAL.
	// MRP retry interval when peer is idle (not recently active).
	IdleInterval time.Duration

	// ActiveInterval is the SESSION_ACTIVE_INTERVAL.
	// MRP retry interval when peer is active (recently sent/received).
	ActiveInterval time.Duration

	// ActiveThreshold is the SESSION_ACTIVE_THRESHOLD.
	// Duration after last receive before peer transitions from active to idle.
	ActiveThreshold time.Duration
}

// DefaultParams returns the spec-compliant default MRP parameters.
func DefaultParams() Params {
	return Params{
		IdleInterval:    DefaultIdleInterval,
		ActiveInterval:  DefaultActiveInterval,
		ActiveThreshold: DefaultActiveThreshold,
	}
}

// Validate checks that the parameters are within spec limits.
// Returns true if all parameters are valid.
func (p Params) Validate() bool {
	if p.IdleInterval <= 0 || p.IdleInterval > MaxIdleInterval {
		return false
	}
	if p.ActiveInterval <= 0 || p.ActiveInterval > MaxActiveInterval {
		return false
	}
	if p.ActiveThreshold <= 0 || p.ActiveThreshold > MaxActiveThreshold {
		return false
	}
	return true
}

// WithDefaults returns a copy of the parameters with zero values replaced by defaults.
func (p Params) WithDefaults() Params {
	result := p
	if result.IdleInterval == 0 {
		result.IdleInterval = DefaultIdleInterval
	}
	if result.ActiveInterval == 0 {
		result.ActiveInterval = DefaultActiveInterval
	}
	if result.ActiveThreshold == 0 {
		result.ActiveThreshold = DefaultActiveThreshold
	}
	return result
}
