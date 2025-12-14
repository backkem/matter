package exchange

import "time"

// MRP (Message Reliability Protocol) parameters from Spec Section 4.12.8, Table 22.
//
// Note: Session-level timing parameters (SESSION_IDLE_INTERVAL, SESSION_ACTIVE_INTERVAL,
// SESSION_ACTIVE_THRESHOLD) are defined in pkg/session.Params and obtained from
// DNS-SD discovery or session establishment messages.
const (
	// MRPMaxTransmissions is the maximum number of transmission attempts for a
	// reliable message. After this many attempts without acknowledgement, the
	// message is considered undeliverable.
	// Spec: MRP_MAX_TRANSMISSIONS = 5
	MRPMaxTransmissions = 5

	// MRPBackoffBase is the base for exponential backoff calculation.
	// Spec: MRP_BACKOFF_BASE = 1.6
	MRPBackoffBase = 1.6

	// MRPBackoffJitter is the scaler for random jitter in backoff calculation.
	// Spec: MRP_BACKOFF_JITTER = 0.25
	MRPBackoffJitter = 0.25

	// MRPBackoffMargin is the scaler margin increase over peer idle interval.
	// Spec: MRP_BACKOFF_MARGIN = 1.1
	MRPBackoffMargin = 1.1

	// MRPBackoffThreshold is the number of retransmissions before transitioning
	// from linear to exponential backoff.
	// Spec: MRP_BACKOFF_THRESHOLD = 1
	MRPBackoffThreshold = 1

	// MRPStandaloneAckTimeout is the time to wait for an opportunity to piggyback
	// an acknowledgement before sending a standalone ACK.
	// Spec: MRP_STANDALONE_ACK_TIMEOUT = 200ms
	MRPStandaloneAckTimeout = 200 * time.Millisecond
)

// MaxConcurrentExchanges is the recommended maximum concurrent exchanges per session.
// Per Spec 4.10.5.2: "A node SHOULD limit itself to a maximum of 5 concurrent
// exchanges over a unicast session" to prevent exhausting the message counter window.
const MaxConcurrentExchanges = 5
