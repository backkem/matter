package commissioning

import (
	"context"
	"sync"
	"time"

	"github.com/backkem/matter/pkg/discovery"
	"github.com/backkem/matter/pkg/securechannel/pase"
	"github.com/backkem/matter/pkg/session"
)

// CommissioningWindowConfig configures a commissioning window.
type CommissioningWindowConfig struct {
	// Timeout is the duration of the commissioning window.
	// After this duration, the window automatically closes.
	Timeout time.Duration

	// Discriminator for DNS-SD advertisement (12-bit value).
	Discriminator uint16

	// VendorID for DNS-SD advertisement.
	VendorID uint16

	// ProductID for DNS-SD advertisement.
	ProductID uint16

	// DeviceName for DNS-SD (optional, max 32 chars).
	DeviceName string

	// Verifier for PASE authentication.
	// If nil, must be set via SetVerifier before opening.
	Verifier *pase.Verifier

	// Salt for PASE (16-32 bytes).
	Salt []byte

	// Iterations for PBKDF2 (1000-100000).
	Iterations uint32

	// Advertiser for DNS-SD announcements.
	// If nil, a default advertiser will be created.
	Advertiser *discovery.Advertiser

	// OnStateChanged is called when the commissioning state changes.
	OnStateChanged func(state DeviceCommissioningState)

	// OnPASEEstablished is called when a PASE session is established.
	OnPASEEstablished func(sess *session.SecureContext)

	// OnCommissioningComplete is called when commissioning completes.
	OnCommissioningComplete func()

	// OnWindowClosed is called when the commissioning window closes.
	OnWindowClosed func(reason error)
}

// CommissioningWindow manages a commissioning window on the device side.
//
// A commissioning window is a time-limited period during which a device
// accepts commissioning attempts. The device advertises itself via DNS-SD
// and responds to PASE session requests.
type CommissioningWindow struct {
	config    CommissioningWindowConfig
	state     DeviceCommissioningState
	failSafe  *FailSafeTimer
	mu        sync.RWMutex
	closeCh   chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// NewCommissioningWindow creates a new commissioning window.
func NewCommissioningWindow(config CommissioningWindowConfig) (*CommissioningWindow, error) {
	if config.Timeout <= 0 {
		config.Timeout = 3 * time.Minute // Default timeout
	}
	if config.Iterations == 0 {
		config.Iterations = 1000 // Default iterations
	}

	w := &CommissioningWindow{
		config:  config,
		state:   DeviceStateUncommissioned,
		closeCh: make(chan struct{}),
	}

	// Create fail-safe timer
	w.failSafe = NewFailSafeTimer(func() {
		w.onFailSafeExpired()
	})

	return w, nil
}

// Open opens the commissioning window and starts advertising.
//
// The window will automatically close after the configured timeout
// or when Close() is called.
func (w *CommissioningWindow) Open(ctx context.Context) error {
	w.mu.Lock()
	if w.state == DeviceStateAdvertising {
		w.mu.Unlock()
		return ErrWindowAlreadyOpen
	}
	w.setState(DeviceStateAdvertising)
	w.mu.Unlock()

	// Start timeout timer
	timer := time.NewTimer(w.config.Timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		w.closeWithError(ctx.Err())
		return ctx.Err()
	case <-timer.C:
		w.closeWithError(ErrCommissioningTimeout)
		return ErrCommissioningTimeout
	case <-w.closeCh:
		return w.closeErr
	}
}

// Close closes the commissioning window.
func (w *CommissioningWindow) Close() error {
	w.closeWithError(nil)
	return nil
}

// closeWithError closes the window with a specific error.
func (w *CommissioningWindow) closeWithError(err error) {
	w.closeOnce.Do(func() {
		w.closeErr = err
		close(w.closeCh)

		w.mu.Lock()
		w.failSafe.Disarm()
		w.setState(DeviceStateUncommissioned)
		w.mu.Unlock()

		if w.config.OnWindowClosed != nil {
			w.config.OnWindowClosed(err)
		}
	})
}

// State returns the current commissioning state.
func (w *CommissioningWindow) State() DeviceCommissioningState {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.state
}

// setState sets the state and notifies the callback.
// Caller must hold w.mu.
func (w *CommissioningWindow) setState(state DeviceCommissioningState) {
	w.state = state
	if w.config.OnStateChanged != nil {
		w.config.OnStateChanged(state)
	}
}

// Verifier returns the PASE verifier for this window.
func (w *CommissioningWindow) Verifier() *pase.Verifier {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.config.Verifier
}

// SetVerifier sets the PASE verifier for this window.
// Must be called before Open() if not provided in config.
func (w *CommissioningWindow) SetVerifier(v *pase.Verifier) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.config.Verifier = v
}

// Salt returns the PBKDF salt for this window.
func (w *CommissioningWindow) Salt() []byte {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.config.Salt
}

// Iterations returns the PBKDF iteration count for this window.
func (w *CommissioningWindow) Iterations() uint32 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.config.Iterations
}

// OnPASERequest handles an incoming PASE session request.
// Returns an error if the window is not accepting requests.
func (w *CommissioningWindow) OnPASERequest() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.state != DeviceStateAdvertising {
		return ErrWindowClosed
	}

	w.setState(DeviceStatePASEPending)
	return nil
}

// OnPASEComplete handles successful PASE session establishment.
func (w *CommissioningWindow) OnPASEComplete(sess *session.SecureContext) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.state != DeviceStatePASEPending {
		return ErrWindowClosed
	}

	w.setState(DeviceStatePASEEstablished)

	if w.config.OnPASEEstablished != nil {
		w.config.OnPASEEstablished(sess)
	}

	return nil
}

// OnPASEFailed handles PASE session failure.
// Returns the window to the advertising state.
func (w *CommissioningWindow) OnPASEFailed() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.state == DeviceStatePASEPending {
		w.setState(DeviceStateAdvertising)
	}
}

// ArmFailSafe arms the fail-safe timer with the given timeout.
// This is called when the commissioner sends ArmFailSafe.
func (w *CommissioningWindow) ArmFailSafe(timeout time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.setState(DeviceStateCommissioning)
	w.failSafe.Arm(timeout)
}

// DisarmFailSafe disarms the fail-safe timer.
// This is called when commissioning completes successfully.
func (w *CommissioningWindow) DisarmFailSafe() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.failSafe.Disarm()
}

// onFailSafeExpired handles fail-safe timer expiration.
func (w *CommissioningWindow) onFailSafeExpired() {
	w.closeWithError(ErrFailSafeExpired)
}

// OnCommissioningComplete handles successful commissioning completion.
func (w *CommissioningWindow) OnCommissioningComplete() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.failSafe.Disarm()
	w.setState(DeviceStateCommissioned)

	if w.config.OnCommissioningComplete != nil {
		w.config.OnCommissioningComplete()
	}

	return nil
}

// FailSafeTimer implements the commissioning fail-safe timer.
//
// The fail-safe timer ensures that if commissioning is interrupted,
// the device will revert to its pre-commissioning state. The timer
// must be armed by the commissioner and disarmed upon successful
// completion.
//
// See Matter Specification Section 11.10.7.2.
type FailSafeTimer struct {
	timeout   time.Duration
	expiresAt time.Time
	armed     bool
	onExpire  func()
	mu        sync.Mutex
	timer     *time.Timer
}

// NewFailSafeTimer creates a new fail-safe timer.
// The onExpire callback is called when the timer expires.
func NewFailSafeTimer(onExpire func()) *FailSafeTimer {
	return &FailSafeTimer{
		onExpire: onExpire,
	}
}

// Arm arms the fail-safe timer with the given timeout.
// If already armed, the timer is reset to the new timeout.
func (f *FailSafeTimer) Arm(timeout time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Stop existing timer if any
	if f.timer != nil {
		f.timer.Stop()
	}

	f.timeout = timeout
	f.expiresAt = time.Now().Add(timeout)
	f.armed = true

	f.timer = time.AfterFunc(timeout, func() {
		f.mu.Lock()
		wasArmed := f.armed
		f.armed = false
		f.mu.Unlock()

		if wasArmed && f.onExpire != nil {
			f.onExpire()
		}
	})
}

// Disarm disarms the fail-safe timer.
func (f *FailSafeTimer) Disarm() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.armed = false
	if f.timer != nil {
		f.timer.Stop()
		f.timer = nil
	}
}

// IsArmed returns true if the timer is currently armed.
func (f *FailSafeTimer) IsArmed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.armed
}

// RemainingTime returns the time remaining before expiry.
// Returns 0 if the timer is not armed.
func (f *FailSafeTimer) RemainingTime() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.armed {
		return 0
	}

	remaining := time.Until(f.expiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ExpiresAt returns the time when the timer will expire.
// Returns zero time if the timer is not armed.
func (f *FailSafeTimer) ExpiresAt() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.armed {
		return time.Time{}
	}
	return f.expiresAt
}
