package commissioning

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewCommissioningWindow(t *testing.T) {
	config := CommissioningWindowConfig{
		Timeout:       30 * time.Second,
		Discriminator: 3840,
		Iterations:    1000,
	}

	window, err := NewCommissioningWindow(config)
	if err != nil {
		t.Fatalf("NewCommissioningWindow() error: %v", err)
	}

	if window.State() != DeviceStateUncommissioned {
		t.Errorf("State() = %v, want %v", window.State(), DeviceStateUncommissioned)
	}
}

func TestCommissioningWindowStateTransitions(t *testing.T) {
	var stateChanges []DeviceCommissioningState

	config := CommissioningWindowConfig{
		Timeout:    100 * time.Millisecond,
		Iterations: 1000,
		OnStateChanged: func(state DeviceCommissioningState) {
			stateChanges = append(stateChanges, state)
		},
	}

	window, err := NewCommissioningWindow(config)
	if err != nil {
		t.Fatalf("NewCommissioningWindow() error: %v", err)
	}

	// Test PASE request flow
	t.Run("PASE request accepted", func(t *testing.T) {
		stateChanges = nil

		// Simulate opening (in background since it blocks)
		ctx, cancel := context.WithCancel(context.Background())
		go window.Open(ctx)

		// Wait for advertising state
		time.Sleep(10 * time.Millisecond)

		if window.State() != DeviceStateAdvertising {
			t.Errorf("State after Open() = %v, want %v", window.State(), DeviceStateAdvertising)
		}

		// Simulate PASE request
		if err := window.OnPASERequest(); err != nil {
			t.Errorf("OnPASERequest() error: %v", err)
		}

		if window.State() != DeviceStatePASEPending {
			t.Errorf("State after OnPASERequest() = %v, want %v", window.State(), DeviceStatePASEPending)
		}

		// Simulate PASE complete
		if err := window.OnPASEComplete(nil); err != nil {
			t.Errorf("OnPASEComplete() error: %v", err)
		}

		if window.State() != DeviceStatePASEEstablished {
			t.Errorf("State after OnPASEComplete() = %v, want %v", window.State(), DeviceStatePASEEstablished)
		}

		cancel()
		time.Sleep(10 * time.Millisecond)
	})
}

func TestCommissioningWindowClose(t *testing.T) {
	config := CommissioningWindowConfig{
		Timeout:    5 * time.Second,
		Iterations: 1000,
	}

	window, err := NewCommissioningWindow(config)
	if err != nil {
		t.Fatalf("NewCommissioningWindow() error: %v", err)
	}

	// Open in background
	ctx := context.Background()
	errCh := make(chan error, 1)
	go func() {
		errCh <- window.Open(ctx)
	}()

	// Wait for advertising
	time.Sleep(10 * time.Millisecond)

	// Close the window
	if err := window.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}

	// Open should return
	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("Open() returned with: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Open() did not return after Close()")
	}
}

func TestCommissioningWindowTimeout(t *testing.T) {
	config := CommissioningWindowConfig{
		Timeout:    50 * time.Millisecond,
		Iterations: 1000,
	}

	window, err := NewCommissioningWindow(config)
	if err != nil {
		t.Fatalf("NewCommissioningWindow() error: %v", err)
	}

	ctx := context.Background()
	err = window.Open(ctx)

	if err != ErrCommissioningTimeout {
		t.Errorf("Open() error = %v, want %v", err, ErrCommissioningTimeout)
	}
}

func TestFailSafeTimer(t *testing.T) {
	t.Run("basic arm and disarm", func(t *testing.T) {
		var expired atomic.Bool
		timer := NewFailSafeTimer(func() {
			expired.Store(true)
		})

		if timer.IsArmed() {
			t.Error("IsArmed() = true before Arm()")
		}

		timer.Arm(100 * time.Millisecond)

		if !timer.IsArmed() {
			t.Error("IsArmed() = false after Arm()")
		}

		remaining := timer.RemainingTime()
		if remaining <= 0 || remaining > 100*time.Millisecond {
			t.Errorf("RemainingTime() = %v, want 0-100ms", remaining)
		}

		timer.Disarm()

		if timer.IsArmed() {
			t.Error("IsArmed() = true after Disarm()")
		}

		// Wait to ensure callback doesn't fire
		time.Sleep(150 * time.Millisecond)

		if expired.Load() {
			t.Error("Timer expired after Disarm()")
		}
	})

	t.Run("expiration callback", func(t *testing.T) {
		var expired atomic.Bool
		timer := NewFailSafeTimer(func() {
			expired.Store(true)
		})

		timer.Arm(50 * time.Millisecond)

		// Wait for expiration
		time.Sleep(100 * time.Millisecond)

		if !expired.Load() {
			t.Error("Timer callback not called after expiration")
		}

		if timer.IsArmed() {
			t.Error("IsArmed() = true after expiration")
		}
	})

	t.Run("re-arm resets timer", func(t *testing.T) {
		var expired atomic.Bool
		timer := NewFailSafeTimer(func() {
			expired.Store(true)
		})

		timer.Arm(50 * time.Millisecond)

		// Wait 30ms then re-arm
		time.Sleep(30 * time.Millisecond)
		timer.Arm(100 * time.Millisecond)

		// Wait 60ms (would have expired with original 50ms)
		time.Sleep(60 * time.Millisecond)

		if expired.Load() {
			t.Error("Timer expired before re-armed timeout")
		}

		// Now wait for actual expiration
		time.Sleep(60 * time.Millisecond)

		if !expired.Load() {
			t.Error("Timer callback not called after re-armed expiration")
		}
	})
}

func TestCommissioningWindowArmFailSafe(t *testing.T) {
	config := CommissioningWindowConfig{
		Timeout:    1 * time.Second,
		Iterations: 1000,
	}

	window, err := NewCommissioningWindow(config)
	if err != nil {
		t.Fatalf("NewCommissioningWindow() error: %v", err)
	}

	// Open in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go window.Open(ctx)

	time.Sleep(10 * time.Millisecond)

	// Accept PASE
	window.OnPASERequest()
	window.OnPASEComplete(nil)

	// Arm fail-safe
	window.ArmFailSafe(500 * time.Millisecond)

	if window.State() != DeviceStateCommissioning {
		t.Errorf("State after ArmFailSafe() = %v, want %v", window.State(), DeviceStateCommissioning)
	}

	// Disarm before expiration
	window.DisarmFailSafe()
}
