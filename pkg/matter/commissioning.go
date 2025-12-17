package matter

import (
	"context"
	"time"

	"github.com/backkem/matter/pkg/commissioning"
	"github.com/backkem/matter/pkg/discovery"
	"github.com/backkem/matter/pkg/session"
)

// OpenCommissioningWindow opens a commissioning window for pairing.
// The window closes automatically after the timeout or when CloseCommissioningWindow is called.
//
// For uncommissioned devices, a commissioning window is opened automatically on Start().
func (n *Node) OpenCommissioningWindow(timeout time.Duration) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.state.IsRunning() {
		return ErrNotStarted
	}

	return n.openCommissioningWindowLocked(timeout)
}

// openCommissioningWindowLocked opens a commissioning window.
// Caller must hold n.mu.
func (n *Node) openCommissioningWindowLocked(timeout time.Duration) error {
	if n.commWindow != nil {
		return ErrCommissioningWindowOpen
	}

	// Create commissioning window
	var err error
	n.commWindow, err = commissioning.NewCommissioningWindow(commissioning.CommissioningWindowConfig{
		Timeout:       timeout,
		Discriminator: n.config.Discriminator,
		VendorID:      uint16(n.config.VendorID),
		ProductID:     n.config.ProductID,
		DeviceName:    n.config.DeviceName,
		Verifier:      n.paseInfo.verifier,
		Salt:          n.paseInfo.salt,
		Iterations:    n.paseInfo.iterations,
		OnStateChanged: func(state commissioning.DeviceCommissioningState) {
			n.onCommissioningStateChanged(state)
		},
		OnPASEEstablished: func(sess *session.SecureContext) {
			// PASE session established
		},
		OnCommissioningComplete: func() {
			n.onCommissioningComplete()
		},
		OnWindowClosed: func(reason error) {
			n.onCommissioningWindowClosed(reason)
		},
	})
	if err != nil {
		return err
	}

	// Configure PASE responder in secure channel manager
	if n.scMgr != nil {
		if err := n.scMgr.SetPASEResponder(n.paseInfo.verifier, n.paseInfo.salt, n.paseInfo.iterations); err != nil {
			n.commWindow.Close()
			n.commWindow = nil
			return err
		}
	}

	// Start advertising as commissionable
	n.advertiseCommissionable()

	// Update state
	if n.state == NodeStateUncommissioned {
		n.state = NodeStateCommissioningOpen
		if n.config.OnStateChanged != nil {
			n.config.OnStateChanged(n.state)
		}
	}

	// Start the commissioning window in background
	// Capture commWindow to avoid race if Stop() is called
	cw := n.commWindow
	go func() {
		ctx, cancel := context.WithCancel(n.ctx)
		defer cancel()
		cw.Open(ctx)
	}()

	return nil
}

// CloseCommissioningWindow closes any open commissioning window.
func (n *Node) CloseCommissioningWindow() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.commWindow == nil {
		return ErrCommissioningWindowClosed
	}

	n.commWindow.Close()
	n.commWindow = nil

	// Clear PASE responder from secure channel manager
	if n.scMgr != nil {
		n.scMgr.ClearPASEResponder()
	}

	// Stop commissionable advertising
	if n.discoveryMgr != nil {
		n.discoveryMgr.StopAdvertising(discovery.ServiceTypeCommissionable)
	}

	// Update state
	if n.state == NodeStateCommissioningOpen {
		if n.fabricTable.Count() > 0 {
			n.state = NodeStateCommissioned
		} else {
			n.state = NodeStateUncommissioned
		}
		if n.config.OnStateChanged != nil {
			n.config.OnStateChanged(n.state)
		}
	}

	return nil
}

// advertiseCommissionable starts DNS-SD advertising as commissionable.
func (n *Node) advertiseCommissionable() {
	if n.discoveryMgr == nil {
		return
	}

	txt := discovery.CommissionableTXT{
		Discriminator:     n.config.Discriminator,
		VendorID:          n.config.VendorID,
		ProductID:         n.config.ProductID,
		DeviceName:        n.config.DeviceName,
		CommissioningMode: discovery.CommissioningModeBasic,
	}

	n.discoveryMgr.StartCommissionable(txt)
}

// onCommissioningStateChanged handles commissioning state changes.
func (n *Node) onCommissioningStateChanged(state commissioning.DeviceCommissioningState) {
	// Notify callback
	if n.config.OnCommissioningStart != nil && state == commissioning.DeviceStatePASEPending {
		n.config.OnCommissioningStart()
	}
}

// onCommissioningComplete handles successful commissioning.
func (n *Node) onCommissioningComplete() {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Close commissioning window
	if n.commWindow != nil {
		n.commWindow = nil
	}

	// Clear PASE responder from secure channel manager
	if n.scMgr != nil {
		n.scMgr.ClearPASEResponder()
	}

	// Stop commissionable advertising
	if n.discoveryMgr != nil {
		n.discoveryMgr.StopAdvertising(discovery.ServiceTypeCommissionable)
	}

	// Start operational advertising
	n.advertiseOperational()

	// Update state
	n.state = NodeStateCommissioned
	if n.config.OnStateChanged != nil {
		n.config.OnStateChanged(n.state)
	}

	// Notify callback with fabric index
	// TODO: Get fabric index from commissioning flow
	if n.config.OnCommissioningComplete != nil {
		n.config.OnCommissioningComplete(1) // Placeholder fabric index
	}
}

// onCommissioningWindowClosed handles window closure.
func (n *Node) onCommissioningWindowClosed(reason error) {
	// Use TryLock to avoid deadlock if called during Stop()
	if !n.mu.TryLock() {
		// Already being shut down
		return
	}
	defer n.mu.Unlock()

	// Already cleaned up (e.g., by Stop())
	if n.commWindow == nil {
		return
	}
	n.commWindow = nil

	// Clear PASE responder from secure channel manager
	if n.scMgr != nil {
		n.scMgr.ClearPASEResponder()
	}

	// Stop commissionable advertising
	if n.discoveryMgr != nil {
		n.discoveryMgr.StopAdvertising(discovery.ServiceTypeCommissionable)
	}

	// Update state
	if n.state == NodeStateCommissioningOpen {
		if n.fabricTable.Count() > 0 {
			n.state = NodeStateCommissioned
		} else {
			n.state = NodeStateUncommissioned
		}
		if n.config.OnStateChanged != nil {
			n.config.OnStateChanged(n.state)
		}
	}
}

// IsCommissioningWindowOpen returns true if a commissioning window is open.
func (n *Node) IsCommissioningWindowOpen() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.commWindow != nil
}

// CommissioningWindowTimeout returns the remaining time in the commissioning window.
// Returns 0 if no window is open.
func (n *Node) CommissioningWindowTimeout() time.Duration {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if n.commWindow == nil {
		return 0
	}

	// The commissioning window tracks this internally
	// For now, return 0 - would need to expose this from CommissioningWindow
	return 0
}
