package matter

// NodeState represents the lifecycle state of a Matter Node.
type NodeState int

const (
	// NodeStateUninitialized is the initial state before NewNode completes.
	NodeStateUninitialized NodeState = iota

	// NodeStateInitialized means the node is created but not started.
	NodeStateInitialized

	// NodeStateStarting means Start() has been called and initialization is in progress.
	NodeStateStarting

	// NodeStateUncommissioned means the node is running but not commissioned to any fabric.
	// The node is advertising via DNS-SD as commissionable.
	NodeStateUncommissioned

	// NodeStateCommissioningOpen means a commissioning window is currently open.
	NodeStateCommissioningOpen

	// NodeStateCommissioned means the node is commissioned to at least one fabric.
	// The node is advertising via DNS-SD as operational.
	NodeStateCommissioned

	// NodeStateStopping means Stop() has been called and shutdown is in progress.
	NodeStateStopping

	// NodeStateStopped means the node has been shut down.
	NodeStateStopped
)

// String returns a human-readable name for the state.
func (s NodeState) String() string {
	switch s {
	case NodeStateUninitialized:
		return "Uninitialized"
	case NodeStateInitialized:
		return "Initialized"
	case NodeStateStarting:
		return "Starting"
	case NodeStateUncommissioned:
		return "Uncommissioned"
	case NodeStateCommissioningOpen:
		return "CommissioningOpen"
	case NodeStateCommissioned:
		return "Commissioned"
	case NodeStateStopping:
		return "Stopping"
	case NodeStateStopped:
		return "Stopped"
	default:
		return "Unknown"
	}
}

// IsRunning returns true if the node is in an operational state.
func (s NodeState) IsRunning() bool {
	switch s {
	case NodeStateUncommissioned, NodeStateCommissioningOpen, NodeStateCommissioned:
		return true
	default:
		return false
	}
}

// CanStart returns true if Start() can be called in this state.
func (s NodeState) CanStart() bool {
	return s == NodeStateInitialized
}

// CanStop returns true if Stop() can be called in this state.
func (s NodeState) CanStop() bool {
	return s.IsRunning() || s == NodeStateStarting
}
