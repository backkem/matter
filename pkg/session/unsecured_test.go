package session

import (
	"testing"

	"github.com/backkem/matter/pkg/fabric"
)

func TestNewUnsecuredContext(t *testing.T) {
	t.Run("initiator generates ephemeral node ID", func(t *testing.T) {
		ctx, err := NewUnsecuredContext(SessionRoleInitiator)
		if err != nil {
			t.Fatalf("NewUnsecuredContext() error = %v", err)
		}

		nodeID := ctx.EphemeralNodeID()
		if !nodeID.IsOperational() {
			t.Errorf("EphemeralNodeID() = %v, not in operational range", nodeID)
		}
	})

	t.Run("responder generates ephemeral node ID", func(t *testing.T) {
		ctx, err := NewUnsecuredContext(SessionRoleResponder)
		if err != nil {
			t.Fatalf("NewUnsecuredContext() error = %v", err)
		}

		nodeID := ctx.EphemeralNodeID()
		if !nodeID.IsOperational() {
			t.Errorf("EphemeralNodeID() = %v, not in operational range", nodeID)
		}
	})

	t.Run("invalid role returns error", func(t *testing.T) {
		_, err := NewUnsecuredContext(SessionRoleUnknown)
		if err != ErrInvalidRole {
			t.Errorf("NewUnsecuredContext() error = %v, want %v", err, ErrInvalidRole)
		}
	})
}

func TestUnsecuredContext_Role(t *testing.T) {
	ctx, _ := NewUnsecuredContext(SessionRoleInitiator)
	if ctx.Role() != SessionRoleInitiator {
		t.Errorf("Role() = %v, want %v", ctx.Role(), SessionRoleInitiator)
	}
}

func TestUnsecuredContext_SetPeerEphemeralNodeID(t *testing.T) {
	ctx, _ := NewUnsecuredContext(SessionRoleResponder)

	testNodeID := fabric.NodeID(0x1234567890ABCDEF)
	ctx.SetPeerEphemeralNodeID(testNodeID)

	if ctx.PeerEphemeralNodeID() != testNodeID {
		t.Errorf("PeerEphemeralNodeID() = %v, want %v", ctx.PeerEphemeralNodeID(), testNodeID)
	}
}

func TestUnsecuredContext_CheckCounter(t *testing.T) {
	ctx, _ := NewUnsecuredContext(SessionRoleInitiator)

	// First counter should always be accepted
	if !ctx.CheckCounter(100) {
		t.Error("CheckCounter(100) first time should be accepted")
	}

	// Same counter should be rejected (replay)
	if ctx.CheckCounter(100) {
		t.Error("CheckCounter(100) duplicate should be rejected")
	}

	// Higher counter should be accepted
	if !ctx.CheckCounter(101) {
		t.Error("CheckCounter(101) higher counter should be accepted")
	}

	// Much higher counter should be accepted
	if !ctx.CheckCounter(200) {
		t.Error("CheckCounter(200) should be accepted")
	}
}

func TestUnsecuredContext_Params(t *testing.T) {
	ctx, _ := NewUnsecuredContext(SessionRoleInitiator)

	// Default params
	params := ctx.GetParams()
	if params.IdleInterval != DefaultIdleInterval {
		t.Errorf("GetParams().IdleInterval = %v, want %v", params.IdleInterval, DefaultIdleInterval)
	}

	// Set custom params
	custom := Params{
		IdleInterval:    1000,
		ActiveInterval:  500,
		ActiveThreshold: 2000,
	}
	ctx.SetParams(custom)

	params = ctx.GetParams()
	if params.IdleInterval != custom.IdleInterval {
		t.Errorf("GetParams().IdleInterval = %v, want %v", params.IdleInterval, custom.IdleInterval)
	}
}

func TestGenerateEphemeralNodeID_Uniqueness(t *testing.T) {
	// Generate multiple IDs and check they're all unique and valid
	ids := make(map[fabric.NodeID]bool)
	iterations := 100

	for i := 0; i < iterations; i++ {
		nodeID, err := generateEphemeralNodeID()
		if err != nil {
			t.Fatalf("generateEphemeralNodeID() error = %v", err)
		}

		if !nodeID.IsOperational() {
			t.Errorf("generateEphemeralNodeID() = %v, not in operational range", nodeID)
		}

		if ids[nodeID] {
			t.Errorf("generateEphemeralNodeID() generated duplicate: %v", nodeID)
		}
		ids[nodeID] = true
	}
}
