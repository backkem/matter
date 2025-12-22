package webrtctransport

import (
	"context"
	"testing"

	"github.com/backkem/matter/pkg/datamodel"
)

// mockRequestorDelegate implements RequestorDelegate for testing.
type mockRequestorDelegate struct {
	onOffer         func(ctx context.Context, sessionID uint16, sdp string, iceServers []ICEServerStruct, iceTransportPolicy string) error
	onAnswer        func(ctx context.Context, sessionID uint16, sdp string) error
	onICECandidates func(ctx context.Context, sessionID uint16, candidates []ICECandidateStruct) error
	onEnd           func(ctx context.Context, sessionID uint16, reason WebRTCEndReasonEnum) error
}

func (m *mockRequestorDelegate) OnOffer(ctx context.Context, sessionID uint16, sdp string, iceServers []ICEServerStruct, iceTransportPolicy string) error {
	if m.onOffer != nil {
		return m.onOffer(ctx, sessionID, sdp, iceServers, iceTransportPolicy)
	}
	return nil
}

func (m *mockRequestorDelegate) OnAnswer(ctx context.Context, sessionID uint16, sdp string) error {
	if m.onAnswer != nil {
		return m.onAnswer(ctx, sessionID, sdp)
	}
	return nil
}

func (m *mockRequestorDelegate) OnICECandidates(ctx context.Context, sessionID uint16, candidates []ICECandidateStruct) error {
	if m.onICECandidates != nil {
		return m.onICECandidates(ctx, sessionID, candidates)
	}
	return nil
}

func (m *mockRequestorDelegate) OnEnd(ctx context.Context, sessionID uint16, reason WebRTCEndReasonEnum) error {
	if m.onEnd != nil {
		return m.onEnd(ctx, sessionID, reason)
	}
	return nil
}

func TestRequestor_NewRequestor(t *testing.T) {
	cfg := RequestorConfig{
		EndpointID: 2,
		Delegate:   &mockRequestorDelegate{},
	}

	r := NewRequestor(cfg)

	if r == nil {
		t.Fatal("expected non-nil Requestor")
	}
	if r.ID() != datamodel.ClusterID(RequestorClusterID) {
		t.Errorf("expected cluster ID %x, got %x", RequestorClusterID, r.ID())
	}
	if r.EndpointID() != datamodel.EndpointID(2) {
		t.Errorf("expected endpoint ID 2, got %d", r.EndpointID())
	}
}

func TestRequestor_AcceptedCommandList(t *testing.T) {
	r := NewRequestor(RequestorConfig{EndpointID: 1})

	commands := r.AcceptedCommandList()

	expectedCmds := []uint32{
		CmdOffer,
		CmdAnswer,
		CmdICECandidates,
		CmdEnd,
	}

	if len(commands) != len(expectedCmds) {
		t.Fatalf("expected %d commands, got %d", len(expectedCmds), len(commands))
	}

	for i, cmd := range expectedCmds {
		if uint32(commands[i].ID) != cmd {
			t.Errorf("command %d: expected %x, got %x", i, cmd, commands[i].ID)
		}
	}
}

func TestRequestor_GeneratedCommandList(t *testing.T) {
	r := NewRequestor(RequestorConfig{EndpointID: 1})

	commands := r.GeneratedCommandList()

	if len(commands) != 0 {
		t.Errorf("expected no generated commands, got %d", len(commands))
	}
}

func TestRequestor_SessionManagement(t *testing.T) {
	r := NewRequestor(RequestorConfig{EndpointID: 1})

	// Initially no sessions
	if session := r.GetSession(0); session != nil {
		t.Error("expected no session initially")
	}

	// Add a session
	session := &WebRTCSessionStruct{
		ID:          100,
		PeerNodeID:  67890,
		StreamUsage: StreamUsageAnalysis,
		FabricIndex: 1,
	}
	r.AddSession(session)

	// Retrieve session
	retrieved := r.GetSession(100)
	if retrieved == nil {
		t.Fatal("expected to retrieve session")
	}
	if retrieved.PeerNodeID != 67890 {
		t.Errorf("expected peer node ID 67890, got %d", retrieved.PeerNodeID)
	}
	if retrieved.StreamUsage != StreamUsageAnalysis {
		t.Errorf("expected stream usage Analysis, got %v", retrieved.StreamUsage)
	}

	// Remove session
	r.RemoveSession(100)

	// Session should be gone
	if session := r.GetSession(100); session != nil {
		t.Error("expected session to be removed")
	}
}

func TestRequestor_AddMultipleSessions(t *testing.T) {
	r := NewRequestor(RequestorConfig{EndpointID: 1})

	sessions := []*WebRTCSessionStruct{
		{ID: 1, PeerNodeID: 100, FabricIndex: 1},
		{ID: 2, PeerNodeID: 200, FabricIndex: 1},
		{ID: 3, PeerNodeID: 300, FabricIndex: 2},
	}

	for _, s := range sessions {
		r.AddSession(s)
	}

	// Verify all sessions exist
	for _, expected := range sessions {
		retrieved := r.GetSession(expected.ID)
		if retrieved == nil {
			t.Errorf("session %d not found", expected.ID)
			continue
		}
		if retrieved.PeerNodeID != expected.PeerNodeID {
			t.Errorf("session %d: expected peer %d, got %d", expected.ID, expected.PeerNodeID, retrieved.PeerNodeID)
		}
	}

	// Remove one session
	r.RemoveSession(2)

	// Verify removal
	if r.GetSession(2) != nil {
		t.Error("session 2 should be removed")
	}
	if r.GetSession(1) == nil {
		t.Error("session 1 should still exist")
	}
	if r.GetSession(3) == nil {
		t.Error("session 3 should still exist")
	}
}
