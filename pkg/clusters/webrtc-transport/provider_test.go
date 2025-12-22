package webrtctransport

import (
	"bytes"
	"context"
	"testing"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/tlv"
)

// mockProviderDelegate implements ProviderDelegate for testing.
type mockProviderDelegate struct {
	onSolicitOffer  func(ctx context.Context, req *SolicitOfferRequest) (bool, error)
	onOfferReceived func(ctx context.Context, req *ProvideOfferRequest) (*ProvideOfferResult, error)
	onAnswerReceived func(ctx context.Context, sessionID uint16, sdp string) error
	onICECandidates func(ctx context.Context, sessionID uint16, candidates []ICECandidateStruct) error
	onSessionEnded  func(ctx context.Context, sessionID uint16, reason WebRTCEndReasonEnum) error
}

func (m *mockProviderDelegate) OnSolicitOffer(ctx context.Context, req *SolicitOfferRequest) (bool, error) {
	if m.onSolicitOffer != nil {
		return m.onSolicitOffer(ctx, req)
	}
	return false, nil
}

func (m *mockProviderDelegate) OnOfferReceived(ctx context.Context, req *ProvideOfferRequest) (*ProvideOfferResult, error) {
	if m.onOfferReceived != nil {
		return m.onOfferReceived(ctx, req)
	}
	return &ProvideOfferResult{
		AnswerSDP: "v=0\r\ntest answer",
	}, nil
}

func (m *mockProviderDelegate) OnAnswerReceived(ctx context.Context, sessionID uint16, sdp string) error {
	if m.onAnswerReceived != nil {
		return m.onAnswerReceived(ctx, sessionID, sdp)
	}
	return nil
}

func (m *mockProviderDelegate) OnICECandidates(ctx context.Context, sessionID uint16, candidates []ICECandidateStruct) error {
	if m.onICECandidates != nil {
		return m.onICECandidates(ctx, sessionID, candidates)
	}
	return nil
}

func (m *mockProviderDelegate) OnSessionEnded(ctx context.Context, sessionID uint16, reason WebRTCEndReasonEnum) error {
	if m.onSessionEnded != nil {
		return m.onSessionEnded(ctx, sessionID, reason)
	}
	return nil
}

func TestProvider_NewProvider(t *testing.T) {
	cfg := ProviderConfig{
		EndpointID: 1,
		Delegate:   &mockProviderDelegate{},
	}

	p := NewProvider(cfg)

	if p == nil {
		t.Fatal("expected non-nil Provider")
	}
	if p.ID() != datamodel.ClusterID(ProviderClusterID) {
		t.Errorf("expected cluster ID %x, got %x", ProviderClusterID, p.ID())
	}
	if p.EndpointID() != datamodel.EndpointID(1) {
		t.Errorf("expected endpoint ID 1, got %d", p.EndpointID())
	}
}

func TestProvider_AcceptedCommandList(t *testing.T) {
	p := NewProvider(ProviderConfig{EndpointID: 1})

	commands := p.AcceptedCommandList()

	expectedCmds := []uint32{
		CmdSolicitOffer,
		CmdProvideOffer,
		CmdProvideAnswer,
		CmdProvideICECandidates,
		CmdEndSession,
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

func TestProvider_GeneratedCommandList(t *testing.T) {
	p := NewProvider(ProviderConfig{EndpointID: 1})

	commands := p.GeneratedCommandList()

	expectedCmds := []uint32{
		CmdSolicitOfferResponse,
		CmdProvideOfferResponse,
	}

	if len(commands) != len(expectedCmds) {
		t.Fatalf("expected %d commands, got %d", len(expectedCmds), len(commands))
	}

	for i, cmd := range expectedCmds {
		if uint32(commands[i]) != cmd {
			t.Errorf("command %d: expected %x, got %x", i, cmd, commands[i])
		}
	}
}

func TestProvider_SessionManagement(t *testing.T) {
	p := NewProvider(ProviderConfig{EndpointID: 1})

	// Initially no sessions
	if session := p.GetSession(0); session != nil {
		t.Error("expected no session initially")
	}

	// Add a session directly (simulating handleSolicitOffer)
	session := &WebRTCSessionStruct{
		ID:          42,
		PeerNodeID:  12345,
		StreamUsage: StreamUsageInternal,
		FabricIndex: 1,
	}
	p.mu.Lock()
	p.sessions[session.ID] = session
	p.mu.Unlock()

	// Retrieve session
	retrieved := p.GetSession(42)
	if retrieved == nil {
		t.Fatal("expected to retrieve session")
	}
	if retrieved.PeerNodeID != 12345 {
		t.Errorf("expected peer node ID 12345, got %d", retrieved.PeerNodeID)
	}

	// End session
	err := p.EndSession(context.Background(), 42, WebRTCEndReasonUserHangup)
	if err != nil {
		t.Fatalf("unexpected error ending session: %v", err)
	}

	// Session should be removed
	if session := p.GetSession(42); session != nil {
		t.Error("expected session to be removed after EndSession")
	}

	// End non-existent session should fail
	err = p.EndSession(context.Background(), 99, WebRTCEndReasonUserHangup)
	if err != ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestProvider_AllocateSessionID(t *testing.T) {
	p := NewProvider(ProviderConfig{EndpointID: 1})

	// Allocate several IDs
	ids := make(map[uint16]bool)
	for i := 0; i < 100; i++ {
		id := p.allocateSessionID()
		if ids[id] {
			t.Errorf("duplicate session ID allocated: %d", id)
		}
		ids[id] = true

		// Mark the session as in-use
		p.mu.Lock()
		p.sessions[id] = &WebRTCSessionStruct{ID: id}
		p.mu.Unlock()
	}
}

func TestEncodeSolicitOfferResponse(t *testing.T) {
	videoID := uint16(10)
	audioID := uint16(20)

	data, err := encodeSolicitOfferResponse(42, true, &videoID, &audioID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Decode and verify
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read structure: %v", err)
	}
	if r.Type() != tlv.ElementTypeStruct {
		t.Fatalf("expected struct, got %v", r.Type())
	}
	if err := r.EnterContainer(); err != nil {
		t.Fatalf("failed to enter container: %v", err)
	}

	var sessionID uint16
	var deferredOffer bool
	var gotVideoID, gotAudioID *uint16

	for {
		if err := r.Next(); err != nil {
			break
		}
		if r.Type() == tlv.ElementTypeEnd {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			continue
		}

		switch tag.TagNumber() {
		case 0:
			val, _ := r.Uint()
			sessionID = uint16(val)
		case 1:
			deferredOffer, _ = r.Bool()
		case 2:
			if r.Type() != tlv.ElementTypeNull {
				val, _ := r.Uint()
				id := uint16(val)
				gotVideoID = &id
			}
		case 3:
			if r.Type() != tlv.ElementTypeNull {
				val, _ := r.Uint()
				id := uint16(val)
				gotAudioID = &id
			}
		}
	}

	if sessionID != 42 {
		t.Errorf("expected session ID 42, got %d", sessionID)
	}
	if !deferredOffer {
		t.Error("expected deferredOffer to be true")
	}
	if gotVideoID == nil || *gotVideoID != 10 {
		t.Errorf("expected video ID 10, got %v", gotVideoID)
	}
	if gotAudioID == nil || *gotAudioID != 20 {
		t.Errorf("expected audio ID 20, got %v", gotAudioID)
	}
}

func TestEncodeProvideOfferResponse(t *testing.T) {
	videoID := uint16(5)

	data, err := encodeProvideOfferResponse(123, &videoID, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Decode
	sessionID, gotVideoID, gotAudioID, err := DecodeProvideOfferResponse(data)
	if err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}

	if sessionID != 123 {
		t.Errorf("expected session ID 123, got %d", sessionID)
	}
	if gotVideoID == nil || *gotVideoID != 5 {
		t.Errorf("expected video ID 5, got %v", gotVideoID)
	}
	if gotAudioID != nil {
		t.Errorf("expected nil audio ID, got %v", gotAudioID)
	}
}
