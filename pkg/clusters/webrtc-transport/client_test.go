package webrtctransport

import (
	"bytes"
	"testing"

	"github.com/backkem/matter/pkg/tlv"
)

func TestEncodeProvideOffer(t *testing.T) {
	tests := []struct {
		name               string
		sessionID          *uint16
		sdp                string
		streamUsage        StreamUsageEnum
		originatingEP      uint16
		videoStreamID      *uint16
		audioStreamID      *uint16
		iceServers         []ICEServerStruct
		iceTransportPolicy string
		metadataEnabled    bool
	}{
		{
			name:            "new session basic",
			sessionID:       nil,
			sdp:             "v=0\r\no=- 123 1 IN IP4 127.0.0.1\r\n",
			streamUsage:     StreamUsageInternal,
			originatingEP:   1,
			metadataEnabled: false,
		},
		{
			name:               "re-offer with streams",
			sessionID:          ptrUint16(42),
			sdp:                "v=0\r\ntest sdp",
			streamUsage:        StreamUsageAnalysis,
			originatingEP:      2,
			videoStreamID:      ptrUint16(10),
			audioStreamID:      ptrUint16(20),
			iceTransportPolicy: "all",
			metadataEnabled:    true,
		},
		{
			name:        "with ICE servers",
			sessionID:   nil,
			sdp:         "v=0\r\nsdp",
			streamUsage: StreamUsageInternal,
			iceServers: []ICEServerStruct{
				{
					URLs:       []string{"stun:stun.example.com:3478"},
					Username:   ptrString("user"),
					Credential: ptrString("pass"),
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := EncodeProvideOffer(tc.sessionID, tc.sdp, tc.streamUsage, tc.originatingEP,
				tc.videoStreamID, tc.audioStreamID, tc.iceServers, tc.iceTransportPolicy, tc.metadataEnabled)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify we can parse the encoded data
			r := tlv.NewReader(bytes.NewReader(data))
			if err := r.Next(); err != nil {
				t.Fatalf("failed to read: %v", err)
			}
			if r.Type() != tlv.ElementTypeStruct {
				t.Fatalf("expected struct, got %v", r.Type())
			}
		})
	}
}

func TestEncodeProvideAnswer(t *testing.T) {
	data, err := EncodeProvideAnswer(123, "v=0\r\nanswer sdp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse and verify
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	if r.Type() != tlv.ElementTypeStruct {
		t.Fatalf("expected struct, got %v", r.Type())
	}
	if err := r.EnterContainer(); err != nil {
		t.Fatalf("failed to enter container: %v", err)
	}

	var sessionID uint16
	var sdp string

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
			sdp, _ = r.String()
		}
	}

	if sessionID != 123 {
		t.Errorf("expected session ID 123, got %d", sessionID)
	}
	if sdp != "v=0\r\nanswer sdp" {
		t.Errorf("unexpected SDP: %s", sdp)
	}
}

func TestEncodeProvideICECandidates(t *testing.T) {
	candidates := []ICECandidateStruct{
		{
			Candidate:     "candidate:1 1 udp 2122260223 192.168.1.1 12345 typ host",
			SDPMid:        ptrString("0"),
			SDPMLineIndex: ptrUint16(0),
		},
		{
			Candidate:     "candidate:2 1 udp 2122194687 10.0.0.1 54321 typ srflx",
			SDPMid:        nil,
			SDPMLineIndex: nil,
		},
	}

	data, err := EncodeProvideICECandidates(42, candidates)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify structure
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	if r.Type() != tlv.ElementTypeStruct {
		t.Fatalf("expected struct, got %v", r.Type())
	}
}

func TestEncodeEndSession(t *testing.T) {
	data, err := EncodeEndSession(99, WebRTCEndReasonOutOfResources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse and verify
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	if r.Type() != tlv.ElementTypeStruct {
		t.Fatalf("expected struct, got %v", r.Type())
	}
	if err := r.EnterContainer(); err != nil {
		t.Fatalf("failed to enter container: %v", err)
	}

	var sessionID uint16
	var reason WebRTCEndReasonEnum

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
			val, _ := r.Uint()
			reason = WebRTCEndReasonEnum(val)
		}
	}

	if sessionID != 99 {
		t.Errorf("expected session ID 99, got %d", sessionID)
	}
	if reason != WebRTCEndReasonOutOfResources {
		t.Errorf("expected reason OutOfResources, got %v", reason)
	}
}

func TestEncodeOffer(t *testing.T) {
	iceServers := []ICEServerStruct{
		{URLs: []string{"stun:stun.l.google.com:19302"}},
	}

	data, err := EncodeOffer(1, "v=0\r\noffer", iceServers, "relay")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify structure
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	if r.Type() != tlv.ElementTypeStruct {
		t.Fatalf("expected struct, got %v", r.Type())
	}
}

func TestEncodeAnswer(t *testing.T) {
	data, err := EncodeAnswer(50, "v=0\r\nanswer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify structure
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	if r.Type() != tlv.ElementTypeStruct {
		t.Fatalf("expected struct, got %v", r.Type())
	}
}

func TestEncodeICECandidates(t *testing.T) {
	candidates := []ICECandidateStruct{
		{
			Candidate: "candidate:0 1 udp 2113937151 192.168.1.1 12345 typ host",
		},
	}

	data, err := EncodeICECandidates(77, candidates)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify structure
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	if r.Type() != tlv.ElementTypeStruct {
		t.Fatalf("expected struct, got %v", r.Type())
	}
}

func TestEncodeEnd(t *testing.T) {
	data, err := EncodeEnd(88, WebRTCEndReasonICETimeout)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse and verify
	r := tlv.NewReader(bytes.NewReader(data))
	if err := r.Next(); err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	if r.Type() != tlv.ElementTypeStruct {
		t.Fatalf("expected struct, got %v", r.Type())
	}
}

// Helper functions
func ptrUint16(v uint16) *uint16 {
	return &v
}

func ptrString(s string) *string {
	return &s
}
