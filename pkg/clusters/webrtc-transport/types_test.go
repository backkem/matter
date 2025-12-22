package webrtctransport

import (
	"bytes"
	"testing"

	"github.com/backkem/matter/pkg/tlv"
)

func TestStreamUsageEnum_String(t *testing.T) {
	tests := []struct {
		val  StreamUsageEnum
		want string
	}{
		{StreamUsageInternal, "Internal"},
		{StreamUsageRecording, "Recording"},
		{StreamUsageAnalysis, "Analysis"},
		{StreamUsageLiveView, "LiveView"},
		{StreamUsageEnum(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.val.String(); got != tt.want {
			t.Errorf("StreamUsageEnum(%d).String() = %q, want %q", tt.val, got, tt.want)
		}
	}
}

func TestStreamUsageEnum_IsValid(t *testing.T) {
	tests := []struct {
		val  StreamUsageEnum
		want bool
	}{
		{StreamUsageInternal, true},
		{StreamUsageLiveView, true},
		{StreamUsageEnum(4), false},
		{StreamUsageEnum(255), false},
	}

	for _, tt := range tests {
		if got := tt.val.IsValid(); got != tt.want {
			t.Errorf("StreamUsageEnum(%d).IsValid() = %v, want %v", tt.val, got, tt.want)
		}
	}
}

func TestWebRTCEndReasonEnum_String(t *testing.T) {
	tests := []struct {
		val  WebRTCEndReasonEnum
		want string
	}{
		{WebRTCEndReasonICEFailed, "ICEFailed"},
		{WebRTCEndReasonUserHangup, "UserHangup"},
		{WebRTCEndReasonOutOfResources, "OutOfResources"},
		{WebRTCEndReasonUnknownReason, "UnknownReason"},
		{WebRTCEndReasonEnum(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.val.String(); got != tt.want {
			t.Errorf("WebRTCEndReasonEnum(%d).String() = %q, want %q", tt.val, got, tt.want)
		}
	}
}

func TestWebRTCEndReasonEnum_IsValid(t *testing.T) {
	tests := []struct {
		val  WebRTCEndReasonEnum
		want bool
	}{
		{WebRTCEndReasonICEFailed, true},
		{WebRTCEndReasonUnknownReason, true},
		{WebRTCEndReasonEnum(13), false},
		{WebRTCEndReasonEnum(255), false},
	}

	for _, tt := range tests {
		if got := tt.val.IsValid(); got != tt.want {
			t.Errorf("WebRTCEndReasonEnum(%d).IsValid() = %v, want %v", tt.val, got, tt.want)
		}
	}
}

func TestICEServerStruct_TLVRoundtrip(t *testing.T) {
	username := "testuser"
	credential := "testpass"
	caid := uint16(1234)

	tests := []struct {
		name string
		s    ICEServerStruct
	}{
		{
			name: "full",
			s: ICEServerStruct{
				URLs:       []string{"stun:stun.example.com:3478", "turn:turn.example.com:3478"},
				Username:   &username,
				Credential: &credential,
				CAID:       &caid,
			},
		},
		{
			name: "minimal",
			s: ICEServerStruct{
				URLs: []string{"stun:stun.l.google.com:19302"},
			},
		},
		{
			name: "empty_urls",
			s: ICEServerStruct{
				URLs: []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)
			if err := tt.s.MarshalTLV(w); err != nil {
				t.Fatalf("MarshalTLV failed: %v", err)
			}

			// Decode
			r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
			var decoded ICEServerStruct
			if err := decoded.UnmarshalTLV(r); err != nil {
				t.Fatalf("UnmarshalTLV failed: %v", err)
			}

			// Compare
			if len(decoded.URLs) != len(tt.s.URLs) {
				t.Errorf("URLs length mismatch: got %d, want %d", len(decoded.URLs), len(tt.s.URLs))
			}
			for i := range tt.s.URLs {
				if i < len(decoded.URLs) && decoded.URLs[i] != tt.s.URLs[i] {
					t.Errorf("URLs[%d] mismatch: got %q, want %q", i, decoded.URLs[i], tt.s.URLs[i])
				}
			}

			if (decoded.Username == nil) != (tt.s.Username == nil) {
				t.Errorf("Username nil mismatch")
			} else if decoded.Username != nil && *decoded.Username != *tt.s.Username {
				t.Errorf("Username mismatch: got %q, want %q", *decoded.Username, *tt.s.Username)
			}

			if (decoded.Credential == nil) != (tt.s.Credential == nil) {
				t.Errorf("Credential nil mismatch")
			} else if decoded.Credential != nil && *decoded.Credential != *tt.s.Credential {
				t.Errorf("Credential mismatch: got %q, want %q", *decoded.Credential, *tt.s.Credential)
			}

			if (decoded.CAID == nil) != (tt.s.CAID == nil) {
				t.Errorf("CAID nil mismatch")
			} else if decoded.CAID != nil && *decoded.CAID != *tt.s.CAID {
				t.Errorf("CAID mismatch: got %d, want %d", *decoded.CAID, *tt.s.CAID)
			}
		})
	}
}

func TestICECandidateStruct_TLVRoundtrip(t *testing.T) {
	sdpMid := "audio"
	sdpMLineIndex := uint16(0)

	tests := []struct {
		name string
		c    ICECandidateStruct
	}{
		{
			name: "full",
			c: ICECandidateStruct{
				Candidate:     "candidate:1 1 UDP 2130706431 192.168.1.1 12345 typ host",
				SDPMid:        &sdpMid,
				SDPMLineIndex: &sdpMLineIndex,
			},
		},
		{
			name: "nullable_fields",
			c: ICECandidateStruct{
				Candidate:     "candidate:2 1 UDP 1694498815 203.0.113.1 54321 typ srflx",
				SDPMid:        nil,
				SDPMLineIndex: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)
			if err := tt.c.MarshalTLV(w); err != nil {
				t.Fatalf("MarshalTLV failed: %v", err)
			}

			// Decode
			r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
			var decoded ICECandidateStruct
			if err := decoded.UnmarshalTLV(r); err != nil {
				t.Fatalf("UnmarshalTLV failed: %v", err)
			}

			// Compare
			if decoded.Candidate != tt.c.Candidate {
				t.Errorf("Candidate mismatch: got %q, want %q", decoded.Candidate, tt.c.Candidate)
			}

			if (decoded.SDPMid == nil) != (tt.c.SDPMid == nil) {
				t.Errorf("SDPMid nil mismatch: got %v, want %v", decoded.SDPMid, tt.c.SDPMid)
			} else if decoded.SDPMid != nil && *decoded.SDPMid != *tt.c.SDPMid {
				t.Errorf("SDPMid mismatch: got %q, want %q", *decoded.SDPMid, *tt.c.SDPMid)
			}

			if (decoded.SDPMLineIndex == nil) != (tt.c.SDPMLineIndex == nil) {
				t.Errorf("SDPMLineIndex nil mismatch: got %v, want %v", decoded.SDPMLineIndex, tt.c.SDPMLineIndex)
			} else if decoded.SDPMLineIndex != nil && *decoded.SDPMLineIndex != *tt.c.SDPMLineIndex {
				t.Errorf("SDPMLineIndex mismatch: got %d, want %d", *decoded.SDPMLineIndex, *tt.c.SDPMLineIndex)
			}
		})
	}
}

func TestSFrameStruct_TLVRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		s    SFrameStruct
	}{
		{
			name: "aes_gcm_128",
			s: SFrameStruct{
				CipherSuite: 1, // AES_GCM_128_SHA256
				BaseKey:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
				KID:         []byte{0x00, 0x01},
			},
		},
		{
			name: "long_kid",
			s: SFrameStruct{
				CipherSuite: 2,
				BaseKey:     []byte{0x01, 0x02, 0x03, 0x04},
				KID:         []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)
			if err := tt.s.MarshalTLV(w); err != nil {
				t.Fatalf("MarshalTLV failed: %v", err)
			}

			// Decode
			r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
			var decoded SFrameStruct
			if err := decoded.UnmarshalTLV(r); err != nil {
				t.Fatalf("UnmarshalTLV failed: %v", err)
			}

			// Compare
			if decoded.CipherSuite != tt.s.CipherSuite {
				t.Errorf("CipherSuite mismatch: got %d, want %d", decoded.CipherSuite, tt.s.CipherSuite)
			}
			if !bytes.Equal(decoded.BaseKey, tt.s.BaseKey) {
				t.Errorf("BaseKey mismatch: got %x, want %x", decoded.BaseKey, tt.s.BaseKey)
			}
			if !bytes.Equal(decoded.KID, tt.s.KID) {
				t.Errorf("KID mismatch: got %x, want %x", decoded.KID, tt.s.KID)
			}
		})
	}
}

func TestWebRTCSessionStruct_TLVRoundtrip(t *testing.T) {
	videoID := uint16(1)
	audioID := uint16(2)

	tests := []struct {
		name string
		s    WebRTCSessionStruct
	}{
		{
			name: "full",
			s: WebRTCSessionStruct{
				ID:              42,
				PeerNodeID:      0x0102030405060708,
				PeerEndpointID:  1,
				StreamUsage:     StreamUsageLiveView,
				VideoStreamID:   &videoID,
				AudioStreamID:   &audioID,
				MetadataEnabled: true,
				FabricIndex:     1,
			},
		},
		{
			name: "no_streams",
			s: WebRTCSessionStruct{
				ID:              100,
				PeerNodeID:      0xDEADBEEF,
				PeerEndpointID:  0,
				StreamUsage:     StreamUsageRecording,
				VideoStreamID:   nil,
				AudioStreamID:   nil,
				MetadataEnabled: false,
				FabricIndex:     2,
			},
		},
		{
			name: "video_only",
			s: WebRTCSessionStruct{
				ID:              1,
				PeerNodeID:      1234567890,
				PeerEndpointID:  5,
				StreamUsage:     StreamUsageAnalysis,
				VideoStreamID:   &videoID,
				AudioStreamID:   nil,
				MetadataEnabled: false,
				FabricIndex:     3,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)
			if err := tt.s.MarshalTLV(w); err != nil {
				t.Fatalf("MarshalTLV failed: %v", err)
			}

			// Decode
			r := tlv.NewReader(bytes.NewReader(buf.Bytes()))
			var decoded WebRTCSessionStruct
			if err := decoded.UnmarshalTLV(r); err != nil {
				t.Fatalf("UnmarshalTLV failed: %v", err)
			}

			// Compare
			if decoded.ID != tt.s.ID {
				t.Errorf("ID mismatch: got %d, want %d", decoded.ID, tt.s.ID)
			}
			if decoded.PeerNodeID != tt.s.PeerNodeID {
				t.Errorf("PeerNodeID mismatch: got %x, want %x", decoded.PeerNodeID, tt.s.PeerNodeID)
			}
			if decoded.PeerEndpointID != tt.s.PeerEndpointID {
				t.Errorf("PeerEndpointID mismatch: got %d, want %d", decoded.PeerEndpointID, tt.s.PeerEndpointID)
			}
			if decoded.StreamUsage != tt.s.StreamUsage {
				t.Errorf("StreamUsage mismatch: got %d, want %d", decoded.StreamUsage, tt.s.StreamUsage)
			}
			if (decoded.VideoStreamID == nil) != (tt.s.VideoStreamID == nil) {
				t.Errorf("VideoStreamID nil mismatch")
			} else if decoded.VideoStreamID != nil && *decoded.VideoStreamID != *tt.s.VideoStreamID {
				t.Errorf("VideoStreamID mismatch: got %d, want %d", *decoded.VideoStreamID, *tt.s.VideoStreamID)
			}
			if (decoded.AudioStreamID == nil) != (tt.s.AudioStreamID == nil) {
				t.Errorf("AudioStreamID nil mismatch")
			} else if decoded.AudioStreamID != nil && *decoded.AudioStreamID != *tt.s.AudioStreamID {
				t.Errorf("AudioStreamID mismatch: got %d, want %d", *decoded.AudioStreamID, *tt.s.AudioStreamID)
			}
			if decoded.MetadataEnabled != tt.s.MetadataEnabled {
				t.Errorf("MetadataEnabled mismatch: got %v, want %v", decoded.MetadataEnabled, tt.s.MetadataEnabled)
			}
			if decoded.FabricIndex != tt.s.FabricIndex {
				t.Errorf("FabricIndex mismatch: got %d, want %d", decoded.FabricIndex, tt.s.FabricIndex)
			}
		})
	}
}
