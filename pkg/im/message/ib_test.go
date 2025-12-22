package message

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/backkem/matter/pkg/tlv"
)

func TestStatusIB_Roundtrip(t *testing.T) {
	tests := []struct {
		name   string
		status StatusIB
	}{
		{
			name: "C reference vector",
			status: StatusIB{
				Status: StatusInvalidSubscription,
			},
		},
		{
			name: "success",
			status: StatusIB{
				Status: StatusSuccess,
			},
		},
		{
			name: "failure with cluster status",
			status: StatusIB{
				Status:        StatusFailure,
				ClusterStatus: Ptr(uint8(0x42)),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.status.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded StatusIB
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.status, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.status)
			}
		})
	}
}

func TestEventFilterIB_Roundtrip(t *testing.T) {
	tests := []struct {
		name   string
		filter EventFilterIB
	}{
		{
			name: "C reference vector",
			filter: EventFilterIB{
				Node:     Ptr(NodeID(1)),
				EventMin: 2,
			},
		},
		{
			name: "no node",
			filter: EventFilterIB{
				EventMin: 100,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.filter.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded EventFilterIB
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.filter, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.filter)
			}
		})
	}
}

func TestDataVersionFilterIB_Roundtrip(t *testing.T) {
	tests := []struct {
		name   string
		filter DataVersionFilterIB
	}{
		{
			name: "C reference vector",
			filter: DataVersionFilterIB{
				Path: ClusterPathIB{
					Node:     Ptr(NodeID(1)),
					Endpoint: Ptr(EndpointID(2)),
					Cluster:  Ptr(ClusterID(3)),
				},
				DataVersion: 2,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.filter.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded DataVersionFilterIB
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.filter, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.filter)
			}
		})
	}
}

func TestCommandDataIB_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		cmd  CommandDataIB
	}{
		{
			name: "C reference vector",
			cmd: CommandDataIB{
				Path: CommandPathIB{
					Endpoint: 1,
					Cluster:  3,
					Command:  4,
				},
				// Fields with context tag 1 struct containing bool true
				// This matches chip-tool format: context tag 1 (0x35 0x01), context tag 1 bool true (0x29 0x01), end (0x18)
				Fields: []byte{0x35, 0x01, 0x29, 0x01, 0x18},
			},
		},
		{
			name: "with ref",
			cmd: CommandDataIB{
				Path: CommandPathIB{
					Endpoint: 1,
					Cluster:  6,
					Command:  0,
				},
				Ref: Ptr(uint16(42)),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.cmd.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded CommandDataIB
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.cmd, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.cmd)
			}
		})
	}
}

func TestCommandStatusIB_Roundtrip(t *testing.T) {
	tests := []struct {
		name   string
		status CommandStatusIB
	}{
		{
			name: "success",
			status: CommandStatusIB{
				Path: CommandPathIB{
					Endpoint: 1,
					Cluster:  3,
					Command:  4,
				},
				Status: StatusIB{
					Status: StatusSuccess,
				},
			},
		},
		{
			name: "unsupported command",
			status: CommandStatusIB{
				Path: CommandPathIB{
					Endpoint: 1,
					Cluster:  0x0006,
					Command:  0xFF,
				},
				Status: StatusIB{
					Status: StatusUnsupportedCommand,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.status.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded CommandStatusIB
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.status, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.status)
			}
		})
	}
}

func TestInvokeResponseIB_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		resp InvokeResponseIB
	}{
		{
			name: "with command",
			resp: InvokeResponseIB{
				Command: &CommandDataIB{
					Path: CommandPathIB{
						Endpoint: 1,
						Cluster:  3,
						Command:  4,
					},
				},
			},
		},
		{
			name: "with status",
			resp: InvokeResponseIB{
				Status: &CommandStatusIB{
					Path: CommandPathIB{
						Endpoint: 1,
						Cluster:  3,
						Command:  4,
					},
					Status: StatusIB{
						Status: StatusSuccess,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.resp.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded InvokeResponseIB
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.resp, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.resp)
			}
		})
	}
}

func TestAttributeReportIB_Roundtrip(t *testing.T) {
	tests := []struct {
		name   string
		report AttributeReportIB
	}{
		{
			name: "with data",
			report: AttributeReportIB{
				AttributeData: &AttributeDataIB{
					DataVersion: 2,
					Path: AttributePathIB{
						Endpoint:  Ptr(EndpointID(1)),
						Cluster:   Ptr(ClusterID(6)),
						Attribute: Ptr(AttributeID(0)),
					},
					// Data with context tag 2 (attrDataTagData): boolean false
					Data: []byte{0x28, 0x02}, // Context tag 2, boolean false
				},
			},
		},
		{
			name: "with status",
			report: AttributeReportIB{
				AttributeStatus: &AttributeStatusIB{
					Path: AttributePathIB{
						Endpoint:  Ptr(EndpointID(1)),
						Cluster:   Ptr(ClusterID(6)),
						Attribute: Ptr(AttributeID(0xFF)),
					},
					Status: StatusIB{
						Status: StatusUnsupportedAttribute,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.report.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded AttributeReportIB
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.report, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.report)
			}
		})
	}
}

func TestEventDataIB_Roundtrip(t *testing.T) {
	tests := []struct {
		name  string
		event EventDataIB
	}{
		{
			name: "C reference vector",
			event: EventDataIB{
				Path: EventPathIB{
					Node:     Ptr(NodeID(1)),
					Endpoint: Ptr(EndpointID(2)),
					Cluster:  Ptr(ClusterID(3)),
					Event:    Ptr(EventID(4)),
					IsUrgent: Ptr(true),
				},
				EventNumber:          2,
				Priority:             3,
				EpochTimestamp:       Ptr(uint64(4)),
				SystemTimestamp:      Ptr(uint64(5)),
				DeltaEpochTimestamp:  Ptr(uint64(6)),
				DeltaSystemTimestamp: Ptr(uint64(7)),
				// Data with context tag 7 (eventDataTagData): struct with bool true
				Data: []byte{0x35, 0x07, 0x29, 0x01, 0x18},
			},
		},
		{
			name: "minimal",
			event: EventDataIB{
				Path: EventPathIB{
					Endpoint: Ptr(EndpointID(0)),
					Cluster:  Ptr(ClusterID(0x0028)),
					Event:    Ptr(EventID(0)),
				},
				EventNumber: 1,
				Priority:    EventPriorityCritical,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.event.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded EventDataIB
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.event, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.event)
			}
		})
	}
}
