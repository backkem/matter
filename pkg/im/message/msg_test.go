package message

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/backkem/matter/pkg/tlv"
)

func TestStatusResponseMessage_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  StatusResponseMessage
	}{
		{
			name: "success",
			msg:  StatusResponseMessage{Status: StatusSuccess},
		},
		{
			name: "failure",
			msg:  StatusResponseMessage{Status: StatusInvalidAction},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.msg.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded StatusResponseMessage
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if tt.msg != decoded {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.msg)
			}
		})
	}
}

func TestReadRequestMessage_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  ReadRequestMessage
	}{
		{
			name: "C reference vector",
			msg: ReadRequestMessage{
				AttributeRequests: []AttributePathIB{
					{
						EnableTagCompression: Ptr(false),
						Node:                 Ptr(NodeID(1)),
						Endpoint:             Ptr(EndpointID(2)),
						Cluster:              Ptr(ClusterID(3)),
						Attribute:            Ptr(AttributeID(4)),
						ListIndex:            Ptr(ListIndex(5)),
					},
				},
				EventRequests: []EventPathIB{
					{
						Node:     Ptr(NodeID(1)),
						Endpoint: Ptr(EndpointID(2)),
						Cluster:  Ptr(ClusterID(3)),
						Event:    Ptr(EventID(4)),
						IsUrgent: Ptr(true),
					},
				},
				EventFilters: []EventFilterIB{
					{Node: Ptr(NodeID(1)), EventMin: 2},
				},
				FabricFiltered: true,
				DataVersionFilters: []DataVersionFilterIB{
					{
						Path: ClusterPathIB{
							Node:     Ptr(NodeID(1)),
							Endpoint: Ptr(EndpointID(2)),
							Cluster:  Ptr(ClusterID(3)),
						},
						DataVersion: 2,
					},
				},
			},
		},
		{
			name: "minimal",
			msg: ReadRequestMessage{
				FabricFiltered: false,
			},
		},
		{
			name: "attributes only",
			msg: ReadRequestMessage{
				AttributeRequests: []AttributePathIB{
					{
						Endpoint:  Ptr(EndpointID(1)),
						Cluster:   Ptr(ClusterID(6)),
						Attribute: Ptr(AttributeID(0)),
					},
				},
				FabricFiltered: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.msg.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded ReadRequestMessage
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.msg, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.msg)
			}
		})
	}
}

func TestInvokeRequestMessage_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  InvokeRequestMessage
	}{
		{
			name: "C reference vector",
			msg: InvokeRequestMessage{
				SuppressResponse: true,
				TimedRequest:     true,
				InvokeRequests: []CommandDataIB{
					{
						Path: CommandPathIB{
							Endpoint: 1,
							Cluster:  3,
							Command:  4,
						},
						// Fields with context tag 1: struct with bool true
						Fields: []byte{0x35, 0x01, 0x29, 0x01, 0x18},
					},
				},
			},
		},
		{
			name: "OnOff toggle",
			msg: InvokeRequestMessage{
				SuppressResponse: false,
				TimedRequest:     false,
				InvokeRequests: []CommandDataIB{
					{
						Path: CommandPathIB{
							Endpoint: 1,
							Cluster:  0x0006,
							Command:  2, // Toggle
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.msg.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded InvokeRequestMessage
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.msg, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.msg)
			}
		})
	}
}

func TestInvokeResponseMessage_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  InvokeResponseMessage
	}{
		{
			name: "C reference vector",
			msg: InvokeResponseMessage{
				SuppressResponse: true,
				InvokeResponses: []InvokeResponseIB{
					{
						Command: &CommandDataIB{
							Path: CommandPathIB{
								Endpoint: 1,
								Cluster:  3,
								Command:  4,
							},
							// Fields with context tag 1: struct with bool true
							Fields: []byte{0x35, 0x01, 0x29, 0x01, 0x18},
						},
					},
				},
				MoreChunkedMessages: true,
			},
		},
		{
			name: "status response",
			msg: InvokeResponseMessage{
				SuppressResponse: false,
				InvokeResponses: []InvokeResponseIB{
					{
						Status: &CommandStatusIB{
							Path: CommandPathIB{
								Endpoint: 1,
								Cluster:  6,
								Command:  0,
							},
							Status: StatusIB{
								Status: StatusSuccess,
							},
						},
					},
				},
				MoreChunkedMessages: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.msg.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded InvokeResponseMessage
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.msg, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.msg)
			}
		})
	}
}

func TestReportDataMessage_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  ReportDataMessage
	}{
		{
			name: "C reference vector",
			msg: ReportDataMessage{
				SubscriptionID: Ptr(SubscriptionID(2)),
				AttributeReports: []AttributeReportIB{
					{
						AttributeData: &AttributeDataIB{
							DataVersion: 2,
							Path: AttributePathIB{
								EnableTagCompression: Ptr(false),
								Node:                 Ptr(NodeID(1)),
								Endpoint:             Ptr(EndpointID(2)),
								Cluster:              Ptr(ClusterID(3)),
								Attribute:            Ptr(AttributeID(4)),
								ListIndex:            Ptr(ListIndex(5)),
							},
							// Data with context tag 2: struct with bool true
							Data: []byte{0x35, 0x02, 0x29, 0x01, 0x18},
						},
					},
				},
				EventReports: []EventReportIB{
					{
						EventData: &EventDataIB{
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
							// Data with context tag 7: struct with bool true
							Data: []byte{0x35, 0x07, 0x29, 0x01, 0x18},
						},
					},
				},
				MoreChunkedMessages: true,
				SuppressResponse:    true,
			},
		},
		{
			name: "minimal",
			msg: ReportDataMessage{
				MoreChunkedMessages: false,
				SuppressResponse:    false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.msg.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded ReportDataMessage
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.msg, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.msg)
			}
		})
	}
}

func TestSubscribeRequestMessage_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  SubscribeRequestMessage
	}{
		{
			name: "C reference vector",
			msg: SubscribeRequestMessage{
				KeepSubscriptions:  true,
				MinIntervalFloor:   2,
				MaxIntervalCeiling: 3,
				AttributeRequests: []AttributePathIB{
					{
						EnableTagCompression: Ptr(false),
						Node:                 Ptr(NodeID(1)),
						Endpoint:             Ptr(EndpointID(2)),
						Cluster:              Ptr(ClusterID(3)),
						Attribute:            Ptr(AttributeID(4)),
						ListIndex:            Ptr(ListIndex(5)),
					},
				},
				EventRequests: []EventPathIB{
					{
						Node:     Ptr(NodeID(1)),
						Endpoint: Ptr(EndpointID(2)),
						Cluster:  Ptr(ClusterID(3)),
						Event:    Ptr(EventID(4)),
						IsUrgent: Ptr(true),
					},
				},
				EventFilters: []EventFilterIB{
					{Node: Ptr(NodeID(1)), EventMin: 2},
				},
				FabricFiltered: true,
				DataVersionFilters: []DataVersionFilterIB{
					{
						Path: ClusterPathIB{
							Node:     Ptr(NodeID(1)),
							Endpoint: Ptr(EndpointID(2)),
							Cluster:  Ptr(ClusterID(3)),
						},
						DataVersion: 2,
					},
				},
			},
		},
		{
			name: "minimal",
			msg: SubscribeRequestMessage{
				KeepSubscriptions:  false,
				MinIntervalFloor:   0,
				MaxIntervalCeiling: 60,
				FabricFiltered:     true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.msg.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded SubscribeRequestMessage
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.msg, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.msg)
			}
		})
	}
}

func TestSubscribeResponseMessage_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  SubscribeResponseMessage
	}{
		{
			name: "C reference vector",
			msg: SubscribeResponseMessage{
				SubscriptionID: 1,
				MaxInterval:    2,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.msg.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded SubscribeResponseMessage
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if tt.msg != decoded {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.msg)
			}
		})
	}
}

func TestWriteRequestMessage_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  WriteRequestMessage
	}{
		{
			name: "C reference vector",
			msg: WriteRequestMessage{
				SuppressResponse: true,
				TimedRequest:     true,
				WriteRequests: []AttributeDataIB{
					{
						DataVersion: 2,
						Path: AttributePathIB{
							EnableTagCompression: Ptr(false),
							Node:                 Ptr(NodeID(1)),
							Endpoint:             Ptr(EndpointID(2)),
							Cluster:              Ptr(ClusterID(3)),
							Attribute:            Ptr(AttributeID(4)),
							ListIndex:            Ptr(ListIndex(5)),
						},
						// Data with context tag 2: struct with bool true
						Data: []byte{0x35, 0x02, 0x29, 0x01, 0x18},
					},
				},
				MoreChunkedMessages: true,
			},
		},
		{
			name: "minimal",
			msg: WriteRequestMessage{
				SuppressResponse:    false,
				TimedRequest:        false,
				MoreChunkedMessages: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.msg.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded WriteRequestMessage
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.msg, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.msg)
			}
		})
	}
}

func TestWriteResponseMessage_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  WriteResponseMessage
	}{
		{
			name: "C reference vector",
			msg: WriteResponseMessage{
				WriteResponses: []AttributeStatusIB{
					{
						Path: AttributePathIB{
							EnableTagCompression: Ptr(false),
							Node:                 Ptr(NodeID(1)),
							Endpoint:             Ptr(EndpointID(2)),
							Cluster:              Ptr(ClusterID(3)),
							Attribute:            Ptr(AttributeID(4)),
							ListIndex:            Ptr(ListIndex(5)),
						},
						Status: StatusIB{
							Status: StatusInvalidSubscription,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.msg.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded WriteResponseMessage
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.msg, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.msg)
			}
		})
	}
}

func TestTimedRequestMessage_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  TimedRequestMessage
	}{
		{
			name: "100ms timeout",
			msg:  TimedRequestMessage{Timeout: 100},
		},
		{
			name: "5000ms timeout",
			msg:  TimedRequestMessage{Timeout: 5000},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.msg.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded TimedRequestMessage
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if tt.msg != decoded {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.msg)
			}
		})
	}
}
