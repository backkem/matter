package message

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/backkem/matter/pkg/tlv"
)

func TestAttributePathIB_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		path AttributePathIB
	}{
		{
			name: "C reference vector",
			path: AttributePathIB{
				EnableTagCompression: Ptr(false),
				Node:                 Ptr(NodeID(1)),
				Endpoint:             Ptr(EndpointID(2)),
				Cluster:              Ptr(ClusterID(3)),
				Attribute:            Ptr(AttributeID(4)),
				ListIndex:            Ptr(ListIndex(5)),
			},
		},
		{
			name: "minimal (wildcard)",
			path: AttributePathIB{},
		},
		{
			name: "endpoint and cluster only",
			path: AttributePathIB{
				Endpoint: Ptr(EndpointID(1)),
				Cluster:  Ptr(ClusterID(0x0006)),
			},
		},
		{
			name: "with tag compression",
			path: AttributePathIB{
				EnableTagCompression: Ptr(true),
				Endpoint:             Ptr(EndpointID(1)),
				Cluster:              Ptr(ClusterID(6)),
				Attribute:            Ptr(AttributeID(0)),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.path.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded AttributePathIB
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.path, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.path)
			}
		})
	}
}

func TestEventPathIB_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		path EventPathIB
	}{
		{
			name: "C reference vector",
			path: EventPathIB{
				Node:     Ptr(NodeID(1)),
				Endpoint: Ptr(EndpointID(2)),
				Cluster:  Ptr(ClusterID(3)),
				Event:    Ptr(EventID(4)),
				IsUrgent: Ptr(true),
			},
		},
		{
			name: "minimal (wildcard)",
			path: EventPathIB{},
		},
		{
			name: "not urgent",
			path: EventPathIB{
				Endpoint: Ptr(EndpointID(0)),
				Cluster:  Ptr(ClusterID(0x0028)),
				Event:    Ptr(EventID(0)),
				IsUrgent: Ptr(false),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.path.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded EventPathIB
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.path, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.path)
			}
		})
	}
}

func TestCommandPathIB_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		path CommandPathIB
	}{
		{
			name: "C reference vector",
			path: CommandPathIB{
				Endpoint: 1,
				Cluster:  3,
				Command:  4,
			},
		},
		{
			name: "OnOff toggle",
			path: CommandPathIB{
				Endpoint: 1,
				Cluster:  0x0006, // OnOff cluster
				Command:  2,     // Toggle command
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.path.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded CommandPathIB
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if tt.path != decoded {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.path)
			}
		})
	}
}

func TestClusterPathIB_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		path ClusterPathIB
	}{
		{
			name: "C reference vector",
			path: ClusterPathIB{
				Node:     Ptr(NodeID(1)),
				Endpoint: Ptr(EndpointID(2)),
				Cluster:  Ptr(ClusterID(3)),
			},
		},
		{
			name: "minimal",
			path: ClusterPathIB{},
		},
		{
			name: "endpoint and cluster",
			path: ClusterPathIB{
				Endpoint: Ptr(EndpointID(0)),
				Cluster:  Ptr(ClusterID(0x0028)),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := tlv.NewWriter(&buf)

			if err := tt.path.Encode(w); err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			r := tlv.NewReader(&buf)
			var decoded ClusterPathIB
			if err := decoded.Decode(r); err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if !reflect.DeepEqual(tt.path, decoded) {
				t.Errorf("Roundtrip mismatch:\ngot:  %+v\nwant: %+v", decoded, tt.path)
			}
		})
	}
}
