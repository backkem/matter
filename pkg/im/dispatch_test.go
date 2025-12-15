package im

import (
	"context"
	"testing"

	"github.com/backkem/matter/pkg/acl"
	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/im/message"
	"github.com/backkem/matter/pkg/tlv"
)

func TestAttributeReadRequest_ToDataModelRequest(t *testing.T) {
	ep := message.EndpointID(1)
	cl := message.ClusterID(0x001D)
	attr := message.AttributeID(0x0000)

	tests := []struct {
		name             string
		req              AttributeReadRequest
		wantEndpoint     datamodel.EndpointID
		wantCluster      datamodel.ClusterID
		wantAttribute    datamodel.AttributeID
		wantFabricFilter bool
	}{
		{
			name: "basic path",
			req: AttributeReadRequest{
				Path: message.AttributePathIB{
					Endpoint:  &ep,
					Cluster:   &cl,
					Attribute: &attr,
				},
				IsFabricFiltered: false,
			},
			wantEndpoint:     1,
			wantCluster:      0x001D,
			wantAttribute:    0x0000,
			wantFabricFilter: false,
		},
		{
			name: "fabric filtered",
			req: AttributeReadRequest{
				Path: message.AttributePathIB{
					Endpoint:  &ep,
					Cluster:   &cl,
					Attribute: &attr,
				},
				IsFabricFiltered: true,
			},
			wantEndpoint:     1,
			wantCluster:      0x001D,
			wantAttribute:    0x0000,
			wantFabricFilter: true,
		},
		{
			name: "nil path fields default to zero",
			req: AttributeReadRequest{
				Path: message.AttributePathIB{
					Endpoint:  nil,
					Cluster:   nil,
					Attribute: nil,
				},
			},
			wantEndpoint:  0,
			wantCluster:   0,
			wantAttribute: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.req.ToDataModelRequest()

			if got.Path.Endpoint != tt.wantEndpoint {
				t.Errorf("Endpoint = %d, want %d", got.Path.Endpoint, tt.wantEndpoint)
			}
			if got.Path.Cluster != tt.wantCluster {
				t.Errorf("Cluster = %d, want %d", got.Path.Cluster, tt.wantCluster)
			}
			if got.Path.Attribute != tt.wantAttribute {
				t.Errorf("Attribute = %d, want %d", got.Path.Attribute, tt.wantAttribute)
			}

			hasFabricFilter := (got.ReadFlags & datamodel.ReadFlagFabricFiltered) != 0
			if hasFabricFilter != tt.wantFabricFilter {
				t.Errorf("FabricFiltered = %v, want %v", hasFabricFilter, tt.wantFabricFilter)
			}
		})
	}
}

func TestAttributeReadRequest_ToDataModelRequest_WithIMContext(t *testing.T) {
	ep := message.EndpointID(1)
	cl := message.ClusterID(0x001D)
	attr := message.AttributeID(0x0000)

	req := AttributeReadRequest{
		Path: message.AttributePathIB{
			Endpoint:  &ep,
			Cluster:   &cl,
			Attribute: &attr,
		},
		IMContext: &RequestContext{
			Subject: acl.SubjectDescriptor{
				FabricIndex: 1,
				Subject:     12345,
				AuthMode:    acl.AuthModeCASE,
			},
		},
	}

	got := req.ToDataModelRequest()

	if got.Subject == nil {
		t.Fatal("expected Subject to be set")
	}
	if got.Subject.FabricIndex != 1 {
		t.Errorf("FabricIndex = %d, want %d", got.Subject.FabricIndex, 1)
	}
	if got.Subject.NodeID != 12345 {
		t.Errorf("NodeID = %d, want %d", got.Subject.NodeID, 12345)
	}
	if got.Subject.AuthMode != datamodel.AuthModeCASE {
		t.Errorf("AuthMode = %v, want %v", got.Subject.AuthMode, datamodel.AuthModeCASE)
	}
}

func TestAttributeWriteRequest_ToDataModelRequest(t *testing.T) {
	ep := message.EndpointID(0)
	cl := message.ClusterID(0x001F)
	attr := message.AttributeID(0x0000)
	listIdx := message.ListIndex(5)
	dv := message.DataVersion(42)

	tests := []struct {
		name          string
		req           AttributeWriteRequest
		wantEndpoint  datamodel.EndpointID
		wantListIndex *message.ListIndex
		wantTimed     bool
		wantDV        bool
	}{
		{
			name: "basic write",
			req: AttributeWriteRequest{
				Path: message.AttributePathIB{
					Endpoint:  &ep,
					Cluster:   &cl,
					Attribute: &attr,
				},
			},
			wantEndpoint: 0,
			wantTimed:    false,
			wantDV:       false,
		},
		{
			name: "timed write",
			req: AttributeWriteRequest{
				Path: message.AttributePathIB{
					Endpoint:  &ep,
					Cluster:   &cl,
					Attribute: &attr,
				},
				IsTimed: true,
			},
			wantEndpoint: 0,
			wantTimed:    true,
		},
		{
			name: "with data version",
			req: AttributeWriteRequest{
				Path: message.AttributePathIB{
					Endpoint:  &ep,
					Cluster:   &cl,
					Attribute: &attr,
				},
				DataVersion: &dv,
			},
			wantEndpoint: 0,
			wantDV:       true,
		},
		{
			name: "with list index",
			req: AttributeWriteRequest{
				Path: message.AttributePathIB{
					Endpoint:  &ep,
					Cluster:   &cl,
					Attribute: &attr,
					ListIndex: &listIdx,
				},
			},
			wantEndpoint:  0,
			wantListIndex: &listIdx,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.req.ToDataModelRequest()

			if got.Path.Endpoint != tt.wantEndpoint {
				t.Errorf("Endpoint = %d, want %d", got.Path.Endpoint, tt.wantEndpoint)
			}

			hasTimed := (got.WriteFlags & datamodel.WriteFlagTimed) != 0
			if hasTimed != tt.wantTimed {
				t.Errorf("Timed = %v, want %v", hasTimed, tt.wantTimed)
			}

			if tt.wantDV && got.DataVersion == nil {
				t.Error("expected DataVersion to be set")
			}
			if !tt.wantDV && got.DataVersion != nil {
				t.Error("expected DataVersion to be nil")
			}

			if tt.wantListIndex != nil {
				if got.Path.ListIndex == nil {
					t.Error("expected ListIndex to be set")
				} else if *got.Path.ListIndex != *tt.wantListIndex {
					t.Errorf("ListIndex = %d, want %d", *got.Path.ListIndex, *tt.wantListIndex)
				}
			}
		})
	}
}

func TestCommandInvokeRequest_ToDataModelRequest(t *testing.T) {
	tests := []struct {
		name        string
		req         CommandInvokeRequest
		wantEndpoint datamodel.EndpointID
		wantCluster  datamodel.ClusterID
		wantCommand  datamodel.CommandID
		wantTimed   bool
	}{
		{
			name: "basic invoke",
			req: CommandInvokeRequest{
				Path: message.CommandPathIB{
					Endpoint: 1,
					Cluster:  0x0006,
					Command:  2,
				},
			},
			wantEndpoint: 1,
			wantCluster:  0x0006,
			wantCommand:  2,
			wantTimed:   false,
		},
		{
			name: "timed invoke",
			req: CommandInvokeRequest{
				Path: message.CommandPathIB{
					Endpoint: 1,
					Cluster:  0x0101,
					Command:  0,
				},
				IsTimed: true,
			},
			wantEndpoint: 1,
			wantCluster:  0x0101,
			wantCommand:  0,
			wantTimed:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.req.ToDataModelRequest()

			if got.Path.Endpoint != tt.wantEndpoint {
				t.Errorf("Endpoint = %d, want %d", got.Path.Endpoint, tt.wantEndpoint)
			}
			if got.Path.Cluster != tt.wantCluster {
				t.Errorf("Cluster = %d, want %d", got.Path.Cluster, tt.wantCluster)
			}
			if got.Path.Command != tt.wantCommand {
				t.Errorf("Command = %d, want %d", got.Path.Command, tt.wantCommand)
			}

			hasTimed := (got.InvokeFlags & datamodel.InvokeFlagTimed) != 0
			if hasTimed != tt.wantTimed {
				t.Errorf("Timed = %v, want %v", hasTimed, tt.wantTimed)
			}
		})
	}
}

func TestNullDispatcher_ReadAttribute(t *testing.T) {
	d := NullDispatcher{}
	err := d.ReadAttribute(context.Background(), &AttributeReadRequest{}, nil)
	if err != ErrClusterNotFound {
		t.Errorf("ReadAttribute() = %v, want %v", err, ErrClusterNotFound)
	}
}

func TestNullDispatcher_WriteAttribute(t *testing.T) {
	d := NullDispatcher{}
	err := d.WriteAttribute(context.Background(), &AttributeWriteRequest{}, nil)
	if err != ErrClusterNotFound {
		t.Errorf("WriteAttribute() = %v, want %v", err, ErrClusterNotFound)
	}
}

func TestNullDispatcher_InvokeCommand(t *testing.T) {
	d := NullDispatcher{}
	resp, err := d.InvokeCommand(context.Background(), &CommandInvokeRequest{}, nil)
	if err != ErrClusterNotFound {
		t.Errorf("InvokeCommand() error = %v, want %v", err, ErrClusterNotFound)
	}
	if resp != nil {
		t.Errorf("InvokeCommand() response = %v, want nil", resp)
	}
}

func TestToDataModelAuthMode(t *testing.T) {
	tests := []struct {
		name string
		acl  acl.AuthMode
		want datamodel.AuthMode
	}{
		{"CASE", acl.AuthModeCASE, datamodel.AuthModeCASE},
		{"PASE", acl.AuthModePASE, datamodel.AuthModePASE},
		{"Group", acl.AuthModeGroup, datamodel.AuthModeGroup},
		{"Unknown", acl.AuthMode(99), datamodel.AuthModeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toDataModelAuthMode(tt.acl)
			if got != tt.want {
				t.Errorf("toDataModelAuthMode(%v) = %v, want %v", tt.acl, got, tt.want)
			}
		})
	}
}

func TestDerefHelpers(t *testing.T) {
	ep := message.EndpointID(5)
	cl := message.ClusterID(100)
	attr := message.AttributeID(200)

	// Non-nil
	if got := derefEndpoint(&ep); got != 5 {
		t.Errorf("derefEndpoint(&5) = %d, want 5", got)
	}
	if got := derefCluster(&cl); got != 100 {
		t.Errorf("derefCluster(&100) = %d, want 100", got)
	}
	if got := derefAttribute(&attr); got != 200 {
		t.Errorf("derefAttribute(&200) = %d, want 200", got)
	}

	// Nil defaults to 0
	if got := derefEndpoint(nil); got != 0 {
		t.Errorf("derefEndpoint(nil) = %d, want 0", got)
	}
	if got := derefCluster(nil); got != 0 {
		t.Errorf("derefCluster(nil) = %d, want 0", got)
	}
	if got := derefAttribute(nil); got != 0 {
		t.Errorf("derefAttribute(nil) = %d, want 0", got)
	}
}

// mockDispatcher for interface verification.
type mockDispatcher struct{}

func (m *mockDispatcher) ReadAttribute(ctx context.Context, req *AttributeReadRequest, w *tlv.Writer) error {
	return nil
}
func (m *mockDispatcher) WriteAttribute(ctx context.Context, req *AttributeWriteRequest, r *tlv.Reader) error {
	return nil
}
func (m *mockDispatcher) InvokeCommand(ctx context.Context, req *CommandInvokeRequest, r *tlv.Reader) ([]byte, error) {
	return nil, nil
}

func TestDispatcherInterface(t *testing.T) {
	// Verify mockDispatcher implements Dispatcher
	var _ Dispatcher = (*mockDispatcher)(nil)
	var _ Dispatcher = NullDispatcher{}
}
