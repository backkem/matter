package acl

import "testing"

func TestIsOperationalNodeID(t *testing.T) {
	tests := []struct {
		nodeID uint64
		want   bool
	}{
		// Valid operational range
		{NodeIDMinOperational, true},
		{0x0123_4567_89AB_CDEF, true},
		{NodeIDMaxOperational, true},

		// Invalid: unspecified
		{NodeIDUnspecified, false},

		// Invalid: reserved ranges
		{0xFFFF_FFF0_0000_0000, false}, // Reserved
		{0xFFFF_FFFB_0000_0000, false}, // PAKE
		{0xFFFF_FFFD_0000_0001, false}, // CAT
		{0xFFFF_FFFF_0000_0001, false}, // Group
	}

	for _, tt := range tests {
		if got := IsOperationalNodeID(tt.nodeID); got != tt.want {
			t.Errorf("IsOperationalNodeID(0x%016X) = %v, want %v", tt.nodeID, got, tt.want)
		}
	}
}

func TestIsGroupNodeID(t *testing.T) {
	tests := []struct {
		nodeID uint64
		want   bool
	}{
		// Valid group range
		{NodeIDMinGroup, true},
		{0xFFFF_FFFF_FFFF_8000, true},
		{NodeIDMaxGroup, true},

		// Not groups
		{0x0000_0000_0000_0001, false}, // Operational
		{0xFFFF_FFFD_0001_0001, false}, // CAT
		{0xFFFF_FFFB_0000_0001, false}, // PAKE
	}

	for _, tt := range tests {
		if got := IsGroupNodeID(tt.nodeID); got != tt.want {
			t.Errorf("IsGroupNodeID(0x%016X) = %v, want %v", tt.nodeID, got, tt.want)
		}
	}
}

func TestIsPAKENodeID(t *testing.T) {
	tests := []struct {
		nodeID uint64
		want   bool
	}{
		{NodeIDMinPAKE, true},
		{0xFFFF_FFFB_0000_0001, true},
		{NodeIDMaxPAKE, true},

		// Not PAKE
		{0x0000_0000_0000_0001, false},
		{0xFFFF_FFFB_0001_0000, false}, // Out of range (upper bits used)
	}

	for _, tt := range tests {
		if got := IsPAKENodeID(tt.nodeID); got != tt.want {
			t.Errorf("IsPAKENodeID(0x%016X) = %v, want %v", tt.nodeID, got, tt.want)
		}
	}
}

func TestNodeIDFromGroupID(t *testing.T) {
	tests := []struct {
		groupID uint16
		want    uint64
	}{
		{0x0001, 0xFFFF_FFFF_FFFF_0001},
		{0x0002, 0xFFFF_FFFF_FFFF_0002},
		{0xFFFF, 0xFFFF_FFFF_FFFF_FFFF},
	}

	for _, tt := range tests {
		if got := NodeIDFromGroupID(tt.groupID); got != tt.want {
			t.Errorf("NodeIDFromGroupID(0x%04X) = 0x%016X, want 0x%016X", tt.groupID, got, tt.want)
		}
	}
}

func TestGroupIDFromNodeID(t *testing.T) {
	tests := []struct {
		nodeID uint64
		want   uint16
	}{
		{0xFFFF_FFFF_FFFF_0001, 0x0001},
		{0xFFFF_FFFF_FFFF_0002, 0x0002},
		{0xFFFF_FFFF_FFFF_FFFF, 0xFFFF},
		// Non-group returns 0
		{0x0000_0000_0000_0001, 0},
	}

	for _, tt := range tests {
		if got := GroupIDFromNodeID(tt.nodeID); got != tt.want {
			t.Errorf("GroupIDFromNodeID(0x%016X) = 0x%04X, want 0x%04X", tt.nodeID, got, tt.want)
		}
	}
}

func TestIsValidGroupID(t *testing.T) {
	tests := []struct {
		groupID uint16
		want    bool
	}{
		{0x0000, false}, // 0 is reserved
		{0x0001, true},
		{0x7FFF, true},
		{0x8000, true},
		{0xFFFF, true},
	}

	for _, tt := range tests {
		if got := IsValidGroupID(tt.groupID); got != tt.want {
			t.Errorf("IsValidGroupID(0x%04X) = %v, want %v", tt.groupID, got, tt.want)
		}
	}
}

func TestTarget_Constructors(t *testing.T) {
	t.Run("NewTargetCluster", func(t *testing.T) {
		target := NewTargetCluster(0x0006)
		if !target.HasCluster() {
			t.Error("should have cluster")
		}
		if *target.Cluster != 0x0006 {
			t.Errorf("cluster = %d, want 6", *target.Cluster)
		}
		if target.HasEndpoint() || target.HasDeviceType() {
			t.Error("should not have endpoint or device type")
		}
	})

	t.Run("NewTargetEndpoint", func(t *testing.T) {
		target := NewTargetEndpoint(1)
		if !target.HasEndpoint() {
			t.Error("should have endpoint")
		}
		if *target.Endpoint != 1 {
			t.Errorf("endpoint = %d, want 1", *target.Endpoint)
		}
		if target.HasCluster() || target.HasDeviceType() {
			t.Error("should not have cluster or device type")
		}
	})

	t.Run("NewTargetDeviceType", func(t *testing.T) {
		target := NewTargetDeviceType(0x0100)
		if !target.HasDeviceType() {
			t.Error("should have device type")
		}
		if *target.DeviceType != 0x0100 {
			t.Errorf("deviceType = %d, want 256", *target.DeviceType)
		}
	})

	t.Run("NewTargetClusterEndpoint", func(t *testing.T) {
		target := NewTargetClusterEndpoint(0x0006, 2)
		if !target.HasCluster() || !target.HasEndpoint() {
			t.Error("should have both cluster and endpoint")
		}
		if *target.Cluster != 0x0006 || *target.Endpoint != 2 {
			t.Errorf("got cluster=%d endpoint=%d, want 6, 2", *target.Cluster, *target.Endpoint)
		}
	})

	t.Run("NewTargetClusterDeviceType", func(t *testing.T) {
		target := NewTargetClusterDeviceType(0x0006, 0x0100)
		if !target.HasCluster() || !target.HasDeviceType() {
			t.Error("should have both cluster and device type")
		}
	})
}

func TestTarget_IsEmpty(t *testing.T) {
	tests := []struct {
		name   string
		target Target
		want   bool
	}{
		{"empty", Target{}, true},
		{"cluster only", NewTargetCluster(6), false},
		{"endpoint only", NewTargetEndpoint(1), false},
		{"device type only", NewTargetDeviceType(256), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.target.IsEmpty(); got != tt.want {
				t.Errorf("Target.IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewRequestPath(t *testing.T) {
	path := NewRequestPath(0x0006, 1, RequestTypeAttributeRead)

	if path.Cluster != 0x0006 {
		t.Errorf("Cluster = %d, want 6", path.Cluster)
	}
	if path.Endpoint != 1 {
		t.Errorf("Endpoint = %d, want 1", path.Endpoint)
	}
	if path.RequestType != RequestTypeAttributeRead {
		t.Errorf("RequestType = %v, want AttributeRead", path.RequestType)
	}
	if path.EntityID != nil {
		t.Error("EntityID should be nil")
	}
}

func TestNewRequestPathWithEntity(t *testing.T) {
	path := NewRequestPathWithEntity(0x0006, 1, RequestTypeAttributeRead, 0x0000)

	if path.Cluster != 0x0006 {
		t.Errorf("Cluster = %d, want 6", path.Cluster)
	}
	if path.EntityID == nil {
		t.Fatal("EntityID should not be nil")
	}
	if *path.EntityID != 0x0000 {
		t.Errorf("EntityID = %d, want 0", *path.EntityID)
	}
}
