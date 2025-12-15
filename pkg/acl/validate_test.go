package acl

import (
	"testing"

	"github.com/backkem/matter/pkg/fabric"
)

// Test vectors from C++ TestAccessControl.cpp

// Valid CASE subjects
var validCaseSubjects = []uint64{
	0x0000_0000_0000_0001, // min operational
	0x0000_0000_0000_0002,
	0x0123_4567_89AB_CDEF,
	0xFFFF_FFEF_FFFF_FFFE,
	0xFFFF_FFEF_FFFF_FFFF, // max operational

	// CAT NodeIDs (0xFFFF_FFFD_xxxx_xxxx)
	NewCASEAuthTag(0x0000, 0x0001).NodeID(),
	NewCASEAuthTag(0x0000, 0x0002).NodeID(),
	NewCASEAuthTag(0x0000, 0xFFFE).NodeID(),
	NewCASEAuthTag(0x0000, 0xFFFF).NodeID(),

	NewCASEAuthTag(0x0001, 0x0001).NodeID(),
	NewCASEAuthTag(0x0001, 0x0002).NodeID(),
	NewCASEAuthTag(0x0001, 0xFFFE).NodeID(),
	NewCASEAuthTag(0x0001, 0xFFFF).NodeID(),

	NewCASEAuthTag(0xFFFE, 0x0001).NodeID(),
	NewCASEAuthTag(0xFFFE, 0x0002).NodeID(),
	NewCASEAuthTag(0xFFFE, 0xFFFE).NodeID(),
	NewCASEAuthTag(0xFFFE, 0xFFFF).NodeID(),

	NewCASEAuthTag(0xFFFF, 0x0001).NodeID(),
	NewCASEAuthTag(0xFFFF, 0x0002).NodeID(),
	NewCASEAuthTag(0xFFFF, 0xFFFE).NodeID(),
	NewCASEAuthTag(0xFFFF, 0xFFFF).NodeID(),
}

// Valid group subjects
var validGroupSubjects = []uint64{
	NodeIDFromGroupID(0x0001), // start of fabric-scoped
	NodeIDFromGroupID(0x0002),
	NodeIDFromGroupID(0x7FFE),
	NodeIDFromGroupID(0x7FFF), // end of fabric-scoped
	NodeIDFromGroupID(0x8000), // start of universal
	NodeIDFromGroupID(0x8001),
	NodeIDFromGroupID(0xFFFB),
	NodeIDFromGroupID(0xFFFC), // end of universal
	NodeIDFromGroupID(0xFFFD), // all proxies
	NodeIDFromGroupID(0xFFFE), // all non sleepy
	NodeIDFromGroupID(0xFFFF), // all nodes
}

// Valid PASE subjects
var validPaseSubjects = []uint64{
	NodeIDFromPAKEKeyID(0x0000),
	NodeIDFromPAKEKeyID(0x0001),
	NodeIDFromPAKEKeyID(0xFFFE),
	NodeIDFromPAKEKeyID(0xFFFF),
}

// Invalid subjects (for any auth mode)
var invalidSubjects = []uint64{
	0x0000_0000_0000_0000, // unspecified

	// Reserved ranges
	0xFFFF_FFF0_0000_0000,
	0xFFFF_FFF0_0000_0001,
	0xFFFF_FFF0_FFFF_FFFE,
	0xFFFF_FFF0_FFFF_FFFF,

	// CAT with version 0 (invalid)
	0xFFFF_FFFD_0000_0000,
	0xFFFF_FFFD_0001_0000,
	0xFFFF_FFFD_FFFE_0000,
	0xFFFF_FFFD_FFFF_0000,

	// Temporary local
	0xFFFF_FFFE_0000_0000,
	0xFFFF_FFFE_0000_0001,
	0xFFFF_FFFE_FFFF_FFFE,
	0xFFFF_FFFE_FFFF_FFFF,
}

// Valid clusters
var validClusters = []uint32{
	0x0000_0000, // start std
	0x0000_0001,
	0x0000_7FFE,
	0x0000_7FFF, // end std

	0x0001_FC00, // start MS (vendor 0x0001)
	0x0001_FC01,
	0x0001_FFFD,
	0x0001_FFFE, // end MS

	0xFFF1_FC00, // start MS (vendor 0xFFF1)
	0xFFF1_FC01,
	0xFFF1_FFFD,
	0xFFF1_FFFE, // end MS

	0xFFF4_FC00, // start MS (vendor 0xFFF4)
	0xFFF4_FC01,
	0xFFF4_FFFD,
	0xFFF4_FFFE, // end MS
}

// Invalid clusters
var invalidClusters = []uint32{
	0x0000_8000, // start unused
	0x0000_8001,
	0x0000_FBFE,
	0x0000_FBFF, // end unused
	0x0000_FFFF, // wildcard

	0xFFFF_FFFF, // global wildcard
}

// Valid endpoints
var validEndpoints = []uint16{
	0x0000,
	0x0001,
	0xFFFD,
	0xFFFE, // max
}

// Invalid endpoints
var invalidEndpoints = []uint16{
	0xFFFF, // invalid/wildcard
}

// Valid device types
var validDeviceTypes = []uint32{
	0x0000_0000,
	0x0000_0001,
	0x0000_BFFE,
	0x0000_BFFF, // max

	0x0001_0000, // vendor 1
	0x0001_0001,
	0x0001_BFFE,
	0x0001_BFFF,
}

// Invalid device types
var invalidDeviceTypes = []uint32{
	0x0000_C000, // start unused
	0x0000_C001,
	0x0000_FFFD,
	0x0000_FFFE, // end unused
	0x0000_FFFF, // wildcard
}

func TestValidateEntry_FabricIndex(t *testing.T) {
	validEntry := Entry{
		FabricIndex: 1,
		Privilege:   PrivilegeView,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{0x0123_4567_89AB_CDEF},
		Targets:     []Target{NewTargetCluster(0x0006)},
	}

	// Valid fabric indexes
	for _, fi := range []fabric.FabricIndex{1, 2, 3, 254} {
		entry := validEntry
		entry.FabricIndex = fi
		if err := ValidateEntry(&entry); err != nil {
			t.Errorf("FabricIndex %d should be valid, got: %v", fi, err)
		}
	}

	// Invalid fabric indexes
	for _, fi := range []fabric.FabricIndex{0, 255} {
		entry := validEntry
		entry.FabricIndex = fi
		if err := ValidateEntry(&entry); err != ErrInvalidFabricIndex {
			t.Errorf("FabricIndex %d should be invalid, got: %v", fi, err)
		}
	}
}

func TestValidateEntry_AuthModeSubject(t *testing.T) {
	baseEntry := Entry{
		FabricIndex: 1,
		Privilege:   PrivilegeView,
		Targets:     []Target{NewTargetCluster(0x0006)},
	}

	// CASE with valid subjects
	t.Run("CASE valid subjects", func(t *testing.T) {
		for _, subject := range validCaseSubjects {
			entry := baseEntry
			entry.AuthMode = AuthModeCASE
			entry.Subjects = []uint64{subject}
			if err := ValidateEntry(&entry); err != nil {
				t.Errorf("CASE subject 0x%016X should be valid, got: %v", subject, err)
			}
		}
	})

	// CASE with empty subjects (wildcard - valid)
	t.Run("CASE empty subjects", func(t *testing.T) {
		entry := baseEntry
		entry.AuthMode = AuthModeCASE
		entry.Subjects = nil
		if err := ValidateEntry(&entry); err != nil {
			t.Errorf("CASE with empty subjects should be valid, got: %v", err)
		}
	})

	// Group with valid subjects
	t.Run("Group valid subjects", func(t *testing.T) {
		for _, subject := range validGroupSubjects {
			entry := baseEntry
			entry.AuthMode = AuthModeGroup
			entry.Subjects = []uint64{subject}
			if err := ValidateEntry(&entry); err != nil {
				t.Errorf("Group subject 0x%016X should be valid, got: %v", subject, err)
			}
		}
	})

	// Group with empty subjects (wildcard - valid)
	t.Run("Group empty subjects", func(t *testing.T) {
		entry := baseEntry
		entry.AuthMode = AuthModeGroup
		entry.Subjects = nil
		if err := ValidateEntry(&entry); err != nil {
			t.Errorf("Group with empty subjects should be valid, got: %v", err)
		}
	})

	// Cross-auth mode invalid: CASE subjects for Group
	t.Run("CASE subjects for Group auth", func(t *testing.T) {
		for _, subject := range validCaseSubjects[:5] { // Test a few
			entry := baseEntry
			entry.AuthMode = AuthModeGroup
			entry.Subjects = []uint64{subject}
			if err := ValidateEntry(&entry); err != ErrInvalidSubject {
				t.Errorf("CASE subject 0x%016X should be invalid for Group, got: %v", subject, err)
			}
		}
	})

	// Cross-auth mode invalid: Group subjects for CASE
	t.Run("Group subjects for CASE auth", func(t *testing.T) {
		for _, subject := range validGroupSubjects[:5] { // Test a few
			entry := baseEntry
			entry.AuthMode = AuthModeCASE
			entry.Subjects = []uint64{subject}
			if err := ValidateEntry(&entry); err != ErrInvalidSubject {
				t.Errorf("Group subject 0x%016X should be invalid for CASE, got: %v", subject, err)
			}
		}
	})

	// Invalid subjects for any auth mode
	t.Run("Invalid subjects", func(t *testing.T) {
		for _, subject := range invalidSubjects {
			entry := baseEntry
			entry.AuthMode = AuthModeCASE
			entry.Subjects = []uint64{subject}
			if err := ValidateEntry(&entry); err != ErrInvalidSubject {
				t.Errorf("Subject 0x%016X should be invalid for CASE, got: %v", subject, err)
			}
		}
	})

	// PASE auth mode not allowed in stored ACL entries
	t.Run("PASE auth mode rejected", func(t *testing.T) {
		entry := baseEntry
		entry.AuthMode = AuthModePASE
		entry.Subjects = validPaseSubjects[:1]
		if err := ValidateEntry(&entry); err != ErrInvalidAuthMode {
			t.Errorf("PASE auth mode should be rejected, got: %v", err)
		}
	})
}

func TestValidateEntry_Privilege(t *testing.T) {
	baseEntry := Entry{
		FabricIndex: 1,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{0x0123_4567_89AB_CDEF},
		Targets:     []Target{NewTargetCluster(0x0006)},
	}

	// All privileges valid for CASE
	for _, priv := range []Privilege{PrivilegeView, PrivilegeProxyView, PrivilegeOperate, PrivilegeManage, PrivilegeAdminister} {
		entry := baseEntry
		entry.Privilege = priv
		if err := ValidateEntry(&entry); err != nil {
			t.Errorf("Privilege %s should be valid for CASE, got: %v", priv, err)
		}
	}

	// Group cannot have Administer
	t.Run("Group cannot have Administer", func(t *testing.T) {
		entry := baseEntry
		entry.AuthMode = AuthModeGroup
		entry.Subjects = []uint64{NodeIDFromGroupID(0x0002)}
		entry.Privilege = PrivilegeAdminister
		if err := ValidateEntry(&entry); err != ErrGroupAdminister {
			t.Errorf("Group with Administer should fail, got: %v", err)
		}
	})

	// Group can have other privileges
	for _, priv := range []Privilege{PrivilegeView, PrivilegeProxyView, PrivilegeOperate, PrivilegeManage} {
		entry := baseEntry
		entry.AuthMode = AuthModeGroup
		entry.Subjects = []uint64{NodeIDFromGroupID(0x0002)}
		entry.Privilege = priv
		if err := ValidateEntry(&entry); err != nil {
			t.Errorf("Privilege %s should be valid for Group, got: %v", priv, err)
		}
	}
}

func TestValidateEntry_Target(t *testing.T) {
	baseEntry := Entry{
		FabricIndex: 1,
		Privilege:   PrivilegeView,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{0x0123_4567_89AB_CDEF},
	}

	// Valid cluster-only targets
	t.Run("Valid clusters", func(t *testing.T) {
		for _, cluster := range validClusters {
			entry := baseEntry
			entry.Targets = []Target{NewTargetCluster(cluster)}
			if err := ValidateEntry(&entry); err != nil {
				t.Errorf("Cluster 0x%08X should be valid, got: %v", cluster, err)
			}
		}
	})

	// Invalid clusters
	t.Run("Invalid clusters", func(t *testing.T) {
		for _, cluster := range invalidClusters {
			entry := baseEntry
			entry.Targets = []Target{NewTargetCluster(cluster)}
			if err := ValidateEntry(&entry); err != ErrInvalidClusterID {
				t.Errorf("Cluster 0x%08X should be invalid, got: %v", cluster, err)
			}
		}
	})

	// Valid endpoint-only targets
	t.Run("Valid endpoints", func(t *testing.T) {
		for _, endpoint := range validEndpoints {
			entry := baseEntry
			entry.Targets = []Target{NewTargetEndpoint(endpoint)}
			if err := ValidateEntry(&entry); err != nil {
				t.Errorf("Endpoint 0x%04X should be valid, got: %v", endpoint, err)
			}
		}
	})

	// Invalid endpoints
	t.Run("Invalid endpoints", func(t *testing.T) {
		for _, endpoint := range invalidEndpoints {
			entry := baseEntry
			entry.Targets = []Target{NewTargetEndpoint(endpoint)}
			if err := ValidateEntry(&entry); err != ErrInvalidEndpointID {
				t.Errorf("Endpoint 0x%04X should be invalid, got: %v", endpoint, err)
			}
		}
	})

	// Valid device types
	t.Run("Valid device types", func(t *testing.T) {
		for _, dt := range validDeviceTypes {
			entry := baseEntry
			entry.Targets = []Target{NewTargetDeviceType(dt)}
			if err := ValidateEntry(&entry); err != nil {
				t.Errorf("DeviceType 0x%08X should be valid, got: %v", dt, err)
			}
		}
	})

	// Invalid device types
	t.Run("Invalid device types", func(t *testing.T) {
		for _, dt := range invalidDeviceTypes {
			entry := baseEntry
			entry.Targets = []Target{NewTargetDeviceType(dt)}
			if err := ValidateEntry(&entry); err != ErrInvalidDeviceTypeID {
				t.Errorf("DeviceType 0x%08X should be invalid, got: %v", dt, err)
			}
		}
	})

	// Cluster + Endpoint (valid combination)
	t.Run("Cluster + Endpoint", func(t *testing.T) {
		entry := baseEntry
		entry.Targets = []Target{NewTargetClusterEndpoint(0x0006, 1)}
		if err := ValidateEntry(&entry); err != nil {
			t.Errorf("Cluster+Endpoint should be valid, got: %v", err)
		}
	})

	// Cluster + DeviceType (valid combination)
	t.Run("Cluster + DeviceType", func(t *testing.T) {
		entry := baseEntry
		entry.Targets = []Target{NewTargetClusterDeviceType(0x0006, 0x0100)}
		if err := ValidateEntry(&entry); err != nil {
			t.Errorf("Cluster+DeviceType should be valid, got: %v", err)
		}
	})

	// Endpoint + DeviceType (INVALID combination)
	t.Run("Endpoint + DeviceType invalid", func(t *testing.T) {
		entry := baseEntry
		endpoint := uint16(1)
		deviceType := uint32(0x0100)
		entry.Targets = []Target{{Endpoint: &endpoint, DeviceType: &deviceType}}
		if err := ValidateEntry(&entry); err != ErrTargetEndpointAndType {
			t.Errorf("Endpoint+DeviceType should be invalid, got: %v", err)
		}
	})

	// Empty target (INVALID)
	t.Run("Empty target invalid", func(t *testing.T) {
		entry := baseEntry
		entry.Targets = []Target{{}}
		if err := ValidateEntry(&entry); err != ErrTargetEmpty {
			t.Errorf("Empty target should be invalid, got: %v", err)
		}
	})

	// Empty targets list (valid - wildcard)
	t.Run("Empty targets list valid", func(t *testing.T) {
		entry := baseEntry
		entry.Targets = nil
		if err := ValidateEntry(&entry); err != nil {
			t.Errorf("Empty targets list should be valid (wildcard), got: %v", err)
		}
	})
}

func TestIsValidClusterID(t *testing.T) {
	for _, cluster := range validClusters {
		if !IsValidClusterID(cluster) {
			t.Errorf("IsValidClusterID(0x%08X) = false, want true", cluster)
		}
	}

	for _, cluster := range invalidClusters {
		if IsValidClusterID(cluster) {
			t.Errorf("IsValidClusterID(0x%08X) = true, want false", cluster)
		}
	}
}

func TestIsValidEndpointID(t *testing.T) {
	for _, ep := range validEndpoints {
		if !IsValidEndpointID(ep) {
			t.Errorf("IsValidEndpointID(0x%04X) = false, want true", ep)
		}
	}

	for _, ep := range invalidEndpoints {
		if IsValidEndpointID(ep) {
			t.Errorf("IsValidEndpointID(0x%04X) = true, want false", ep)
		}
	}
}

func TestIsValidDeviceTypeID(t *testing.T) {
	for _, dt := range validDeviceTypes {
		if !IsValidDeviceTypeID(dt) {
			t.Errorf("IsValidDeviceTypeID(0x%08X) = false, want true", dt)
		}
	}

	for _, dt := range invalidDeviceTypes {
		if IsValidDeviceTypeID(dt) {
			t.Errorf("IsValidDeviceTypeID(0x%08X) = true, want false", dt)
		}
	}
}
