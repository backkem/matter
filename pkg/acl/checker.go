package acl

import "sync"

// DeviceTypeResolver resolves whether a device type is present on an endpoint.
// This interface allows the ACL checker to support device-type-based targets
// without depending on the data model package directly.
type DeviceTypeResolver interface {
	// IsDeviceTypeOnEndpoint returns true if the endpoint supports the device type.
	IsDeviceTypeOnEndpoint(deviceType uint32, endpoint uint16) bool
}

// NullDeviceTypeResolver is a resolver that always returns false.
// Use this when device type matching is not needed or not yet implemented.
type NullDeviceTypeResolver struct{}

// IsDeviceTypeOnEndpoint always returns false.
func (NullDeviceTypeResolver) IsDeviceTypeOnEndpoint(uint32, uint16) bool {
	return false
}

// Checker performs access control checks against an ACL.
// It implements the algorithm from Spec 6.6.6.2.
type Checker struct {
	entries            []Entry
	deviceTypeResolver DeviceTypeResolver
	mu                 sync.RWMutex
}

// NewChecker creates a new access control checker.
// If resolver is nil, NullDeviceTypeResolver is used.
func NewChecker(resolver DeviceTypeResolver) *Checker {
	if resolver == nil {
		resolver = NullDeviceTypeResolver{}
	}
	return &Checker{
		deviceTypeResolver: resolver,
	}
}

// SetEntries replaces all ACL entries.
// Entries are copied to prevent external modification.
func (c *Checker) SetEntries(entries []Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make([]Entry, len(entries))
	copy(c.entries, entries)
}

// GetEntries returns a copy of all ACL entries.
func (c *Checker) GetEntries() []Entry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]Entry, len(c.entries))
	copy(result, c.entries)
	return result
}

// AddEntry adds an ACL entry. Returns error if entry is invalid.
func (c *Checker) AddEntry(entry Entry) error {
	if err := ValidateEntry(&entry); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = append(c.entries, entry)
	return nil
}

// Check evaluates whether the subject has the required privilege on the target.
// Implements Spec 6.6.6.2 "Overall Algorithm".
//
// The algorithm:
//  1. If PASE during commissioning: implicit Administer privilege (allow all)
//  2. For each ACL entry:
//     a. FabricIndex must match
//     b. AuthMode must match
//     c. Entry's privilege must grant the requested privilege
//     d. Subject must match (empty = wildcard, or exact/CAT match)
//     e. Target must match (empty = wildcard, or cluster/endpoint/devicetype match)
//  3. First matching entry grants access; no match = denied
func (c *Checker) Check(subject SubjectDescriptor, target RequestPath, required Privilege) Result {
	// Step 1: PASE commissioning gets implicit Administer
	// Spec 6.6.2.9: "Bootstrapping of the Access Control List"
	if subject.AuthMode == AuthModePASE && subject.IsCommissioning {
		return ResultAllowed
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Step 2: Check each ACL entry
	for i := range c.entries {
		entry := &c.entries[i]

		// 2a: FabricIndex must match (0 is invalid for stored entries)
		if entry.FabricIndex == 0 {
			continue
		}
		if entry.FabricIndex != subject.FabricIndex {
			continue
		}

		// 2b: AuthMode must match
		if entry.AuthMode != subject.AuthMode {
			continue
		}

		// 2c: Check privilege grants the requested privilege
		if !entry.Privilege.Grants(required) {
			continue
		}

		// 2d: Check subject match
		if !c.subjectMatches(entry, &subject) {
			continue
		}

		// 2e: Check target match
		if !c.targetMatches(entry, &target) {
			continue
		}

		// Match found!
		return ResultAllowed
	}

	// Step 3: No matching entry
	return ResultDenied
}

// subjectMatches checks if the subject descriptor matches the entry's subjects.
// Empty subjects list = wildcard (matches any subject for CASE/Group).
// Spec 6.6.6.2: subject_matches function
func (c *Checker) subjectMatches(entry *Entry, subject *SubjectDescriptor) bool {
	// Empty subjects list = wildcard
	if len(entry.Subjects) == 0 {
		// Precondition: only CASE and Group can have empty subjects
		return entry.AuthMode == AuthModeCASE || entry.AuthMode == AuthModeGroup
	}

	// Non-empty requires a match
	for _, aclSubject := range entry.Subjects {
		// Check primary subject match
		if c.singleSubjectMatches(aclSubject, subject) {
			return true
		}
	}

	return false
}

// singleSubjectMatches checks if a single ACL subject matches the subject descriptor.
// Implements the subject_matches logic from Spec 6.6.6.2.
func (c *Checker) singleSubjectMatches(aclSubject uint64, subject *SubjectDescriptor) bool {
	// Exact match on primary subject
	if aclSubject == subject.Subject {
		return true
	}

	// CAT matching for CASE auth mode
	// If ACL subject is a CAT, check against the subject's CATs
	if subject.AuthMode == AuthModeCASE && IsCATNodeID(aclSubject) {
		// Check if any of the subject's CATs match this ACL CAT subject
		// The subject's CAT must have same identifier and version >= ACL CAT version
		if subject.CATs.CheckSubjectAgainstCATs(aclSubject) {
			return true
		}
	}

	return false
}

// targetMatches checks if the request path matches the entry's targets.
// Empty targets list = wildcard (matches all targets).
// Spec 6.6.6.2: target matching logic
func (c *Checker) targetMatches(entry *Entry, path *RequestPath) bool {
	// Empty targets = wildcard
	if len(entry.Targets) == 0 {
		return true
	}

	// Non-empty requires a match
	for i := range entry.Targets {
		target := &entry.Targets[i]

		if c.singleTargetMatches(target, path) {
			return true
		}
	}

	return false
}

// singleTargetMatches checks if a single ACL target matches the request path.
func (c *Checker) singleTargetMatches(target *Target, path *RequestPath) bool {
	// Cluster must match if specified
	if target.Cluster != nil && *target.Cluster != path.Cluster {
		return false
	}

	// Endpoint must match if specified
	if target.Endpoint != nil && *target.Endpoint != path.Endpoint {
		return false
	}

	// Device type: endpoint must support the device type
	if target.DeviceType != nil {
		if !c.deviceTypeResolver.IsDeviceTypeOnEndpoint(*target.DeviceType, path.Endpoint) {
			return false
		}
	}

	return true
}
