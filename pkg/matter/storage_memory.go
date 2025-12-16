package matter

import (
	"sync"

	"github.com/backkem/matter/pkg/acl"
	"github.com/backkem/matter/pkg/fabric"
)

// MemoryStorage is an in-memory Storage implementation.
// Useful for testing and development. Data is lost when the process exits.
//
// All methods are safe for concurrent use.
type MemoryStorage struct {
	mu sync.RWMutex

	fabrics   map[fabric.FabricIndex]*fabric.FabricInfo
	acls      []*acl.Entry
	counters  *CounterState
	groupKeys []GroupKeyEntry
}

// NewMemoryStorage creates a new in-memory storage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		fabrics:   make(map[fabric.FabricIndex]*fabric.FabricInfo),
		acls:      make([]*acl.Entry, 0),
		counters:  NewCounterState(),
		groupKeys: make([]GroupKeyEntry, 0),
	}
}

// LoadFabrics returns all stored fabrics.
func (m *MemoryStorage) LoadFabrics() ([]*fabric.FabricInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*fabric.FabricInfo, 0, len(m.fabrics))
	for _, f := range m.fabrics {
		result = append(result, f.Clone())
	}
	return result, nil
}

// SaveFabric stores or updates a fabric.
func (m *MemoryStorage) SaveFabric(info *fabric.FabricInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.fabrics[info.FabricIndex] = info.Clone()
	return nil
}

// DeleteFabric removes a fabric by index.
func (m *MemoryStorage) DeleteFabric(index fabric.FabricIndex) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.fabrics, index)

	// Also remove ACLs for this fabric
	filtered := make([]*acl.Entry, 0, len(m.acls))
	for _, e := range m.acls {
		if e.FabricIndex != index {
			filtered = append(filtered, e)
		}
	}
	m.acls = filtered

	return nil
}

// LoadACLs returns all stored ACL entries.
func (m *MemoryStorage) LoadACLs() ([]*acl.Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*acl.Entry, len(m.acls))
	for i, e := range m.acls {
		// Clone the entry
		clone := *e
		if e.Subjects != nil {
			clone.Subjects = make([]uint64, len(e.Subjects))
			copy(clone.Subjects, e.Subjects)
		}
		if e.Targets != nil {
			clone.Targets = make([]acl.Target, len(e.Targets))
			copy(clone.Targets, e.Targets)
		}
		result[i] = &clone
	}
	return result, nil
}

// SaveACLs replaces all ACL entries.
func (m *MemoryStorage) SaveACLs(entries []*acl.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.acls = make([]*acl.Entry, len(entries))
	for i, e := range entries {
		clone := *e
		if e.Subjects != nil {
			clone.Subjects = make([]uint64, len(e.Subjects))
			copy(clone.Subjects, e.Subjects)
		}
		if e.Targets != nil {
			clone.Targets = make([]acl.Target, len(e.Targets))
			copy(clone.Targets, e.Targets)
		}
		m.acls[i] = &clone
	}
	return nil
}

// LoadCounters returns the stored counter state.
func (m *MemoryStorage) LoadCounters() (*CounterState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.counters.Clone(), nil
}

// SaveCounters stores the counter state.
func (m *MemoryStorage) SaveCounters(state *CounterState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.counters = state.Clone()
	return nil
}

// LoadGroupKeys returns all stored group keys.
func (m *MemoryStorage) LoadGroupKeys() ([]GroupKeyEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]GroupKeyEntry, len(m.groupKeys))
	copy(result, m.groupKeys)
	return result, nil
}

// SaveGroupKeys replaces all group keys.
func (m *MemoryStorage) SaveGroupKeys(keys []GroupKeyEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.groupKeys = make([]GroupKeyEntry, len(keys))
	copy(m.groupKeys, keys)
	return nil
}

// Clear removes all stored data.
func (m *MemoryStorage) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.fabrics = make(map[fabric.FabricIndex]*fabric.FabricInfo)
	m.acls = make([]*acl.Entry, 0)
	m.counters = NewCounterState()
	m.groupKeys = make([]GroupKeyEntry, 0)
}

// Verify MemoryStorage implements Storage.
var _ Storage = (*MemoryStorage)(nil)
