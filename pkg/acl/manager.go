package acl

import (
	"errors"
	"sync"

	"github.com/backkem/matter/pkg/fabric"
)

// Manager errors.
var (
	ErrEntryNotFound    = errors.New("acl: entry not found")
	ErrTooManyEntries   = errors.New("acl: too many entries for fabric")
	ErrTooManySubjects  = errors.New("acl: too many subjects in entry")
	ErrTooManyTargets   = errors.New("acl: too many targets in entry")
	ErrFabricNotFound   = errors.New("acl: fabric not found")
	ErrIndexOutOfRange  = errors.New("acl: index out of range")
)

// Default limits per spec.
const (
	// DefaultMaxEntriesPerFabric is the minimum required by spec.
	DefaultMaxEntriesPerFabric = 4

	// DefaultMaxSubjectsPerEntry is the minimum required by spec.
	DefaultMaxSubjectsPerEntry = 4

	// DefaultMaxTargetsPerEntry is the minimum required by spec.
	DefaultMaxTargetsPerEntry = 3
)

// Store defines the interface for ACL persistence.
// Implementations can store entries in memory, flash, or other storage.
type Store interface {
	// Load returns all entries for a fabric.
	// Returns empty slice if no entries exist.
	Load(fabricIndex fabric.FabricIndex) ([]Entry, error)

	// Save persists an entry and returns its index within the fabric's entry list.
	Save(fabricIndex fabric.FabricIndex, entry Entry) (int, error)

	// Update replaces an entry at the given index.
	Update(fabricIndex fabric.FabricIndex, index int, entry Entry) error

	// Delete removes an entry at the given index.
	Delete(fabricIndex fabric.FabricIndex, index int) error

	// DeleteAllForFabric removes all entries for a fabric.
	DeleteAllForFabric(fabricIndex fabric.FabricIndex) error

	// Count returns the number of entries for a fabric.
	Count(fabricIndex fabric.FabricIndex) (int, error)
}

// MemoryStore is an in-memory implementation of Store for testing.
type MemoryStore struct {
	entries map[fabric.FabricIndex][]Entry
	mu      sync.RWMutex
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		entries: make(map[fabric.FabricIndex][]Entry),
	}
}

// Load returns all entries for a fabric.
func (s *MemoryStore) Load(fabricIndex fabric.FabricIndex) ([]Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries := s.entries[fabricIndex]
	result := make([]Entry, len(entries))
	copy(result, entries)
	return result, nil
}

// Save persists an entry and returns its index.
func (s *MemoryStore) Save(fabricIndex fabric.FabricIndex, entry Entry) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	index := len(s.entries[fabricIndex])
	s.entries[fabricIndex] = append(s.entries[fabricIndex], entry)
	return index, nil
}

// Update replaces an entry at the given index.
func (s *MemoryStore) Update(fabricIndex fabric.FabricIndex, index int, entry Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries := s.entries[fabricIndex]
	if index < 0 || index >= len(entries) {
		return ErrIndexOutOfRange
	}
	s.entries[fabricIndex][index] = entry
	return nil
}

// Delete removes an entry at the given index.
func (s *MemoryStore) Delete(fabricIndex fabric.FabricIndex, index int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries := s.entries[fabricIndex]
	if index < 0 || index >= len(entries) {
		return ErrIndexOutOfRange
	}

	// Remove entry at index
	s.entries[fabricIndex] = append(entries[:index], entries[index+1:]...)
	return nil
}

// DeleteAllForFabric removes all entries for a fabric.
func (s *MemoryStore) DeleteAllForFabric(fabricIndex fabric.FabricIndex) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, fabricIndex)
	return nil
}

// Count returns the number of entries for a fabric.
func (s *MemoryStore) Count(fabricIndex fabric.FabricIndex) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.entries[fabricIndex]), nil
}

// Manager coordinates ACL operations with storage and checking.
type Manager struct {
	checker *Checker
	store   Store
	mu      sync.RWMutex

	// Limits
	maxEntriesPerFabric int
	maxSubjectsPerEntry int
	maxTargetsPerEntry  int
}

// ManagerOption configures a Manager.
type ManagerOption func(*Manager)

// WithMaxEntriesPerFabric sets the maximum entries per fabric.
func WithMaxEntriesPerFabric(max int) ManagerOption {
	return func(m *Manager) {
		m.maxEntriesPerFabric = max
	}
}

// WithMaxSubjectsPerEntry sets the maximum subjects per entry.
func WithMaxSubjectsPerEntry(max int) ManagerOption {
	return func(m *Manager) {
		m.maxSubjectsPerEntry = max
	}
}

// WithMaxTargetsPerEntry sets the maximum targets per entry.
func WithMaxTargetsPerEntry(max int) ManagerOption {
	return func(m *Manager) {
		m.maxTargetsPerEntry = max
	}
}

// NewManager creates a new ACL manager.
// If store is nil, a MemoryStore is used.
// If resolver is nil, NullDeviceTypeResolver is used.
func NewManager(store Store, resolver DeviceTypeResolver, opts ...ManagerOption) *Manager {
	if store == nil {
		store = NewMemoryStore()
	}

	m := &Manager{
		checker:             NewChecker(resolver),
		store:               store,
		maxEntriesPerFabric: DefaultMaxEntriesPerFabric,
		maxSubjectsPerEntry: DefaultMaxSubjectsPerEntry,
		maxTargetsPerEntry:  DefaultMaxTargetsPerEntry,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Check performs an access control check.
func (m *Manager) Check(subject SubjectDescriptor, target RequestPath, privilege Privilege) Result {
	return m.checker.Check(subject, target, privilege)
}

// CreateEntry validates and stores a new ACL entry.
// Returns the index of the new entry within the fabric's entry list.
func (m *Manager) CreateEntry(fabricIndex fabric.FabricIndex, entry Entry) (int, error) {
	// Set fabric index
	entry.FabricIndex = fabricIndex

	// Validate entry
	if err := ValidateEntry(&entry); err != nil {
		return -1, err
	}

	// Check limits
	if len(entry.Subjects) > m.maxSubjectsPerEntry {
		return -1, ErrTooManySubjects
	}
	if len(entry.Targets) > m.maxTargetsPerEntry {
		return -1, ErrTooManyTargets
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check entry count limit
	count, err := m.store.Count(fabricIndex)
	if err != nil {
		return -1, err
	}
	if count >= m.maxEntriesPerFabric {
		return -1, ErrTooManyEntries
	}

	// Save to store
	index, err := m.store.Save(fabricIndex, entry)
	if err != nil {
		return -1, err
	}

	// Reload checker
	if err := m.reloadChecker(); err != nil {
		return -1, err
	}

	return index, nil
}

// UpdateEntry replaces an entry at the given index.
func (m *Manager) UpdateEntry(fabricIndex fabric.FabricIndex, index int, entry Entry) error {
	// Set fabric index
	entry.FabricIndex = fabricIndex

	// Validate entry
	if err := ValidateEntry(&entry); err != nil {
		return err
	}

	// Check limits
	if len(entry.Subjects) > m.maxSubjectsPerEntry {
		return ErrTooManySubjects
	}
	if len(entry.Targets) > m.maxTargetsPerEntry {
		return ErrTooManyTargets
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Update in store
	if err := m.store.Update(fabricIndex, index, entry); err != nil {
		return err
	}

	// Reload checker
	return m.reloadChecker()
}

// DeleteEntry removes an entry.
func (m *Manager) DeleteEntry(fabricIndex fabric.FabricIndex, index int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.store.Delete(fabricIndex, index); err != nil {
		return err
	}

	return m.reloadChecker()
}

// GetEntries returns all entries for a fabric.
func (m *Manager) GetEntries(fabricIndex fabric.FabricIndex) ([]Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.store.Load(fabricIndex)
}

// GetEntry returns a specific entry.
func (m *Manager) GetEntry(fabricIndex fabric.FabricIndex, index int) (*Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entries, err := m.store.Load(fabricIndex)
	if err != nil {
		return nil, err
	}

	if index < 0 || index >= len(entries) {
		return nil, ErrEntryNotFound
	}

	return &entries[index], nil
}

// GetEntryCount returns the number of entries for a fabric.
func (m *Manager) GetEntryCount(fabricIndex fabric.FabricIndex) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.store.Count(fabricIndex)
}

// DeleteAllForFabric removes all entries for a fabric.
// Called when a fabric is removed.
func (m *Manager) DeleteAllForFabric(fabricIndex fabric.FabricIndex) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.store.DeleteAllForFabric(fabricIndex); err != nil {
		return err
	}

	return m.reloadChecker()
}

// reloadChecker rebuilds the checker's entry list from the store.
// Must be called with m.mu held.
func (m *Manager) reloadChecker() error {
	// Collect all entries from all fabrics
	var allEntries []Entry

	// Load entries for fabrics 1-254
	for fi := fabric.FabricIndexMin; fi <= fabric.FabricIndexMax; fi++ {
		entries, err := m.store.Load(fi)
		if err != nil {
			return err
		}
		allEntries = append(allEntries, entries...)
	}

	m.checker.SetEntries(allEntries)
	return nil
}

// LoadFromStore reloads all entries from the store into the checker.
// Call this after initializing the manager if the store has persisted entries.
func (m *Manager) LoadFromStore() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.reloadChecker()
}
