package fabric

import (
	"errors"
	"fmt"
	"sync"
)

// Table errors.
var (
	// ErrTableFull is returned when the fabric table is full.
	ErrTableFull = errors.New("fabric: table full")
	// ErrFabricNotFound is returned when a fabric is not found.
	ErrFabricNotFound = errors.New("fabric: not found")
	// ErrFabricConflict is returned when adding a fabric that conflicts with existing.
	ErrFabricConflict = errors.New("fabric: fabric already exists with same root key and fabric ID")
	// ErrLabelConflict is returned when a label is already in use by another fabric.
	ErrLabelConflict = errors.New("fabric: label already in use")
	// ErrFabricIndexInUse is returned when a fabric index is already in use.
	ErrFabricIndexInUse = errors.New("fabric: fabric index already in use")
)

// TableConfig configures the fabric table.
type TableConfig struct {
	// MaxFabrics is the maximum number of fabrics supported (SupportedFabrics attribute).
	// Valid range: 5-254. Default: 5.
	MaxFabrics uint8
}

// DefaultTableConfig returns the default table configuration.
func DefaultTableConfig() TableConfig {
	return TableConfig{
		MaxFabrics: DefaultSupportedFabrics,
	}
}

// Table manages the fabric table.
//
// The fabric table stores all fabrics to which a node is commissioned.
// It provides thread-safe access to fabric entries and implements the
// backend for the Operational Credentials Cluster attributes.
//
// Thread Safety: All methods are safe for concurrent use.
type Table struct {
	mu      sync.RWMutex
	fabrics map[FabricIndex]*FabricInfo
	config  TableConfig
}

// NewTable creates a new fabric table with the given configuration.
func NewTable(config TableConfig) *Table {
	// Clamp max fabrics to valid range
	if config.MaxFabrics < MinSupportedFabrics {
		config.MaxFabrics = MinSupportedFabrics
	}
	if config.MaxFabrics > MaxSupportedFabrics {
		config.MaxFabrics = MaxSupportedFabrics
	}

	return &Table{
		fabrics: make(map[FabricIndex]*FabricInfo),
		config:  config,
	}
}

// Add adds a new fabric to the table.
//
// Returns ErrTableFull if the table is at capacity.
// Returns ErrFabricIndexInUse if the fabric index is already in use.
// Returns ErrFabricConflict if a fabric with the same root key and fabric ID exists.
func (t *Table) Add(info *FabricInfo) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check capacity
	if len(t.fabrics) >= int(t.config.MaxFabrics) {
		return ErrTableFull
	}

	// Check if index is already in use
	if _, exists := t.fabrics[info.FabricIndex]; exists {
		return ErrFabricIndexInUse
	}

	// Check for conflict (same root key + fabric ID)
	for _, existing := range t.fabrics {
		if existing.MatchesRootPublicKey(info.RootPublicKey) &&
			existing.FabricID == info.FabricID {
			return ErrFabricConflict
		}
	}

	// Store a clone to prevent external modification
	t.fabrics[info.FabricIndex] = info.Clone()
	return nil
}

// Remove removes a fabric from the table by index.
//
// Returns ErrFabricNotFound if the fabric doesn't exist.
func (t *Table) Remove(index FabricIndex) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, exists := t.fabrics[index]; !exists {
		return ErrFabricNotFound
	}

	delete(t.fabrics, index)
	return nil
}

// Get returns a fabric by index.
//
// Returns (nil, false) if the fabric doesn't exist.
// The returned FabricInfo is a clone - modifications won't affect the table.
func (t *Table) Get(index FabricIndex) (*FabricInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	info, exists := t.fabrics[index]
	if !exists {
		return nil, false
	}
	return info.Clone(), true
}

// Update atomically updates a fabric in the table.
//
// The update function receives a pointer to the fabric info which can be
// modified in place. Changes are persisted when the function returns without error.
//
// Returns ErrFabricNotFound if the fabric doesn't exist.
func (t *Table) Update(index FabricIndex, fn func(*FabricInfo) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	info, exists := t.fabrics[index]
	if !exists {
		return ErrFabricNotFound
	}

	return fn(info)
}

// FindByRootPublicKey returns the fabric with the given root public key.
//
// Returns (nil, false) if no matching fabric is found.
func (t *Table) FindByRootPublicKey(rootPubKey [RootPublicKeySize]byte) (*FabricInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, info := range t.fabrics {
		if info.MatchesRootPublicKey(rootPubKey) {
			return info.Clone(), true
		}
	}
	return nil, false
}

// FindByCompressedFabricID returns the fabric with the given compressed fabric ID.
//
// Returns (nil, false) if no matching fabric is found.
func (t *Table) FindByCompressedFabricID(cfid [CompressedFabricIDSize]byte) (*FabricInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, info := range t.fabrics {
		if info.MatchesCompressedFabricID(cfid) {
			return info.Clone(), true
		}
	}
	return nil, false
}

// FindByFabricID returns the fabric with the given fabric ID.
//
// Note: Multiple fabrics could theoretically have the same fabric ID with
// different root CAs (though this is unusual). This returns the first match.
//
// Returns (nil, false) if no matching fabric is found.
func (t *Table) FindByFabricID(fabricID FabricID) (*FabricInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, info := range t.fabrics {
		if info.FabricID == fabricID {
			return info.Clone(), true
		}
	}
	return nil, false
}

// FindByRootAndFabricID returns the fabric matching both root public key and fabric ID.
// This is the full "fabric reference" lookup.
//
// Returns (nil, false) if no matching fabric is found.
func (t *Table) FindByRootAndFabricID(rootPubKey [RootPublicKeySize]byte, fabricID FabricID) (*FabricInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, info := range t.fabrics {
		if info.MatchesRootPublicKey(rootPubKey) && info.FabricID == fabricID {
			return info.Clone(), true
		}
	}
	return nil, false
}

// List returns all fabrics in the table.
//
// The returned slice contains clones - modifications won't affect the table.
func (t *Table) List() []*FabricInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]*FabricInfo, 0, len(t.fabrics))
	for _, info := range t.fabrics {
		result = append(result, info.Clone())
	}
	return result
}

// Count returns the number of fabrics in the table.
func (t *Table) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.fabrics)
}

// SupportedFabrics returns the maximum number of supported fabrics.
func (t *Table) SupportedFabrics() uint8 {
	return t.config.MaxFabrics
}

// CommissionedFabrics returns the current number of commissioned fabrics.
func (t *Table) CommissionedFabrics() uint8 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return uint8(len(t.fabrics))
}

// AllocateFabricIndex returns the next available fabric index.
//
// Returns ErrTableFull if no index is available.
func (t *Table) AllocateFabricIndex() (FabricIndex, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Check capacity first
	if len(t.fabrics) >= int(t.config.MaxFabrics) {
		return FabricIndexInvalid, ErrTableFull
	}

	// Find first unused index (1-254)
	for idx := FabricIndexMin; idx <= FabricIndexMax; idx++ {
		if _, exists := t.fabrics[idx]; !exists {
			return idx, nil
		}
	}

	return FabricIndexInvalid, ErrTableFull
}

// IsFabricIndexInUse returns true if the fabric index is currently in use.
func (t *Table) IsFabricIndexInUse(index FabricIndex) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, exists := t.fabrics[index]
	return exists
}

// UpdateLabel updates the label for a fabric.
//
// Returns ErrFabricNotFound if the fabric doesn't exist.
// Returns ErrLabelConflict if the label is already used by another fabric.
// Returns ErrInvalidLabel if the label exceeds max length.
func (t *Table) UpdateLabel(index FabricIndex, label string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	info, exists := t.fabrics[index]
	if !exists {
		return ErrFabricNotFound
	}

	// Check label uniqueness (if non-empty)
	if label != "" {
		for idx, other := range t.fabrics {
			if idx != index && other.Label == label {
				return ErrLabelConflict
			}
		}
	}

	return info.SetLabel(label)
}

// IsLabelInUse returns true if the label is used by any fabric except excludeIndex.
func (t *Table) IsLabelInUse(label string, excludeIndex FabricIndex) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if label == "" {
		return false
	}

	for idx, info := range t.fabrics {
		if idx != excludeIndex && info.Label == label {
			return true
		}
	}
	return false
}

// GetNOCsList returns the NOCs attribute value (list of NOCStruct for all fabrics).
func (t *Table) GetNOCsList() []NOCStruct {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]NOCStruct, 0, len(t.fabrics))
	for _, info := range t.fabrics {
		result = append(result, info.GetNOCStruct())
	}
	return result
}

// GetFabricsList returns the Fabrics attribute value (list of FabricDescriptorStruct).
func (t *Table) GetFabricsList() []FabricDescriptorStruct {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]FabricDescriptorStruct, 0, len(t.fabrics))
	for _, info := range t.fabrics {
		result = append(result, info.GetFabricDescriptor())
	}
	return result
}

// GetTrustedRootCertificates returns the TrustedRootCertificates attribute value.
func (t *Table) GetTrustedRootCertificates() [][]byte {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([][]byte, 0, len(t.fabrics))
	for _, info := range t.fabrics {
		// Return a copy of each root cert
		cert := make([]byte, len(info.RootCert))
		copy(cert, info.RootCert)
		result = append(result, cert)
	}
	return result
}

// Clear removes all fabrics from the table (factory reset).
func (t *Table) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fabrics = make(map[FabricIndex]*FabricInfo)
}

// ForEach iterates over all fabrics in the table.
//
// The callback receives a read-only view of each fabric. To modify a fabric,
// use Update() instead. If the callback returns an error, iteration stops
// and that error is returned.
func (t *Table) ForEach(fn func(*FabricInfo) error) error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, info := range t.fabrics {
		if err := fn(info); err != nil {
			return err
		}
	}
	return nil
}

// String returns a summary of the fabric table.
func (t *Table) String() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return fmt.Sprintf("FabricTable{Count=%d, Max=%d}", len(t.fabrics), t.config.MaxFabrics)
}
