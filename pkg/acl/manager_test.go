package acl

import (
	"testing"

	"github.com/backkem/matter/pkg/fabric"
)

func TestMemoryStore_BasicOps(t *testing.T) {
	store := NewMemoryStore()

	// Initially empty
	entries, err := store.Load(1)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Load() returned %d entries, want 0", len(entries))
	}

	count, err := store.Count(1)
	if err != nil {
		t.Fatalf("Count() error: %v", err)
	}
	if count != 0 {
		t.Errorf("Count() = %d, want 0", count)
	}

	// Save an entry
	entry := Entry{
		FabricIndex: 1,
		Privilege:   PrivilegeView,
		AuthMode:    AuthModeCASE,
	}

	index, err := store.Save(1, entry)
	if err != nil {
		t.Fatalf("Save() error: %v", err)
	}
	if index != 0 {
		t.Errorf("Save() returned index %d, want 0", index)
	}

	// Verify count
	count, err = store.Count(1)
	if err != nil {
		t.Fatalf("Count() error: %v", err)
	}
	if count != 1 {
		t.Errorf("Count() = %d, want 1", count)
	}

	// Load and verify
	entries, err = store.Load(1)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Load() returned %d entries, want 1", len(entries))
	}
	if entries[0].Privilege != PrivilegeView {
		t.Errorf("entries[0].Privilege = %v, want View", entries[0].Privilege)
	}

	// Update entry
	entry.Privilege = PrivilegeOperate
	if err := store.Update(1, 0, entry); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	entries, _ = store.Load(1)
	if entries[0].Privilege != PrivilegeOperate {
		t.Errorf("After update, Privilege = %v, want Operate", entries[0].Privilege)
	}

	// Delete entry
	if err := store.Delete(1, 0); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	count, _ = store.Count(1)
	if count != 0 {
		t.Errorf("After delete, Count() = %d, want 0", count)
	}
}

func TestMemoryStore_MultipleFabrics(t *testing.T) {
	store := NewMemoryStore()

	// Add entries to different fabrics
	store.Save(1, Entry{FabricIndex: 1, Privilege: PrivilegeView, AuthMode: AuthModeCASE})
	store.Save(1, Entry{FabricIndex: 1, Privilege: PrivilegeOperate, AuthMode: AuthModeCASE})
	store.Save(2, Entry{FabricIndex: 2, Privilege: PrivilegeManage, AuthMode: AuthModeCASE})

	// Verify counts
	count1, _ := store.Count(1)
	count2, _ := store.Count(2)
	count3, _ := store.Count(3)

	if count1 != 2 {
		t.Errorf("Fabric 1 count = %d, want 2", count1)
	}
	if count2 != 1 {
		t.Errorf("Fabric 2 count = %d, want 1", count2)
	}
	if count3 != 0 {
		t.Errorf("Fabric 3 count = %d, want 0", count3)
	}

	// Delete all for fabric 1
	if err := store.DeleteAllForFabric(1); err != nil {
		t.Fatalf("DeleteAllForFabric() error: %v", err)
	}

	count1, _ = store.Count(1)
	count2, _ = store.Count(2)

	if count1 != 0 {
		t.Errorf("After delete, fabric 1 count = %d, want 0", count1)
	}
	if count2 != 1 {
		t.Errorf("Fabric 2 should be unaffected, count = %d, want 1", count2)
	}
}

func TestMemoryStore_IndexOutOfRange(t *testing.T) {
	store := NewMemoryStore()
	store.Save(1, Entry{FabricIndex: 1, AuthMode: AuthModeCASE})

	// Update non-existent
	err := store.Update(1, 5, Entry{})
	if err != ErrIndexOutOfRange {
		t.Errorf("Update(5) error = %v, want ErrIndexOutOfRange", err)
	}

	// Delete non-existent
	err = store.Delete(1, 5)
	if err != ErrIndexOutOfRange {
		t.Errorf("Delete(5) error = %v, want ErrIndexOutOfRange", err)
	}

	// Negative index
	err = store.Update(1, -1, Entry{})
	if err != ErrIndexOutOfRange {
		t.Errorf("Update(-1) error = %v, want ErrIndexOutOfRange", err)
	}
}

func TestManager_NewManager(t *testing.T) {
	// With defaults
	m := NewManager(nil, nil)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}

	// With custom options
	m = NewManager(nil, nil,
		WithMaxEntriesPerFabric(10),
		WithMaxSubjectsPerEntry(8),
		WithMaxTargetsPerEntry(5),
	)
	if m.maxEntriesPerFabric != 10 {
		t.Errorf("maxEntriesPerFabric = %d, want 10", m.maxEntriesPerFabric)
	}
}

func TestManager_CreateEntry(t *testing.T) {
	m := NewManager(nil, nil)

	entry := Entry{
		Privilege: PrivilegeView,
		AuthMode:  AuthModeCASE,
		Subjects:  []uint64{0x1111_1111_1111_1111},
		Targets:   []Target{NewTargetCluster(0x0006)},
	}

	index, err := m.CreateEntry(1, entry)
	if err != nil {
		t.Fatalf("CreateEntry() error: %v", err)
	}
	if index != 0 {
		t.Errorf("CreateEntry() index = %d, want 0", index)
	}

	// Verify it was stored
	entries, err := m.GetEntries(1)
	if err != nil {
		t.Fatalf("GetEntries() error: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("GetEntries() returned %d entries, want 1", len(entries))
	}

	// Verify fabric index was set
	if entries[0].FabricIndex != 1 {
		t.Errorf("Entry FabricIndex = %d, want 1", entries[0].FabricIndex)
	}
}

func TestManager_CreateEntry_Validation(t *testing.T) {
	m := NewManager(nil, nil)

	// Invalid auth mode
	_, err := m.CreateEntry(1, Entry{
		Privilege: PrivilegeView,
		AuthMode:  AuthModePASE, // Not allowed in stored entries
	})
	if err != ErrInvalidAuthMode {
		t.Errorf("CreateEntry(PASE) error = %v, want ErrInvalidAuthMode", err)
	}

	// Invalid subject for auth mode
	_, err = m.CreateEntry(1, Entry{
		Privilege: PrivilegeView,
		AuthMode:  AuthModeCASE,
		Subjects:  []uint64{NodeIDFromGroupID(0x0002)}, // Group ID for CASE
	})
	if err != ErrInvalidSubject {
		t.Errorf("CreateEntry(wrong subject) error = %v, want ErrInvalidSubject", err)
	}
}

func TestManager_CreateEntry_Limits(t *testing.T) {
	m := NewManager(nil, nil, WithMaxEntriesPerFabric(2))

	entry := Entry{
		Privilege: PrivilegeView,
		AuthMode:  AuthModeCASE,
	}

	// First two should succeed
	if _, err := m.CreateEntry(1, entry); err != nil {
		t.Errorf("CreateEntry(1) error: %v", err)
	}
	if _, err := m.CreateEntry(1, entry); err != nil {
		t.Errorf("CreateEntry(2) error: %v", err)
	}

	// Third should fail
	_, err := m.CreateEntry(1, entry)
	if err != ErrTooManyEntries {
		t.Errorf("CreateEntry(3) error = %v, want ErrTooManyEntries", err)
	}

	// Different fabric should still work
	if _, err := m.CreateEntry(2, entry); err != nil {
		t.Errorf("CreateEntry(fabric 2) error: %v", err)
	}
}

func TestManager_CreateEntry_SubjectLimit(t *testing.T) {
	m := NewManager(nil, nil, WithMaxSubjectsPerEntry(2))

	entry := Entry{
		Privilege: PrivilegeView,
		AuthMode:  AuthModeCASE,
		Subjects:  []uint64{0x1111_1111_1111_1111, 0x2222_2222_2222_2222, 0x3333_3333_3333_3333},
	}

	_, err := m.CreateEntry(1, entry)
	if err != ErrTooManySubjects {
		t.Errorf("CreateEntry error = %v, want ErrTooManySubjects", err)
	}
}

func TestManager_CreateEntry_TargetLimit(t *testing.T) {
	m := NewManager(nil, nil, WithMaxTargetsPerEntry(1))

	entry := Entry{
		Privilege: PrivilegeView,
		AuthMode:  AuthModeCASE,
		Targets:   []Target{NewTargetCluster(0x0006), NewTargetEndpoint(1)},
	}

	_, err := m.CreateEntry(1, entry)
	if err != ErrTooManyTargets {
		t.Errorf("CreateEntry error = %v, want ErrTooManyTargets", err)
	}
}

func TestManager_UpdateEntry(t *testing.T) {
	m := NewManager(nil, nil)

	// Create initial entry
	entry := Entry{
		Privilege: PrivilegeView,
		AuthMode:  AuthModeCASE,
	}
	m.CreateEntry(1, entry)

	// Update it
	entry.Privilege = PrivilegeOperate
	err := m.UpdateEntry(1, 0, entry)
	if err != nil {
		t.Fatalf("UpdateEntry() error: %v", err)
	}

	// Verify update
	got, err := m.GetEntry(1, 0)
	if err != nil {
		t.Fatalf("GetEntry() error: %v", err)
	}
	if got.Privilege != PrivilegeOperate {
		t.Errorf("After update, Privilege = %v, want Operate", got.Privilege)
	}
}

func TestManager_DeleteEntry(t *testing.T) {
	m := NewManager(nil, nil)

	// Create entries
	m.CreateEntry(1, Entry{Privilege: PrivilegeView, AuthMode: AuthModeCASE})
	m.CreateEntry(1, Entry{Privilege: PrivilegeOperate, AuthMode: AuthModeCASE})

	// Delete first
	err := m.DeleteEntry(1, 0)
	if err != nil {
		t.Fatalf("DeleteEntry() error: %v", err)
	}

	// Verify count
	count, _ := m.GetEntryCount(1)
	if count != 1 {
		t.Errorf("After delete, count = %d, want 1", count)
	}

	// Remaining entry should be the second one
	entries, _ := m.GetEntries(1)
	if entries[0].Privilege != PrivilegeOperate {
		t.Errorf("Remaining entry Privilege = %v, want Operate", entries[0].Privilege)
	}
}

func TestManager_GetEntry_NotFound(t *testing.T) {
	m := NewManager(nil, nil)

	_, err := m.GetEntry(1, 0)
	if err != ErrEntryNotFound {
		t.Errorf("GetEntry(nonexistent) error = %v, want ErrEntryNotFound", err)
	}
}

func TestManager_DeleteAllForFabric(t *testing.T) {
	m := NewManager(nil, nil)

	// Create entries in multiple fabrics
	m.CreateEntry(1, Entry{Privilege: PrivilegeView, AuthMode: AuthModeCASE})
	m.CreateEntry(1, Entry{Privilege: PrivilegeOperate, AuthMode: AuthModeCASE})
	m.CreateEntry(2, Entry{Privilege: PrivilegeManage, AuthMode: AuthModeCASE})

	// Delete fabric 1
	err := m.DeleteAllForFabric(1)
	if err != nil {
		t.Fatalf("DeleteAllForFabric() error: %v", err)
	}

	count1, _ := m.GetEntryCount(1)
	count2, _ := m.GetEntryCount(2)

	if count1 != 0 {
		t.Errorf("Fabric 1 count = %d, want 0", count1)
	}
	if count2 != 1 {
		t.Errorf("Fabric 2 should be unaffected, count = %d, want 1", count2)
	}
}

func TestManager_Check_Integration(t *testing.T) {
	m := NewManager(nil, nil)

	// Create admin entry
	m.CreateEntry(1, Entry{
		Privilege: PrivilegeAdminister,
		AuthMode:  AuthModeCASE,
		Subjects:  []uint64{0x1111_1111_1111_1111},
	})

	subject := SubjectDescriptor{
		FabricIndex: 1,
		AuthMode:    AuthModeCASE,
		Subject:     0x1111_1111_1111_1111,
	}
	path := NewRequestPath(0x001F, 0, RequestTypeAttributeWrite)

	// Should be allowed
	result := m.Check(subject, path, PrivilegeAdminister)
	if result != ResultAllowed {
		t.Errorf("Check() = %v, want Allowed", result)
	}

	// Delete the entry
	m.DeleteEntry(1, 0)

	// Should now be denied
	result = m.Check(subject, path, PrivilegeAdminister)
	if result != ResultDenied {
		t.Errorf("After delete, Check() = %v, want Denied", result)
	}
}

func TestManager_LoadFromStore(t *testing.T) {
	store := NewMemoryStore()

	// Pre-populate store
	store.Save(1, Entry{
		FabricIndex: 1,
		Privilege:   PrivilegeAdminister,
		AuthMode:    AuthModeCASE,
		Subjects:    []uint64{0x1111_1111_1111_1111},
	})

	// Create manager with existing store
	m := NewManager(store, nil)

	// Initially checker is empty
	subject := SubjectDescriptor{
		FabricIndex: 1,
		AuthMode:    AuthModeCASE,
		Subject:     0x1111_1111_1111_1111,
	}
	path := NewRequestPath(0x001F, 0, RequestTypeAttributeRead)

	result := m.Check(subject, path, PrivilegeAdminister)
	if result != ResultDenied {
		t.Errorf("Before LoadFromStore, Check() = %v, want Denied", result)
	}

	// Load from store
	if err := m.LoadFromStore(); err != nil {
		t.Fatalf("LoadFromStore() error: %v", err)
	}

	// Now should work
	result = m.Check(subject, path, PrivilegeAdminister)
	if result != ResultAllowed {
		t.Errorf("After LoadFromStore, Check() = %v, want Allowed", result)
	}
}

func BenchmarkManager_CreateEntry(b *testing.B) {
	m := NewManager(nil, nil, WithMaxEntriesPerFabric(10000))

	entry := Entry{
		Privilege: PrivilegeView,
		AuthMode:  AuthModeCASE,
		Subjects:  []uint64{0x1111_1111_1111_1111},
		Targets:   []Target{NewTargetCluster(0x0006)},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.CreateEntry(fabric.FabricIndex(i%254+1), entry)
	}
}

func BenchmarkManager_Check(b *testing.B) {
	m := NewManager(nil, nil, WithMaxEntriesPerFabric(100))

	// Create entries
	for i := 0; i < 50; i++ {
		m.CreateEntry(1, Entry{
			Privilege: PrivilegeOperate,
			AuthMode:  AuthModeCASE,
			Subjects:  []uint64{uint64(i) + 1},
			Targets:   []Target{NewTargetCluster(uint32(i))},
		})
	}

	subject := SubjectDescriptor{
		FabricIndex: 1,
		AuthMode:    AuthModeCASE,
		Subject:     25,
	}
	path := NewRequestPath(24, 1, RequestTypeAttributeRead)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Check(subject, path, PrivilegeOperate)
	}
}
