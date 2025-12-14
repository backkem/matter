package fabric

import (
	"sync"
	"testing"
)

// createTestFabricInfo creates a FabricInfo for testing using the spec test vectors.
func createTestFabricInfo(t *testing.T, index FabricIndex) *FabricInfo {
	t.Helper()

	rcacTLV := hexToBytes(rcacTLVHex)
	icacTLV := hexToBytes(icacTLVHex)
	nocTLV := hexToBytes(nocTLVHex)
	var ipk [IPKSize]byte
	copy(ipk[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})

	info, err := NewFabricInfo(index, rcacTLV, nocTLV, icacTLV, VendorIDTestVendor1, ipk)
	if err != nil {
		t.Fatalf("NewFabricInfo failed: %v", err)
	}
	return info
}

func TestNewTable(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		table := NewTable(DefaultTableConfig())
		if table.SupportedFabrics() != DefaultSupportedFabrics {
			t.Errorf("expected %d supported fabrics, got %d", DefaultSupportedFabrics, table.SupportedFabrics())
		}
		if table.Count() != 0 {
			t.Errorf("expected 0 fabrics, got %d", table.Count())
		}
	})

	t.Run("clamp min", func(t *testing.T) {
		table := NewTable(TableConfig{MaxFabrics: 1}) // Below min
		if table.SupportedFabrics() != MinSupportedFabrics {
			t.Errorf("expected %d (min), got %d", MinSupportedFabrics, table.SupportedFabrics())
		}
	})

	t.Run("clamp max", func(t *testing.T) {
		table := NewTable(TableConfig{MaxFabrics: 255}) // Above max
		if table.SupportedFabrics() != MaxSupportedFabrics {
			t.Errorf("expected %d (max), got %d", MaxSupportedFabrics, table.SupportedFabrics())
		}
	})
}

func TestTable_AddAndGet(t *testing.T) {
	table := NewTable(DefaultTableConfig())
	info := createTestFabricInfo(t, 1)

	// Add fabric
	err := table.Add(info)
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Get fabric
	retrieved, ok := table.Get(1)
	if !ok {
		t.Fatal("Get returned false for existing fabric")
	}
	if retrieved.FabricIndex != info.FabricIndex {
		t.Errorf("FabricIndex mismatch: got %d, expected %d", retrieved.FabricIndex, info.FabricIndex)
	}
	if retrieved.FabricID != info.FabricID {
		t.Errorf("FabricID mismatch")
	}
	if retrieved.NodeID != info.NodeID {
		t.Errorf("NodeID mismatch")
	}

	// Get returns clone (modifications don't affect table)
	_ = retrieved.SetLabel("modified")
	original, _ := table.Get(1)
	if original.Label == "modified" {
		t.Error("Get should return a clone, not a reference")
	}
}

func TestTable_AddErrors(t *testing.T) {
	t.Run("table full", func(t *testing.T) {
		table := NewTable(TableConfig{MaxFabrics: MinSupportedFabrics})

		// Fill table
		for i := 1; i <= int(MinSupportedFabrics); i++ {
			info := createTestFabricInfo(t, FabricIndex(i))
			// Modify fabric ID to avoid conflict
			info.FabricID = FabricID(uint64(i))
			err := table.Add(info)
			if err != nil {
				t.Fatalf("Add %d failed: %v", i, err)
			}
		}

		// Try to add one more
		info := createTestFabricInfo(t, FabricIndex(MinSupportedFabrics+1))
		info.FabricID = FabricID(100)
		err := table.Add(info)
		if err != ErrTableFull {
			t.Errorf("expected ErrTableFull, got %v", err)
		}
	})

	t.Run("index in use", func(t *testing.T) {
		table := NewTable(DefaultTableConfig())
		info := createTestFabricInfo(t, 1)
		_ = table.Add(info)

		// Try to add same index with different fabric ID
		info2 := createTestFabricInfo(t, 1)
		info2.FabricID = FabricID(999)
		err := table.Add(info2)
		if err != ErrFabricIndexInUse {
			t.Errorf("expected ErrFabricIndexInUse, got %v", err)
		}
	})

	t.Run("fabric conflict", func(t *testing.T) {
		table := NewTable(DefaultTableConfig())
		info := createTestFabricInfo(t, 1)
		_ = table.Add(info)

		// Try to add different index but same root key + fabric ID
		info2 := createTestFabricInfo(t, 2) // Same root key and fabric ID
		err := table.Add(info2)
		if err != ErrFabricConflict {
			t.Errorf("expected ErrFabricConflict, got %v", err)
		}
	})
}

func TestTable_Remove(t *testing.T) {
	table := NewTable(DefaultTableConfig())
	info := createTestFabricInfo(t, 1)
	_ = table.Add(info)

	// Remove existing
	err := table.Remove(1)
	if err != nil {
		t.Errorf("Remove failed: %v", err)
	}

	// Verify removed
	_, ok := table.Get(1)
	if ok {
		t.Error("fabric should be removed")
	}

	// Remove non-existing
	err = table.Remove(1)
	if err != ErrFabricNotFound {
		t.Errorf("expected ErrFabricNotFound, got %v", err)
	}
}

func TestTable_Update(t *testing.T) {
	table := NewTable(DefaultTableConfig())
	info := createTestFabricInfo(t, 1)
	_ = table.Add(info)

	// Update label
	err := table.Update(1, func(f *FabricInfo) error {
		return f.SetLabel("Updated")
	})
	if err != nil {
		t.Errorf("Update failed: %v", err)
	}

	// Verify update
	retrieved, _ := table.Get(1)
	if retrieved.Label != "Updated" {
		t.Errorf("Label not updated: got %q", retrieved.Label)
	}

	// Update non-existing
	err = table.Update(99, func(f *FabricInfo) error {
		return f.SetLabel("test")
	})
	if err != ErrFabricNotFound {
		t.Errorf("expected ErrFabricNotFound, got %v", err)
	}
}

func TestTable_FindByRootPublicKey(t *testing.T) {
	table := NewTable(DefaultTableConfig())
	info := createTestFabricInfo(t, 1)
	_ = table.Add(info)

	// Find existing
	found, ok := table.FindByRootPublicKey(info.RootPublicKey)
	if !ok {
		t.Fatal("FindByRootPublicKey returned false")
	}
	if found.FabricIndex != info.FabricIndex {
		t.Error("wrong fabric returned")
	}

	// Find non-existing
	var differentKey [RootPublicKeySize]byte
	differentKey[0] = 0x04
	_, ok = table.FindByRootPublicKey(differentKey)
	if ok {
		t.Error("should not find non-existing key")
	}
}

func TestTable_FindByCompressedFabricID(t *testing.T) {
	table := NewTable(DefaultTableConfig())
	info := createTestFabricInfo(t, 1)
	_ = table.Add(info)

	// Find existing
	found, ok := table.FindByCompressedFabricID(info.CompressedFabricID)
	if !ok {
		t.Fatal("FindByCompressedFabricID returned false")
	}
	if found.FabricIndex != info.FabricIndex {
		t.Error("wrong fabric returned")
	}

	// Find non-existing
	var differentCFID [CompressedFabricIDSize]byte
	_, ok = table.FindByCompressedFabricID(differentCFID)
	if ok {
		t.Error("should not find non-existing CFID")
	}
}

func TestTable_FindByFabricID(t *testing.T) {
	table := NewTable(DefaultTableConfig())
	info := createTestFabricInfo(t, 1)
	_ = table.Add(info)

	// Find existing
	found, ok := table.FindByFabricID(info.FabricID)
	if !ok {
		t.Fatal("FindByFabricID returned false")
	}
	if found.FabricIndex != info.FabricIndex {
		t.Error("wrong fabric returned")
	}

	// Find non-existing
	_, ok = table.FindByFabricID(FabricID(999999))
	if ok {
		t.Error("should not find non-existing fabric ID")
	}
}

func TestTable_FindByRootAndFabricID(t *testing.T) {
	table := NewTable(DefaultTableConfig())
	info := createTestFabricInfo(t, 1)
	_ = table.Add(info)

	// Find existing
	found, ok := table.FindByRootAndFabricID(info.RootPublicKey, info.FabricID)
	if !ok {
		t.Fatal("FindByRootAndFabricID returned false")
	}
	if found.FabricIndex != info.FabricIndex {
		t.Error("wrong fabric returned")
	}

	// Find non-existing (wrong fabric ID)
	_, ok = table.FindByRootAndFabricID(info.RootPublicKey, FabricID(999999))
	if ok {
		t.Error("should not find with wrong fabric ID")
	}
}

func TestTable_List(t *testing.T) {
	table := NewTable(DefaultTableConfig())

	// Empty list
	list := table.List()
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d", len(list))
	}

	// Add some fabrics
	for i := 1; i <= 3; i++ {
		info := createTestFabricInfo(t, FabricIndex(i))
		info.FabricID = FabricID(uint64(i))
		_ = table.Add(info)
	}

	list = table.List()
	if len(list) != 3 {
		t.Errorf("expected 3 fabrics, got %d", len(list))
	}
}

func TestTable_Count(t *testing.T) {
	table := NewTable(DefaultTableConfig())

	if table.Count() != 0 {
		t.Errorf("expected 0, got %d", table.Count())
	}

	info := createTestFabricInfo(t, 1)
	_ = table.Add(info)

	if table.Count() != 1 {
		t.Errorf("expected 1, got %d", table.Count())
	}

	_ = table.Remove(1)
	if table.Count() != 0 {
		t.Errorf("expected 0 after remove, got %d", table.Count())
	}
}

func TestTable_CommissionedFabrics(t *testing.T) {
	table := NewTable(DefaultTableConfig())

	if table.CommissionedFabrics() != 0 {
		t.Errorf("expected 0, got %d", table.CommissionedFabrics())
	}

	info := createTestFabricInfo(t, 1)
	_ = table.Add(info)

	if table.CommissionedFabrics() != 1 {
		t.Errorf("expected 1, got %d", table.CommissionedFabrics())
	}
}

func TestTable_AllocateFabricIndex(t *testing.T) {
	table := NewTable(DefaultTableConfig())

	// First allocation should return 1
	idx, err := table.AllocateFabricIndex()
	if err != nil {
		t.Fatalf("AllocateFabricIndex failed: %v", err)
	}
	if idx != 1 {
		t.Errorf("expected index 1, got %d", idx)
	}

	// Add fabric at index 1
	info := createTestFabricInfo(t, 1)
	_ = table.Add(info)

	// Next allocation should return 2
	idx, err = table.AllocateFabricIndex()
	if err != nil {
		t.Fatalf("AllocateFabricIndex failed: %v", err)
	}
	if idx != 2 {
		t.Errorf("expected index 2, got %d", idx)
	}
}

func TestTable_AllocateFabricIndex_Full(t *testing.T) {
	table := NewTable(TableConfig{MaxFabrics: MinSupportedFabrics})

	// Fill table
	for i := 1; i <= int(MinSupportedFabrics); i++ {
		info := createTestFabricInfo(t, FabricIndex(i))
		info.FabricID = FabricID(uint64(i))
		_ = table.Add(info)
	}

	// Allocation should fail
	_, err := table.AllocateFabricIndex()
	if err != ErrTableFull {
		t.Errorf("expected ErrTableFull, got %v", err)
	}
}

func TestTable_IsFabricIndexInUse(t *testing.T) {
	table := NewTable(DefaultTableConfig())

	if table.IsFabricIndexInUse(1) {
		t.Error("index 1 should not be in use")
	}

	info := createTestFabricInfo(t, 1)
	_ = table.Add(info)

	if !table.IsFabricIndexInUse(1) {
		t.Error("index 1 should be in use")
	}
}

func TestTable_UpdateLabel(t *testing.T) {
	table := NewTable(DefaultTableConfig())

	// Add two fabrics
	info1 := createTestFabricInfo(t, 1)
	info1.FabricID = FabricID(1)
	_ = table.Add(info1)

	info2 := createTestFabricInfo(t, 2)
	info2.FabricID = FabricID(2)
	_ = table.Add(info2)

	// Set label on first
	err := table.UpdateLabel(1, "Fabric A")
	if err != nil {
		t.Errorf("UpdateLabel failed: %v", err)
	}

	// Verify label
	retrieved, _ := table.Get(1)
	if retrieved.Label != "Fabric A" {
		t.Errorf("Label mismatch: got %q", retrieved.Label)
	}

	// Try to set same label on second (should fail)
	err = table.UpdateLabel(2, "Fabric A")
	if err != ErrLabelConflict {
		t.Errorf("expected ErrLabelConflict, got %v", err)
	}

	// Empty label is allowed
	err = table.UpdateLabel(2, "")
	if err != nil {
		t.Errorf("empty label should be allowed: %v", err)
	}

	// Non-existing fabric
	err = table.UpdateLabel(99, "test")
	if err != ErrFabricNotFound {
		t.Errorf("expected ErrFabricNotFound, got %v", err)
	}
}

func TestTable_IsLabelInUse(t *testing.T) {
	table := NewTable(DefaultTableConfig())

	info := createTestFabricInfo(t, 1)
	_ = table.Add(info)
	_ = table.UpdateLabel(1, "MyLabel")

	// Label should be in use (excluding different index)
	if !table.IsLabelInUse("MyLabel", 2) {
		t.Error("label should be in use")
	}

	// Label should not be in use (excluding same index)
	if table.IsLabelInUse("MyLabel", 1) {
		t.Error("label should not be in use when excluding same index")
	}

	// Empty label is never in use
	if table.IsLabelInUse("", 99) {
		t.Error("empty label should never be in use")
	}
}

func TestTable_GetNOCsList(t *testing.T) {
	table := NewTable(DefaultTableConfig())

	// Empty list
	nocs := table.GetNOCsList()
	if len(nocs) != 0 {
		t.Errorf("expected empty, got %d", len(nocs))
	}

	info := createTestFabricInfo(t, 1)
	_ = table.Add(info)

	nocs = table.GetNOCsList()
	if len(nocs) != 1 {
		t.Errorf("expected 1, got %d", len(nocs))
	}
	if len(nocs[0].NOC) == 0 {
		t.Error("NOC should not be empty")
	}
}

func TestTable_GetFabricsList(t *testing.T) {
	table := NewTable(DefaultTableConfig())

	info := createTestFabricInfo(t, 1)
	_ = table.Add(info)

	fabrics := table.GetFabricsList()
	if len(fabrics) != 1 {
		t.Errorf("expected 1, got %d", len(fabrics))
	}
	if fabrics[0].FabricID != info.FabricID {
		t.Error("FabricID mismatch")
	}
}

func TestTable_GetTrustedRootCertificates(t *testing.T) {
	table := NewTable(DefaultTableConfig())

	info := createTestFabricInfo(t, 1)
	_ = table.Add(info)

	certs := table.GetTrustedRootCertificates()
	if len(certs) != 1 {
		t.Errorf("expected 1, got %d", len(certs))
	}
	if len(certs[0]) == 0 {
		t.Error("root cert should not be empty")
	}
}

func TestTable_Clear(t *testing.T) {
	table := NewTable(DefaultTableConfig())

	// Add some fabrics
	for i := 1; i <= 3; i++ {
		info := createTestFabricInfo(t, FabricIndex(i))
		info.FabricID = FabricID(uint64(i))
		_ = table.Add(info)
	}

	if table.Count() != 3 {
		t.Fatalf("expected 3, got %d", table.Count())
	}

	table.Clear()

	if table.Count() != 0 {
		t.Errorf("expected 0 after clear, got %d", table.Count())
	}
}

func TestTable_ForEach(t *testing.T) {
	table := NewTable(DefaultTableConfig())

	// Add fabrics
	for i := 1; i <= 3; i++ {
		info := createTestFabricInfo(t, FabricIndex(i))
		info.FabricID = FabricID(uint64(i))
		_ = table.Add(info)
	}

	count := 0
	err := table.ForEach(func(f *FabricInfo) error {
		count++
		return nil
	})
	if err != nil {
		t.Errorf("ForEach failed: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 iterations, got %d", count)
	}
}

func TestTable_String(t *testing.T) {
	table := NewTable(DefaultTableConfig())
	info := createTestFabricInfo(t, 1)
	_ = table.Add(info)

	s := table.String()
	if s == "" {
		t.Error("String() should not return empty")
	}
	t.Logf("Table.String() = %s", s)
}

// TestTable_SameRootDifferentFabricID verifies that fabrics with the same root
// CA but different fabric IDs can coexist (not a conflict).
// Reference: TestFabricTable::TestAddMultipleSameRootDifferentFabricId
func TestTable_SameRootDifferentFabricID(t *testing.T) {
	table := NewTable(DefaultTableConfig())

	// Add first fabric
	info1 := createTestFabricInfo(t, 1)
	err := table.Add(info1)
	if err != nil {
		t.Fatalf("Add first fabric failed: %v", err)
	}

	// Create second fabric with same root but different fabric ID
	info2 := createTestFabricInfo(t, 2)
	info2.FabricID = FabricID(0x2222) // Different fabric ID

	err = table.Add(info2)
	if err != nil {
		t.Errorf("Same root + different fabric ID should be allowed: %v", err)
	}

	if table.Count() != 2 {
		t.Errorf("expected 2 fabrics, got %d", table.Count())
	}
}

// TestTable_SameFabricIDDifferentRoot verifies that fabrics with the same
// fabric ID but different root CAs can coexist (not a conflict).
// Reference: TestFabricTable::TestAddMultipleSameFabricIdDifferentRoot
func TestTable_SameFabricIDDifferentRoot(t *testing.T) {
	table := NewTable(DefaultTableConfig())

	// Add first fabric
	info1 := createTestFabricInfo(t, 1)
	err := table.Add(info1)
	if err != nil {
		t.Fatalf("Add first fabric failed: %v", err)
	}

	// Create second fabric with same fabric ID but different root key
	info2 := createTestFabricInfo(t, 2)
	// Modify root public key to simulate different CA
	info2.RootPublicKey[1] = 0xFF
	info2.RootPublicKey[2] = 0xEE
	// Keep same fabric ID - info2.FabricID is already the same

	err = table.Add(info2)
	if err != nil {
		t.Errorf("Different root + same fabric ID should be allowed: %v", err)
	}

	if table.Count() != 2 {
		t.Errorf("expected 2 fabrics, got %d", table.Count())
	}
}

// TestTable_LookupInvalidIndex verifies that looking up invalid fabric indices
// returns appropriate results.
// Reference: TestFabricTable::TestFabricLookup
func TestTable_LookupInvalidIndex(t *testing.T) {
	table := NewTable(DefaultTableConfig())
	info := createTestFabricInfo(t, 1)
	_ = table.Add(info)

	// Lookup index 0 (invalid) should fail
	_, ok := table.Get(FabricIndexInvalid)
	if ok {
		t.Error("Get with FabricIndexInvalid should return false")
	}

	// IsFabricIndexInUse with invalid index
	if table.IsFabricIndexInUse(FabricIndexInvalid) {
		t.Error("IsFabricIndexInUse(0) should return false")
	}

	// Lookup non-existent index
	_, ok = table.Get(FabricIndex(99))
	if ok {
		t.Error("Get with non-existent index should return false")
	}
}

// TestTable_AllocateAfterRemove verifies that removed fabric indices become
// available for reallocation.
func TestTable_AllocateAfterRemove(t *testing.T) {
	table := NewTable(DefaultTableConfig())

	// Add fabric at index 1
	info1 := createTestFabricInfo(t, 1)
	_ = table.Add(info1)

	// Add fabric at index 2
	info2 := createTestFabricInfo(t, 2)
	info2.FabricID = FabricID(2)
	_ = table.Add(info2)

	// Remove fabric at index 1
	_ = table.Remove(1)

	// Allocate should return 1 (first available)
	idx, err := table.AllocateFabricIndex()
	if err != nil {
		t.Fatalf("AllocateFabricIndex failed: %v", err)
	}
	if idx != 1 {
		t.Errorf("expected index 1 to be reallocated, got %d", idx)
	}
}

func TestTable_ConcurrentAccess(t *testing.T) {
	table := NewTable(TableConfig{MaxFabrics: 100})

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	// Concurrent adds
	for i := 1; i <= 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			info := createTestFabricInfo(t, FabricIndex(idx))
			info.FabricID = FabricID(uint64(idx))
			if err := table.Add(info); err != nil {
				errors <- err
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = table.List()
			_ = table.Count()
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("concurrent operation failed: %v", err)
	}

	// Verify final state
	if table.Count() != 50 {
		t.Errorf("expected 50 fabrics, got %d", table.Count())
	}
}
