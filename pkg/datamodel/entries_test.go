package datamodel

import "testing"

// Test vectors from C++ reference: TestMetadataEntries.cpp

// TestAttributeQualityEncoding tests attribute quality flag encoding.
// C++ Reference: TEST(TestMetadataEntries, TestAttributeQualityEncoding)
func TestAttributeQualityEncoding(t *testing.T) {
	allQualities := []AttributeQuality{
		AttrQualityList,
		AttrQualityFabricScoped,
		AttrQualityFabricSensitive,
		AttrQualityChangesOmitted,
		AttrQualityTimed,
	}

	// Test no options set
	t.Run("NoOptions", func(t *testing.T) {
		a := AttributeEntry{ID: 123}

		if a.ID != 123 {
			t.Errorf("ID = %v, want 123", a.ID)
		}

		for _, q := range allQualities {
			if a.HasQuality(q) {
				t.Errorf("HasQuality(%v) = true, want false", q)
			}
		}
	})

	// Test each quality individually
	for _, quality := range allQualities {
		t.Run("Single_"+quality.String(), func(t *testing.T) {
			a := AttributeEntry{ID: 123, Quality: quality}

			for _, testQ := range allQualities {
				got := a.HasQuality(testQ)
				want := testQ == quality
				if got != want {
					t.Errorf("HasQuality(%v) = %v, want %v", testQ, got, want)
				}
			}
		})
	}

	// Test multi-option set
	t.Run("MultiOption", func(t *testing.T) {
		a := AttributeEntry{
			ID:      123,
			Quality: AttrQualityFabricSensitive | AttrQualityTimed,
		}

		if a.HasQuality(AttrQualityList) {
			t.Error("HasQuality(List) = true, want false")
		}
		if a.HasQuality(AttrQualityFabricScoped) {
			t.Error("HasQuality(FabricScoped) = true, want false")
		}
		if !a.HasQuality(AttrQualityFabricSensitive) {
			t.Error("HasQuality(FabricSensitive) = false, want true")
		}
		if a.HasQuality(AttrQualityChangesOmitted) {
			t.Error("HasQuality(ChangesOmitted) = true, want false")
		}
		if !a.HasQuality(AttrQualityTimed) {
			t.Error("HasQuality(Timed) = false, want true")
		}
	})
}

// TestAttributePrivilegeEncoding tests attribute privilege encoding.
// C++ Reference: TEST(TestMetadataEntries, TestAttributePrivilegeEncoding)
func TestAttributePrivilegeEncoding(t *testing.T) {
	allPrivileges := []Privilege{
		PrivilegeView,
		PrivilegeProxyView,
		PrivilegeOperate,
		PrivilegeManage,
		PrivilegeAdminister,
	}

	// Test all privilege combinations
	for _, rp := range allPrivileges {
		for _, wp := range allPrivileges {
			t.Run(rp.String()+"_"+wp.String(), func(t *testing.T) {
				a := AttributeEntry{
					ID:             123,
					ReadPrivilege:  &rp,
					WritePrivilege: &wp,
				}

				if !a.IsReadable() {
					t.Error("IsReadable() = false, want true")
				}
				if *a.ReadPrivilege != rp {
					t.Errorf("ReadPrivilege = %v, want %v", *a.ReadPrivilege, rp)
				}

				if !a.IsWritable() {
					t.Error("IsWritable() = false, want true")
				}
				if *a.WritePrivilege != wp {
					t.Errorf("WritePrivilege = %v, want %v", *a.WritePrivilege, wp)
				}
			})
		}
	}

	// Test read-only
	for _, rp := range allPrivileges {
		t.Run("ReadOnly_"+rp.String(), func(t *testing.T) {
			a := AttributeEntry{ID: 123, ReadPrivilege: &rp}

			if !a.IsReadable() {
				t.Error("IsReadable() = false, want true")
			}
			if a.IsWritable() {
				t.Error("IsWritable() = true, want false")
			}
			if a.ReadPrivilege == nil {
				t.Error("ReadPrivilege = nil, want non-nil")
			}
			if a.WritePrivilege != nil {
				t.Error("WritePrivilege = non-nil, want nil")
			}
		})
	}

	// Test write-only (unusual but valid)
	for _, wp := range allPrivileges {
		t.Run("WriteOnly_"+wp.String(), func(t *testing.T) {
			a := AttributeEntry{ID: 123, WritePrivilege: &wp}

			if a.IsReadable() {
				t.Error("IsReadable() = true, want false")
			}
			if !a.IsWritable() {
				t.Error("IsWritable() = false, want true")
			}
			if a.ReadPrivilege != nil {
				t.Error("ReadPrivilege = non-nil, want nil")
			}
			if a.WritePrivilege == nil {
				t.Error("WritePrivilege = nil, want non-nil")
			}
		})
	}
}

// TestCommandEntry tests command entry encoding.
// C++ Reference: TEST(TestMetadataEntries, TestCommandEntry)
func TestCommandEntry(t *testing.T) {
	allQualities := []CommandQuality{
		CmdQualityFabricScoped,
		CmdQualityTimed,
		CmdQualityLargeMessage,
	}

	allPrivileges := []Privilege{
		PrivilegeView,
		PrivilegeOperate,
		PrivilegeManage,
		PrivilegeAdminister,
	}

	// Test basic command
	t.Run("Basic", func(t *testing.T) {
		c := CommandEntry{
			ID:              123,
			InvokePrivilege: PrivilegeView,
		}

		if c.ID != 123 {
			t.Errorf("ID = %v, want 123", c.ID)
		}
		if c.HasQuality(CmdQualityFabricScoped) {
			t.Error("HasQuality(FabricScoped) = true, want false")
		}
		if c.HasQuality(CmdQualityTimed) {
			t.Error("HasQuality(Timed) = true, want false")
		}
		if c.HasQuality(CmdQualityLargeMessage) {
			t.Error("HasQuality(LargeMessage) = true, want false")
		}
		if c.InvokePrivilege != PrivilegeView {
			t.Errorf("InvokePrivilege = %v, want View", c.InvokePrivilege)
		}
	})

	// Test all privilege and quality combinations
	for _, priv := range allPrivileges {
		for _, qual := range allQualities {
			t.Run(priv.String()+"_"+qual.String(), func(t *testing.T) {
				c := CommandEntry{
					ID:              1,
					Quality:         qual,
					InvokePrivilege: priv,
				}

				for _, testQ := range allQualities {
					got := c.HasQuality(testQ)
					want := testQ == qual
					if got != want {
						t.Errorf("HasQuality(%v) = %v, want %v", testQ, got, want)
					}
				}

				if c.InvokePrivilege != priv {
					t.Errorf("InvokePrivilege = %v, want %v", c.InvokePrivilege, priv)
				}
			})
		}
	}
}

func TestAttributeEntry_Helpers(t *testing.T) {
	t.Run("IsList", func(t *testing.T) {
		a := AttributeEntry{Quality: AttrQualityList}
		if !a.IsList() {
			t.Error("IsList() = false, want true")
		}

		a2 := AttributeEntry{}
		if a2.IsList() {
			t.Error("IsList() = true, want false")
		}
	})

	t.Run("IsFabricScoped", func(t *testing.T) {
		a := AttributeEntry{Quality: AttrQualityFabricScoped}
		if !a.IsFabricScoped() {
			t.Error("IsFabricScoped() = false, want true")
		}
	})

	t.Run("IsFabricSensitive", func(t *testing.T) {
		a := AttributeEntry{Quality: AttrQualityFabricSensitive}
		if !a.IsFabricSensitive() {
			t.Error("IsFabricSensitive() = false, want true")
		}
	})

	t.Run("RequiresTimed", func(t *testing.T) {
		a := AttributeEntry{Quality: AttrQualityTimed}
		if !a.RequiresTimed() {
			t.Error("RequiresTimed() = false, want true")
		}
	})

	t.Run("RequiresAtomic", func(t *testing.T) {
		a := AttributeEntry{Quality: AttrQualityAtomic}
		if !a.RequiresAtomic() {
			t.Error("RequiresAtomic() = false, want true")
		}
	})
}

func TestCommandEntry_Helpers(t *testing.T) {
	t.Run("IsFabricScoped", func(t *testing.T) {
		c := CommandEntry{Quality: CmdQualityFabricScoped}
		if !c.IsFabricScoped() {
			t.Error("IsFabricScoped() = false, want true")
		}
	})

	t.Run("RequiresTimed", func(t *testing.T) {
		c := CommandEntry{Quality: CmdQualityTimed}
		if !c.RequiresTimed() {
			t.Error("RequiresTimed() = false, want true")
		}
	})

	t.Run("IsLargeMessage", func(t *testing.T) {
		c := CommandEntry{Quality: CmdQualityLargeMessage}
		if !c.IsLargeMessage() {
			t.Error("IsLargeMessage() = false, want true")
		}
	})
}

func TestNewAttributeEntry(t *testing.T) {
	readPriv := PrivilegeView
	writePriv := PrivilegeOperate

	a := NewAttributeEntry(123, AttrQualityNullable, &readPriv, &writePriv)

	if a.ID != 123 {
		t.Errorf("ID = %v, want 123", a.ID)
	}
	if a.Quality != AttrQualityNullable {
		t.Errorf("Quality = %v, want Nullable", a.Quality)
	}
	if *a.ReadPrivilege != PrivilegeView {
		t.Errorf("ReadPrivilege = %v, want View", *a.ReadPrivilege)
	}
	if *a.WritePrivilege != PrivilegeOperate {
		t.Errorf("WritePrivilege = %v, want Operate", *a.WritePrivilege)
	}
}

func TestNewReadOnlyAttribute(t *testing.T) {
	a := NewReadOnlyAttribute(456, AttrQualityFixed, PrivilegeView)

	if a.ID != 456 {
		t.Errorf("ID = %v, want 456", a.ID)
	}
	if !a.IsReadable() {
		t.Error("IsReadable() = false, want true")
	}
	if a.IsWritable() {
		t.Error("IsWritable() = true, want false")
	}
}

func TestNewReadWriteAttribute(t *testing.T) {
	a := NewReadWriteAttribute(789, 0, PrivilegeView, PrivilegeOperate)

	if a.ID != 789 {
		t.Errorf("ID = %v, want 789", a.ID)
	}
	if !a.IsReadable() {
		t.Error("IsReadable() = false, want true")
	}
	if !a.IsWritable() {
		t.Error("IsWritable() = false, want true")
	}
}

func TestNewCommandEntry(t *testing.T) {
	c := NewCommandEntry(10, CmdQualityTimed, PrivilegeManage)

	if c.ID != 10 {
		t.Errorf("ID = %v, want 10", c.ID)
	}
	if !c.RequiresTimed() {
		t.Error("RequiresTimed() = false, want true")
	}
	if c.InvokePrivilege != PrivilegeManage {
		t.Errorf("InvokePrivilege = %v, want Manage", c.InvokePrivilege)
	}
}

func TestNewEventEntry(t *testing.T) {
	e := NewEventEntry(20, EventPriorityCritical, PrivilegeView, true)

	if e.ID != 20 {
		t.Errorf("ID = %v, want 20", e.ID)
	}
	if e.Priority != EventPriorityCritical {
		t.Errorf("Priority = %v, want Critical", e.Priority)
	}
	if e.ReadPrivilege != PrivilegeView {
		t.Errorf("ReadPrivilege = %v, want View", e.ReadPrivilege)
	}
	if !e.IsFabricSensitive {
		t.Error("IsFabricSensitive = false, want true")
	}
}
