package fabric

import (
	"testing"
)

func TestNewFabricInfo(t *testing.T) {
	rcacTLV := hexToBytes(rcacTLVHex)
	icacTLV := hexToBytes(icacTLVHex)
	nocTLV := hexToBytes(nocTLVHex)

	var ipk [IPKSize]byte
	copy(ipk[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})

	info, err := NewFabricInfo(
		FabricIndex(1),
		rcacTLV, nocTLV, icacTLV,
		VendorIDTestVendor1,
		ipk,
	)
	if err != nil {
		t.Fatalf("NewFabricInfo failed: %v", err)
	}

	// Verify extracted values
	if info.FabricIndex != FabricIndex(1) {
		t.Errorf("FabricIndex mismatch: got %d", info.FabricIndex)
	}

	expectedFabricID := FabricID(0xFAB000000000001D)
	if info.FabricID != expectedFabricID {
		t.Errorf("FabricID mismatch: got 0x%X, expected 0x%X", info.FabricID, expectedFabricID)
	}

	expectedNodeID := NodeID(0xDEDEDEDE00010001)
	if info.NodeID != expectedNodeID {
		t.Errorf("NodeID mismatch: got 0x%X, expected 0x%X", info.NodeID, expectedNodeID)
	}

	if info.VendorID != VendorIDTestVendor1 {
		t.Errorf("VendorID mismatch: got 0x%X", info.VendorID)
	}

	if !info.HasICAC() {
		t.Error("expected HasICAC to be true")
	}

	// Verify root public key was extracted
	if info.RootPublicKey[0] != 0x04 {
		t.Errorf("RootPublicKey should start with 0x04, got 0x%02X", info.RootPublicKey[0])
	}

	// Verify compressed fabric ID was computed
	var zeroCompressedID [CompressedFabricIDSize]byte
	if info.CompressedFabricID == zeroCompressedID {
		t.Error("CompressedFabricID should not be zero")
	}

	// Verify IPK was stored
	if info.IPK != ipk {
		t.Error("IPK mismatch")
	}
}

func TestNewFabricInfo_NoICAC(t *testing.T) {
	// This test would require a certificate chain without ICAC
	// For now, we'll just test that nil ICAC doesn't cause issues when
	// the chain is properly signed (which our test vectors aren't for direct NOC->RCAC)
	// Skip this test as we don't have appropriate test vectors
	t.Skip("requires certificate chain without ICAC")
}

func TestNewFabricInfo_InvalidIndex(t *testing.T) {
	rcacTLV := hexToBytes(rcacTLVHex)
	icacTLV := hexToBytes(icacTLVHex)
	nocTLV := hexToBytes(nocTLVHex)
	var ipk [IPKSize]byte

	_, err := NewFabricInfo(
		FabricIndexInvalid, // Invalid index
		rcacTLV, nocTLV, icacTLV,
		VendorIDTestVendor1,
		ipk,
	)
	if err == nil {
		t.Error("expected error for invalid fabric index")
	}
}

func TestNewFabricInfo_InvalidCerts(t *testing.T) {
	var ipk [IPKSize]byte

	_, err := NewFabricInfo(
		FabricIndex(1),
		[]byte{0xFF}, // Invalid cert
		[]byte{0xFF},
		nil,
		VendorIDTestVendor1,
		ipk,
	)
	if err == nil {
		t.Error("expected error for invalid certificates")
	}
}

func TestFabricInfo_SetLabel(t *testing.T) {
	rcacTLV := hexToBytes(rcacTLVHex)
	icacTLV := hexToBytes(icacTLVHex)
	nocTLV := hexToBytes(nocTLVHex)
	var ipk [IPKSize]byte

	info, err := NewFabricInfo(
		FabricIndex(1),
		rcacTLV, nocTLV, icacTLV,
		VendorIDTestVendor1,
		ipk,
	)
	if err != nil {
		t.Fatalf("NewFabricInfo failed: %v", err)
	}

	// Set valid label
	err = info.SetLabel("My Fabric")
	if err != nil {
		t.Errorf("SetLabel failed: %v", err)
	}
	if info.Label != "My Fabric" {
		t.Errorf("Label mismatch: got %q", info.Label)
	}

	// Set max length label (32 bytes)
	maxLabel := "12345678901234567890123456789012"
	err = info.SetLabel(maxLabel)
	if err != nil {
		t.Errorf("SetLabel with max length failed: %v", err)
	}

	// Set too long label (33 bytes)
	tooLong := "123456789012345678901234567890123"
	err = info.SetLabel(tooLong)
	if err == nil {
		t.Error("expected error for label exceeding max length")
	}
}

func TestFabricInfo_GetNOCStruct(t *testing.T) {
	rcacTLV := hexToBytes(rcacTLVHex)
	icacTLV := hexToBytes(icacTLVHex)
	nocTLV := hexToBytes(nocTLVHex)
	var ipk [IPKSize]byte

	info, err := NewFabricInfo(
		FabricIndex(1),
		rcacTLV, nocTLV, icacTLV,
		VendorIDTestVendor1,
		ipk,
	)
	if err != nil {
		t.Fatalf("NewFabricInfo failed: %v", err)
	}

	nocStruct := info.GetNOCStruct()

	// Verify NOC and ICAC are present
	if len(nocStruct.NOC) == 0 {
		t.Error("NOCStruct.NOC should not be empty")
	}
	if len(nocStruct.ICAC) == 0 {
		t.Error("NOCStruct.ICAC should not be empty")
	}
}

func TestFabricInfo_GetFabricDescriptor(t *testing.T) {
	rcacTLV := hexToBytes(rcacTLVHex)
	icacTLV := hexToBytes(icacTLVHex)
	nocTLV := hexToBytes(nocTLVHex)
	var ipk [IPKSize]byte

	info, err := NewFabricInfo(
		FabricIndex(1),
		rcacTLV, nocTLV, icacTLV,
		VendorIDTestVendor1,
		ipk,
	)
	if err != nil {
		t.Fatalf("NewFabricInfo failed: %v", err)
	}

	_ = info.SetLabel("Test")
	desc := info.GetFabricDescriptor()

	if desc.VendorID != VendorIDTestVendor1 {
		t.Errorf("VendorID mismatch: got %v", desc.VendorID)
	}
	if desc.FabricID != info.FabricID {
		t.Errorf("FabricID mismatch")
	}
	if desc.NodeID != info.NodeID {
		t.Errorf("NodeID mismatch")
	}
	if desc.Label != "Test" {
		t.Errorf("Label mismatch: got %q", desc.Label)
	}
	if desc.RootPublicKey != info.RootPublicKey {
		t.Error("RootPublicKey mismatch")
	}
}

func TestFabricInfo_Clone(t *testing.T) {
	rcacTLV := hexToBytes(rcacTLVHex)
	icacTLV := hexToBytes(icacTLVHex)
	nocTLV := hexToBytes(nocTLVHex)
	var ipk [IPKSize]byte

	info, err := NewFabricInfo(
		FabricIndex(1),
		rcacTLV, nocTLV, icacTLV,
		VendorIDTestVendor1,
		ipk,
	)
	if err != nil {
		t.Fatalf("NewFabricInfo failed: %v", err)
	}
	_ = info.SetLabel("Original")

	clone := info.Clone()

	// Verify clone has same values
	if clone.FabricIndex != info.FabricIndex {
		t.Error("FabricIndex mismatch")
	}
	if clone.FabricID != info.FabricID {
		t.Error("FabricID mismatch")
	}
	if clone.NodeID != info.NodeID {
		t.Error("NodeID mismatch")
	}
	if clone.Label != info.Label {
		t.Error("Label mismatch")
	}

	// Verify clone is independent (modifying clone doesn't affect original)
	_ = clone.SetLabel("Modified")
	if info.Label == clone.Label {
		t.Error("clone should be independent")
	}
}

func TestFabricInfo_String(t *testing.T) {
	rcacTLV := hexToBytes(rcacTLVHex)
	icacTLV := hexToBytes(icacTLVHex)
	nocTLV := hexToBytes(nocTLVHex)
	var ipk [IPKSize]byte

	info, err := NewFabricInfo(
		FabricIndex(1),
		rcacTLV, nocTLV, icacTLV,
		VendorIDTestVendor1,
		ipk,
	)
	if err != nil {
		t.Fatalf("NewFabricInfo failed: %v", err)
	}

	s := info.String()
	if s == "" {
		t.Error("String() should not return empty string")
	}
	// Just verify it doesn't panic and returns something
	t.Logf("FabricInfo.String() = %s", s)
}
