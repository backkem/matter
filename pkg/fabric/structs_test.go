package fabric

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestNOCStruct_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		noc  *NOCStruct
	}{
		{
			name: "with ICAC",
			noc: &NOCStruct{
				NOC:  []byte{0x15, 0x30, 0x01, 0x02, 0x03, 0x04}, // sample TLV data
				ICAC: []byte{0x15, 0x30, 0x05, 0x06, 0x07, 0x08},
			},
		},
		{
			name: "without ICAC",
			noc: &NOCStruct{
				NOC:  []byte{0x15, 0x30, 0x01, 0x02, 0x03, 0x04},
				ICAC: nil,
			},
		},
		{
			name: "empty NOC",
			noc: &NOCStruct{
				NOC:  []byte{},
				ICAC: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			data, err := tt.noc.MarshalTLV()
			if err != nil {
				t.Fatalf("MarshalTLV failed: %v", err)
			}

			// Decode
			decoded, err := UnmarshalNOCStruct(data)
			if err != nil {
				t.Fatalf("UnmarshalNOCStruct failed: %v", err)
			}

			// Verify
			if !bytes.Equal(decoded.NOC, tt.noc.NOC) {
				t.Errorf("NOC mismatch:\n  got:      %x\n  expected: %x", decoded.NOC, tt.noc.NOC)
			}

			if tt.noc.ICAC == nil {
				if decoded.ICAC != nil {
					t.Errorf("expected nil ICAC, got %x", decoded.ICAC)
				}
			} else {
				if !bytes.Equal(decoded.ICAC, tt.noc.ICAC) {
					t.Errorf("ICAC mismatch:\n  got:      %x\n  expected: %x", decoded.ICAC, tt.noc.ICAC)
				}
			}
		})
	}
}

func TestFabricDescriptorStruct_Roundtrip(t *testing.T) {
	// Create a sample root public key
	rootKeyHex := "044a9f42b1ca4840d37292bbc7f6a7e11e22200c976fc900dbc98a7a383a641cb8254a2e56d4e295a847943b4e3897c4a773e930277b4d9fbede8a052686bfacfa"
	rootKeyBytes, _ := hex.DecodeString(rootKeyHex)
	var rootKey [RootPublicKeySize]byte
	copy(rootKey[:], rootKeyBytes)

	tests := []struct {
		name   string
		fabric *FabricDescriptorStruct
	}{
		{
			name: "full descriptor",
			fabric: &FabricDescriptorStruct{
				RootPublicKey: rootKey,
				VendorID:      VendorIDTestVendor1,
				FabricID:      FabricID(0x2906C908D115D362),
				NodeID:        NodeID(0x0000000000000001),
				Label:         "Test Fabric",
			},
		},
		{
			name: "empty label",
			fabric: &FabricDescriptorStruct{
				RootPublicKey: rootKey,
				VendorID:      VendorID(0x1234),
				FabricID:      FabricID(0x1122334455667788),
				NodeID:        NodeID(0xDEADBEEF),
				Label:         "",
			},
		},
		{
			name: "max label",
			fabric: &FabricDescriptorStruct{
				RootPublicKey: rootKey,
				VendorID:      VendorID(1),
				FabricID:      FabricID(1),
				NodeID:        NodeID(1),
				Label:         "12345678901234567890123456789012", // 32 chars
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			data, err := tt.fabric.MarshalTLV()
			if err != nil {
				t.Fatalf("MarshalTLV failed: %v", err)
			}

			// Decode
			decoded, err := UnmarshalFabricDescriptorStruct(data)
			if err != nil {
				t.Fatalf("UnmarshalFabricDescriptorStruct failed: %v", err)
			}

			// Verify
			if decoded.RootPublicKey != tt.fabric.RootPublicKey {
				t.Errorf("RootPublicKey mismatch")
			}
			if decoded.VendorID != tt.fabric.VendorID {
				t.Errorf("VendorID mismatch: got %v, expected %v", decoded.VendorID, tt.fabric.VendorID)
			}
			if decoded.FabricID != tt.fabric.FabricID {
				t.Errorf("FabricID mismatch: got %v, expected %v", decoded.FabricID, tt.fabric.FabricID)
			}
			if decoded.NodeID != tt.fabric.NodeID {
				t.Errorf("NodeID mismatch: got %v, expected %v", decoded.NodeID, tt.fabric.NodeID)
			}
			if decoded.Label != tt.fabric.Label {
				t.Errorf("Label mismatch: got %q, expected %q", decoded.Label, tt.fabric.Label)
			}
		})
	}
}

func TestFabricDescriptorStruct_CompressedFabricID(t *testing.T) {
	// Use spec test vector
	rootKeyHex := "044a9f42b1ca4840d37292bbc7f6a7e11e22200c976fc900dbc98a7a383a641cb8254a2e56d4e295a847943b4e3897c4a773e930277b4d9fbede8a052686bfacfa"
	rootKeyBytes, _ := hex.DecodeString(rootKeyHex)
	var rootKey [RootPublicKeySize]byte
	copy(rootKey[:], rootKeyBytes)

	f := &FabricDescriptorStruct{
		RootPublicKey: rootKey,
		VendorID:      VendorIDTestVendor1,
		FabricID:      FabricID(0x2906C908D115D362),
		NodeID:        NodeID(1),
		Label:         "",
	}

	cfid, err := f.CompressedFabricIDBytes()
	if err != nil {
		t.Fatalf("CompressedFabricIDBytes failed: %v", err)
	}

	expectedHex := "87e1b004e235a130"
	if hex.EncodeToString(cfid[:]) != expectedHex {
		t.Errorf("CompressedFabricID mismatch:\n  got:      %s\n  expected: %s",
			hex.EncodeToString(cfid[:]), expectedHex)
	}
}

func TestFabricTypes_String(t *testing.T) {
	// Test FabricIndex.String()
	if FabricIndexInvalid.String() != "FabricIndex(invalid)" {
		t.Errorf("FabricIndexInvalid.String() = %q", FabricIndexInvalid.String())
	}
	if FabricIndex(5).String() != "FabricIndex(5)" {
		t.Errorf("FabricIndex(5).String() = %q", FabricIndex(5).String())
	}

	// Test FabricID.String()
	fid := FabricID(0x2906C908D115D362)
	if fid.String() != "FabricID(0x2906C908D115D362)" {
		t.Errorf("FabricID.String() = %q", fid.String())
	}

	// Test NodeID.String()
	nid := NodeID(0xDEADBEEF)
	if nid.String() != "NodeID(0x00000000DEADBEEF)" {
		t.Errorf("NodeID.String() = %q", nid.String())
	}

	// Test VendorID.String()
	vid := VendorIDTestVendor1
	if vid.String() != "VendorID(0xFFF1)" {
		t.Errorf("VendorID.String() = %q", vid.String())
	}
}

func TestFabricIndex_IsValid(t *testing.T) {
	tests := []struct {
		index FabricIndex
		valid bool
	}{
		{FabricIndexInvalid, false},
		{FabricIndex(0), false},
		{FabricIndexMin, true},
		{FabricIndex(1), true},
		{FabricIndex(128), true},
		{FabricIndexMax, true},
		{FabricIndex(254), true},
		{FabricIndex(255), false},
	}

	for _, tt := range tests {
		if got := tt.index.IsValid(); got != tt.valid {
			t.Errorf("FabricIndex(%d).IsValid() = %v, want %v", tt.index, got, tt.valid)
		}
	}
}

func TestFabricID_IsValid(t *testing.T) {
	tests := []struct {
		id    FabricID
		valid bool
	}{
		{FabricIDInvalid, false},
		{FabricID(0), false},
		{FabricID(1), true},
		{FabricID(0xFFFFFFFFFFFFFFFF), true},
	}

	for _, tt := range tests {
		if got := tt.id.IsValid(); got != tt.valid {
			t.Errorf("FabricID(%d).IsValid() = %v, want %v", tt.id, got, tt.valid)
		}
	}
}

func TestNodeID_IsOperational(t *testing.T) {
	tests := []struct {
		id          NodeID
		operational bool
	}{
		{NodeIDUnspecified, false},
		{NodeID(0), false},
		{NodeIDMinOperational, true},
		{NodeID(1), true},
		{NodeID(0x1234567890ABCDEF), true},
		{NodeIDMaxOperational, true},
		{NodeID(0xFFFFFFFEFFFFFFFD), true},
		{NodeID(0xFFFFFFFEFFFFFFFE), false}, // Above max
		{NodeID(0xFFFFFFFFFFFFFFFF), false}, // Way above max
	}

	for _, tt := range tests {
		if got := tt.id.IsOperational(); got != tt.operational {
			t.Errorf("NodeID(0x%X).IsOperational() = %v, want %v", tt.id, got, tt.operational)
		}
	}
}
