package casesession

import (
	"encoding/hex"
	"testing"

	"github.com/backkem/matter/pkg/crypto"
	"github.com/backkem/matter/pkg/fabric"
)

// TestGenerateDestinationID_SpecVector tests the destination ID computation
// against the test vector from Matter Specification Section 4.14.2.4.1.
func TestGenerateDestinationID_SpecVector(t *testing.T) {
	// Test vector from Section 4.14.2.4.1:
	//
	// Root public key (65 bytes, uncompressed):
	// 04:4a:9f:42:b1:ca:48:40:d3:72:92:bb:c7:f6:a7:e1:
	// 1e:22:20:0c:97:6f:c9:00:db:c9:8a:7a:38:3a:64:1c:
	// b8:25:4a:2e:56:d4:e2:95:a8:47:94:3b:4e:38:97:c4:
	// a7:73:e9:30:27:7b:4d:9f:be:de:8a:05:26:86:bf:ac:fa
	rootPublicKeyHex := "044a9f42b1ca4840d37292bbc7f6a7e1" +
		"1e22200c976fc900dbc98a7a383a641c" +
		"b8254a2e56d4e295a847943b4e3897c4" +
		"a773e930277b4d9fbede8a052686bfac" +
		"fa"

	// Fabric ID: 0x2906_C908_D115_D362 (little-endian: 62:d3:15:d1:08:c9:06:29)
	fabricID := uint64(0x2906C908D115D362)

	// Node ID: 0xCD55_44AA_7B13_EF14 (little-endian: 14:ef:13:7b:aa:44:55:cd)
	nodeID := uint64(0xCD5544AA7B13EF14)

	// IPK Epoch Key: 4a:71:cd:d7:b2:a3:ca:90:24:f9:6f:3c:96:a1:9d:ee
	epochKeyHex := "4a71cdd7b2a3ca9024f96f3c96a19dee"

	// Derived IPK (operational group key): 9b:c6:1c:d9:c6:2a:2d:f6:d6:4d:fc:aa:9d:c4:72:d4
	derivedIPKHex := "9bc61cd9c62a2df6d64dfcaa9dc472d4"

	// Initiator Random:
	// 7e:17:12:31:56:8d:fa:17:20:6b:3a:cc:f8:fa:ec:2f:
	// 4d:21:b5:80:11:31:96:f4:7c:7c:4d:eb:81:0a:73:dc
	initiatorRandomHex := "7e171231568dfa17206b3accf8faec2f" +
		"4d21b580113196f47c7c4deb810a73dc"

	// Expected Destination Identifier:
	// dc:35:dd:5f:c9:13:4c:c5:54:45:38:c9:c3:fc:42:97:
	// c1:ec:33:70:c8:39:13:6a:80:e1:07:96:45:1d:4c:53
	expectedDestIDHex := "dc35dd5fc9134cc5544538c9c3fc4297" +
		"c1ec3370c839136a80e10796451d4c53"

	// Parse hex values
	rootPublicKey, err := hex.DecodeString(rootPublicKeyHex)
	if err != nil {
		t.Fatalf("failed to decode root public key: %v", err)
	}
	if len(rootPublicKey) != crypto.P256PublicKeySizeBytes {
		t.Fatalf("root public key wrong size: got %d, want %d", len(rootPublicKey), crypto.P256PublicKeySizeBytes)
	}

	epochKey, err := hex.DecodeString(epochKeyHex)
	if err != nil {
		t.Fatalf("failed to decode epoch key: %v", err)
	}

	initiatorRandom, err := hex.DecodeString(initiatorRandomHex)
	if err != nil {
		t.Fatalf("failed to decode initiator random: %v", err)
	}

	expectedDestID, err := hex.DecodeString(expectedDestIDHex)
	if err != nil {
		t.Fatalf("failed to decode expected destination ID: %v", err)
	}

	derivedIPK, err := hex.DecodeString(derivedIPKHex)
	if err != nil {
		t.Fatalf("failed to decode derived IPK: %v", err)
	}

	// First verify the IPK derivation matches the spec
	// We need to compute the compressed fabric ID from the root public key and fabric ID
	// The spec doesn't provide the compressed fabric ID directly, but we can verify
	// by checking the derived IPK matches.
	//
	// For this test, we'll use the pre-derived IPK from the spec to verify
	// the destination ID computation. We'll test IPK derivation separately.

	// Test with pre-derived IPK (the main test)
	t.Run("WithDerivedIPK", func(t *testing.T) {
		var random [RandomSize]byte
		copy(random[:], initiatorRandom)

		var rootPubKey [crypto.P256PublicKeySizeBytes]byte
		copy(rootPubKey[:], rootPublicKey)

		var ipk [crypto.SymmetricKeySize]byte
		copy(ipk[:], derivedIPK)

		destID := GenerateDestinationID(random, rootPubKey, fabricID, nodeID, ipk)

		if hex.EncodeToString(destID[:]) != expectedDestIDHex {
			t.Errorf("destination ID mismatch:\ngot:  %s\nwant: %s",
				hex.EncodeToString(destID[:]), expectedDestIDHex)
		}
	})

	// Test that MatchDestinationID works
	t.Run("MatchDestinationID", func(t *testing.T) {
		var random [RandomSize]byte
		copy(random[:], initiatorRandom)

		var rootPubKey [crypto.P256PublicKeySizeBytes]byte
		copy(rootPubKey[:], rootPublicKey)

		var ipk [crypto.SymmetricKeySize]byte
		copy(ipk[:], derivedIPK)

		var expectedDest [DestinationIDSize]byte
		copy(expectedDest[:], expectedDestID)

		// Should match with correct parameters
		if !MatchDestinationID(expectedDest, random, rootPubKey, fabricID, nodeID, ipk) {
			t.Error("MatchDestinationID should return true for matching parameters")
		}

		// Should not match with wrong fabric ID
		if MatchDestinationID(expectedDest, random, rootPubKey, fabricID+1, nodeID, ipk) {
			t.Error("MatchDestinationID should return false for wrong fabric ID")
		}

		// Should not match with wrong node ID
		if MatchDestinationID(expectedDest, random, rootPubKey, fabricID, nodeID+1, ipk) {
			t.Error("MatchDestinationID should return false for wrong node ID")
		}

		// Should not match with wrong IPK
		wrongIPK := ipk
		wrongIPK[0] ^= 0xFF
		if MatchDestinationID(expectedDest, random, rootPubKey, fabricID, nodeID, wrongIPK) {
			t.Error("MatchDestinationID should return false for wrong IPK")
		}
	})

	// Test IPK derivation using the spec vector
	// The compressed fabric ID = HKDF-SHA256(RootPublicKey, FabricID, "CompressedFabric", 8)
	// We need to verify that deriving the IPK from epoch key + compressed fabric ID
	// produces the expected IPK from the spec.
	t.Run("IPKDerivation", func(t *testing.T) {
		// Use the fabric package to compute compressed fabric ID properly.
		// The fabric package strips the 0x04 prefix and uses the 64-byte key.
		var rootPubKey [65]byte
		copy(rootPubKey[:], rootPublicKey)

		compressedFabricID, err := fabric.CompressedFabricIDFromCert(rootPubKey, fabric.FabricID(fabricID))
		if err != nil {
			t.Fatalf("failed to compute compressed fabric ID: %v", err)
		}

		// Now derive IPK from epoch key
		derivedIPKResult, err := crypto.DeriveGroupOperationalKeyV1(epochKey, compressedFabricID[:])
		if err != nil {
			t.Fatalf("failed to derive IPK: %v", err)
		}

		// Compare with expected derived IPK from spec
		if hex.EncodeToString(derivedIPKResult) != derivedIPKHex {
			t.Errorf("derived IPK mismatch:\ngot:  %s\nwant: %s",
				hex.EncodeToString(derivedIPKResult), derivedIPKHex)
		}
	})
}

// TestGenerateDestinationID_DifferentInputs verifies that different inputs
// produce different destination IDs (collision resistance).
func TestGenerateDestinationID_DifferentInputs(t *testing.T) {
	// Base parameters
	var random [RandomSize]byte
	for i := range random {
		random[i] = byte(i)
	}

	var rootPubKey [crypto.P256PublicKeySizeBytes]byte
	rootPubKey[0] = 0x04 // Uncompressed marker
	for i := 1; i < len(rootPubKey); i++ {
		rootPubKey[i] = byte(i)
	}

	var ipk [crypto.SymmetricKeySize]byte
	for i := range ipk {
		ipk[i] = byte(i + 100)
	}

	fabricID := uint64(0x1234567890ABCDEF)
	nodeID := uint64(0xFEDCBA0987654321)

	base := GenerateDestinationID(random, rootPubKey, fabricID, nodeID, ipk)

	// Change random
	random2 := random
	random2[0] ^= 0xFF
	if GenerateDestinationID(random2, rootPubKey, fabricID, nodeID, ipk) == base {
		t.Error("different random should produce different destination ID")
	}

	// Change root public key
	rootPubKey2 := rootPubKey
	rootPubKey2[1] ^= 0xFF
	if GenerateDestinationID(random, rootPubKey2, fabricID, nodeID, ipk) == base {
		t.Error("different root public key should produce different destination ID")
	}

	// Change fabric ID
	if GenerateDestinationID(random, rootPubKey, fabricID+1, nodeID, ipk) == base {
		t.Error("different fabric ID should produce different destination ID")
	}

	// Change node ID
	if GenerateDestinationID(random, rootPubKey, fabricID, nodeID+1, ipk) == base {
		t.Error("different node ID should produce different destination ID")
	}

	// Change IPK
	ipk2 := ipk
	ipk2[0] ^= 0xFF
	if GenerateDestinationID(random, rootPubKey, fabricID, nodeID, ipk2) == base {
		t.Error("different IPK should produce different destination ID")
	}
}
