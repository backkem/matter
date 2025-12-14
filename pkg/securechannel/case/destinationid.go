package casesession

import (
	"encoding/binary"

	"github.com/backkem/matter/pkg/crypto"
)

// GenerateDestinationID computes the destination identifier per Section 4.14.2.4.1.
//
// The destination identifier allows the initiator to specify which fabric and node
// it wants to communicate with, in a privacy-preserving manner.
//
// destinationMessage = initiatorRandom || rootPublicKey || fabricId || nodeId
// destinationIdentifier = HMAC-SHA256(key=IPK, message=destinationMessage)
//
// Parameters:
//   - initiatorRandom: 32-byte random from Sigma1
//   - rootPublicKey: 65-byte uncompressed P-256 public key of RCAC
//   - fabricID: Target fabric ID (will be encoded little-endian)
//   - nodeID: Target node ID (will be encoded little-endian)
//   - ipk: 16-byte Identity Protection Key (derived operational group key, not epoch key)
//
// Returns 32-byte HMAC-SHA256 destination identifier.
func GenerateDestinationID(
	initiatorRandom [RandomSize]byte,
	rootPublicKey [crypto.P256PublicKeySizeBytes]byte,
	fabricID uint64,
	nodeID uint64,
	ipk [crypto.SymmetricKeySize]byte,
) [DestinationIDSize]byte {
	// Build destination message:
	// initiatorRandom (32) || rootPublicKey (65) || fabricId (8 LE) || nodeId (8 LE)
	// Total: 32 + 65 + 8 + 8 = 113 bytes
	msg := make([]byte, 0, RandomSize+crypto.P256PublicKeySizeBytes+8+8)

	msg = append(msg, initiatorRandom[:]...)
	msg = append(msg, rootPublicKey[:]...)

	// Fabric ID in little-endian
	fabricBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(fabricBytes, fabricID)
	msg = append(msg, fabricBytes...)

	// Node ID in little-endian
	nodeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nodeBytes, nodeID)
	msg = append(msg, nodeBytes...)

	// HMAC-SHA256 with IPK as key
	return crypto.HMACSHA256(ipk[:], msg)
}

// GenerateDestinationIDFromEpochKey computes the destination identifier using an epoch key.
//
// This is a convenience function that first derives the IPK (operational group key)
// from the epoch key and compressed fabric ID, then generates the destination ID.
//
// Parameters:
//   - initiatorRandom: 32-byte random from Sigma1
//   - rootPublicKey: 65-byte uncompressed P-256 public key of RCAC
//   - fabricID: Target fabric ID
//   - nodeID: Target node ID
//   - epochKey: 16-byte epoch key (raw key from Group Key Set 0 / AddNOC IPKValue)
//   - compressedFabricID: 8-byte compressed fabric identifier
//
// Returns 32-byte destination identifier and any error from key derivation.
func GenerateDestinationIDFromEpochKey(
	initiatorRandom [RandomSize]byte,
	rootPublicKey [crypto.P256PublicKeySizeBytes]byte,
	fabricID uint64,
	nodeID uint64,
	epochKey [crypto.SymmetricKeySize]byte,
	compressedFabricID [crypto.CompressedFabricIDSize]byte,
) ([DestinationIDSize]byte, error) {
	// Derive operational group key (IPK) from epoch key
	ipkSlice, err := crypto.DeriveGroupOperationalKeyV1(epochKey[:], compressedFabricID[:])
	if err != nil {
		return [DestinationIDSize]byte{}, err
	}

	var ipk [crypto.SymmetricKeySize]byte
	copy(ipk[:], ipkSlice)

	return GenerateDestinationID(initiatorRandom, rootPublicKey, fabricID, nodeID, ipk), nil
}

// MatchDestinationID validates an incoming destination ID against candidate parameters.
//
// The responder traverses all installed NOCs and IPK epoch keys, computing candidate
// destination IDs until a match is found.
//
// Parameters:
//   - destinationID: 32-byte incoming destination ID from Sigma1
//   - initiatorRandom: 32-byte random from Sigma1
//   - rootPublicKey: 65-byte uncompressed P-256 public key of candidate RCAC
//   - fabricID: Candidate fabric ID
//   - nodeID: Candidate node ID
//   - ipk: 16-byte candidate IPK (derived operational group key)
//
// Returns true if the destination ID matches.
func MatchDestinationID(
	destinationID [DestinationIDSize]byte,
	initiatorRandom [RandomSize]byte,
	rootPublicKey [crypto.P256PublicKeySizeBytes]byte,
	fabricID uint64,
	nodeID uint64,
	ipk [crypto.SymmetricKeySize]byte,
) bool {
	candidate := GenerateDestinationID(initiatorRandom, rootPublicKey, fabricID, nodeID, ipk)
	return destinationID == candidate
}
