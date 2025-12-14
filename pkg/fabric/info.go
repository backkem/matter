package fabric

import (
	"errors"
	"fmt"
)

// FabricInfo errors.
var (
	// ErrInvalidIPK is returned when the IPK has invalid length.
	ErrInvalidIPK = errors.New("fabric: invalid IPK length")
	// ErrInvalidLabel is returned when the label exceeds max length.
	ErrInvalidLabel = errors.New("fabric: label exceeds maximum length")
)

// FabricInfo stores the internal representation of a fabric entry.
// This is the runtime storage structure, not the wire format.
//
// FabricInfo is created when a node is commissioned into a fabric via AddNOC.
// It stores all the credentials and metadata needed for operational communication.
type FabricInfo struct {
	// FabricIndex is the local 8-bit index for this fabric (1-254).
	FabricIndex FabricIndex

	// FabricID is the 64-bit fabric identifier extracted from the NOC.
	FabricID FabricID

	// NodeID is the 64-bit node identifier extracted from the NOC.
	NodeID NodeID

	// VendorID is the admin vendor ID provided in the AddNOC command.
	VendorID VendorID

	// Label is a user-assigned label for this fabric (max 32 UTF-8 bytes).
	Label string

	// RootCert is the Root CA Certificate (RCAC) in Matter TLV encoding.
	RootCert []byte

	// NOC is the Node Operational Certificate in Matter TLV encoding.
	NOC []byte

	// ICAC is the Intermediate CA Certificate (optional) in Matter TLV encoding.
	// Nil if no ICAC is present in the chain.
	ICAC []byte

	// RootPublicKey is the 65-byte uncompressed public key from the RCAC.
	RootPublicKey [RootPublicKeySize]byte

	// CompressedFabricID is the pre-computed 8-byte compressed fabric ID.
	// Used for DNS-SD operational discovery.
	CompressedFabricID [CompressedFabricIDSize]byte

	// IPK is the Identity Protection Key epoch key (16 bytes).
	// This is Group Key Set 0, provided in the AddNOC command.
	IPK [IPKSize]byte
}

// NewFabricInfo creates a FabricInfo from the provided certificates and parameters.
//
// It validates the certificate chain and extracts:
// - FabricID and NodeID from the NOC
// - RootPublicKey from the RCAC
// - Computes the CompressedFabricID
//
// Parameters:
//   - index: The local fabric index (1-254)
//   - rootCert: RCAC in Matter TLV encoding
//   - noc: NOC in Matter TLV encoding
//   - icac: ICAC in Matter TLV encoding (nil if no ICAC)
//   - vendorID: Admin vendor ID from AddNOC command
//   - ipk: Identity Protection Key epoch key (16 bytes)
func NewFabricInfo(
	index FabricIndex,
	rootCert, noc, icac []byte,
	vendorID VendorID,
	ipk [IPKSize]byte,
) (*FabricInfo, error) {
	// Validate fabric index
	if !index.IsValid() {
		return nil, fmt.Errorf("fabric: invalid fabric index: %d", index)
	}

	// Validate certificate chain
	if err := ValidateNOCChain(rootCert, noc, icac); err != nil {
		return nil, fmt.Errorf("fabric: certificate chain validation failed: %w", err)
	}

	// Extract chain info
	chainInfo, err := ExtractChainInfo(rootCert, noc)
	if err != nil {
		return nil, fmt.Errorf("fabric: failed to extract chain info: %w", err)
	}

	// Compute compressed fabric ID
	compressedID, err := CompressedFabricIDFromCert(chainInfo.RootPublicKey, chainInfo.FabricID)
	if err != nil {
		return nil, fmt.Errorf("fabric: failed to compute compressed fabric ID: %w", err)
	}

	// Create fabric info
	info := &FabricInfo{
		FabricIndex:        index,
		FabricID:           chainInfo.FabricID,
		NodeID:             chainInfo.NodeID,
		VendorID:           vendorID,
		Label:              "",
		RootCert:           make([]byte, len(rootCert)),
		NOC:                make([]byte, len(noc)),
		RootPublicKey:      chainInfo.RootPublicKey,
		CompressedFabricID: compressedID,
		IPK:                ipk,
	}

	// Copy certificates (don't hold references to caller's slices)
	copy(info.RootCert, rootCert)
	copy(info.NOC, noc)

	if icac != nil {
		info.ICAC = make([]byte, len(icac))
		copy(info.ICAC, icac)
	}

	return info, nil
}

// HasICAC returns true if this fabric has an intermediate CA certificate.
func (f *FabricInfo) HasICAC() bool {
	return len(f.ICAC) > 0
}

// SetLabel sets the fabric label. Returns error if label exceeds max length.
func (f *FabricInfo) SetLabel(label string) error {
	if len(label) > MaxLabelSize {
		return fmt.Errorf("%w: %d bytes (max %d)", ErrInvalidLabel, len(label), MaxLabelSize)
	}
	f.Label = label
	return nil
}

// GetNOCStruct returns the NOCStruct wire format for this fabric.
func (f *FabricInfo) GetNOCStruct() NOCStruct {
	return NOCStruct{
		NOC:  f.NOC,
		ICAC: f.ICAC,
	}
}

// GetFabricDescriptor returns the FabricDescriptorStruct wire format for this fabric.
func (f *FabricInfo) GetFabricDescriptor() FabricDescriptorStruct {
	return FabricDescriptorStruct{
		RootPublicKey: f.RootPublicKey,
		VendorID:      f.VendorID,
		FabricID:      f.FabricID,
		NodeID:        f.NodeID,
		Label:         f.Label,
	}
}

// MatchesRootPublicKey returns true if this fabric's root public key matches.
func (f *FabricInfo) MatchesRootPublicKey(key [RootPublicKeySize]byte) bool {
	return f.RootPublicKey == key
}

// MatchesCompressedFabricID returns true if this fabric's compressed ID matches.
func (f *FabricInfo) MatchesCompressedFabricID(cfid [CompressedFabricIDSize]byte) bool {
	return f.CompressedFabricID == cfid
}

// String returns a human-readable representation of the fabric info.
func (f *FabricInfo) String() string {
	icacStatus := "no"
	if f.HasICAC() {
		icacStatus = "yes"
	}
	return fmt.Sprintf("Fabric{Index=%d, FabricID=0x%016X, NodeID=0x%016X, Vendor=0x%04X, Label=%q, ICAC=%s}",
		f.FabricIndex, uint64(f.FabricID), uint64(f.NodeID), uint16(f.VendorID), f.Label, icacStatus)
}

// Clone returns a deep copy of the FabricInfo.
func (f *FabricInfo) Clone() *FabricInfo {
	clone := &FabricInfo{
		FabricIndex:        f.FabricIndex,
		FabricID:           f.FabricID,
		NodeID:             f.NodeID,
		VendorID:           f.VendorID,
		Label:              f.Label,
		RootPublicKey:      f.RootPublicKey,
		CompressedFabricID: f.CompressedFabricID,
		IPK:                f.IPK,
	}

	clone.RootCert = make([]byte, len(f.RootCert))
	copy(clone.RootCert, f.RootCert)

	clone.NOC = make([]byte, len(f.NOC))
	copy(clone.NOC, f.NOC)

	if f.ICAC != nil {
		clone.ICAC = make([]byte, len(f.ICAC))
		copy(clone.ICAC, f.ICAC)
	}

	return clone
}
