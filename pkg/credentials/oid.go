package credentials

import "encoding/asn1"

// Matter TLV context tags for certificate fields.
// Spec Section 6.5.2
const (
	TagSerialNum   uint8 = 1
	TagSigAlgo     uint8 = 2
	TagIssuer      uint8 = 3
	TagNotBefore   uint8 = 4
	TagNotAfter    uint8 = 5
	TagSubject     uint8 = 6
	TagPubKeyAlgo  uint8 = 7
	TagECCurveID   uint8 = 8
	TagECPubKey    uint8 = 9
	TagExtensions  uint8 = 10
	TagSignature   uint8 = 11
)

// Matter TLV context tags for DN attributes.
// Spec Section 6.5.6.1, Table 85 and Table 86
const (
	// Standard DN attributes (UTF8String encoding in X.509)
	TagDNCommonName           uint8 = 1
	TagDNSurname              uint8 = 2
	TagDNSerialNum            uint8 = 3
	TagDNCountryName          uint8 = 4
	TagDNLocalityName         uint8 = 5
	TagDNStateOrProvinceName  uint8 = 6
	TagDNOrgName              uint8 = 7
	TagDNOrgUnitName          uint8 = 8
	TagDNTitle                uint8 = 9
	TagDNName                 uint8 = 10
	TagDNGivenName            uint8 = 11
	TagDNInitials             uint8 = 12
	TagDNGenQualifier         uint8 = 13
	TagDNDNQualifier          uint8 = 14
	TagDNPseudonym            uint8 = 15
	TagDNDomainComponent      uint8 = 16

	// Matter-specific DN attributes
	TagDNMatterNodeID            uint8 = 17
	TagDNMatterFirmwareSigningID uint8 = 18
	TagDNMatterICACID            uint8 = 19
	TagDNMatterRCACID            uint8 = 20
	TagDNMatterFabricID          uint8 = 21
	TagDNMatterNOCCAT            uint8 = 22
	TagDNMatterVVSID             uint8 = 23

	// PrintableString encoding offset (tag + 0x80)
	TagDNPrintableStringOffset uint8 = 0x80
)

// Matter TLV context tags for extensions.
// Spec Section 6.5.11, Table 90
const (
	TagExtBasicConstraints  uint8 = 1
	TagExtKeyUsage          uint8 = 2
	TagExtExtendedKeyUsage  uint8 = 3
	TagExtSubjectKeyID      uint8 = 4
	TagExtAuthorityKeyID    uint8 = 5
	TagExtFutureExtension   uint8 = 6
)

// Basic constraints structure tags.
// Spec Section 6.5.11.1
const (
	TagBasicConstraintsIsCA       uint8 = 1
	TagBasicConstraintsPathLen    uint8 = 2
)

// Standard X.509 DN OIDs.
var (
	OIDCommonName          = asn1.ObjectIdentifier{2, 5, 4, 3}
	OIDSurname             = asn1.ObjectIdentifier{2, 5, 4, 4}
	OIDSerialNumber        = asn1.ObjectIdentifier{2, 5, 4, 5}
	OIDCountryName         = asn1.ObjectIdentifier{2, 5, 4, 6}
	OIDLocalityName        = asn1.ObjectIdentifier{2, 5, 4, 7}
	OIDStateOrProvinceName = asn1.ObjectIdentifier{2, 5, 4, 8}
	OIDOrganizationName    = asn1.ObjectIdentifier{2, 5, 4, 10}
	OIDOrganizationalUnit  = asn1.ObjectIdentifier{2, 5, 4, 11}
	OIDTitle               = asn1.ObjectIdentifier{2, 5, 4, 12}
	OIDName                = asn1.ObjectIdentifier{2, 5, 4, 41}
	OIDGivenName           = asn1.ObjectIdentifier{2, 5, 4, 42}
	OIDInitials            = asn1.ObjectIdentifier{2, 5, 4, 43}
	OIDGenerationQualifier = asn1.ObjectIdentifier{2, 5, 4, 44}
	OIDDNQualifier         = asn1.ObjectIdentifier{2, 5, 4, 46}
	OIDPseudonym           = asn1.ObjectIdentifier{2, 5, 4, 65}
	OIDDomainComponent     = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
)

// Matter-specific DN OIDs under the CSA private arc 1.3.6.1.4.1.37244.
// Spec Section 6.1.1, Table 83
var (
	OIDMatterNodeID            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 1}
	OIDMatterFirmwareSigningID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 2}
	OIDMatterICACID            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 3}
	OIDMatterRCACID            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 4}
	OIDMatterFabricID          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 5}
	OIDMatterNOCCAT            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 6}
	OIDMatterVVSID             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 7}

	// Device Attestation OIDs (for VID/PID in DAC certificates)
	OIDMatterVendorID  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 2, 1}
	OIDMatterProductID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 2, 2}
)

// X.509 signature algorithm OIDs.
var (
	OIDSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// X.509 public key algorithm OIDs.
var (
	OIDPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// X.509 elliptic curve OIDs.
var (
	OIDNamedCurvePrime256v1 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
)

// X.509 extension OIDs.
var (
	OIDExtensionBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	OIDExtensionKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	OIDExtensionExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	OIDExtensionSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
	OIDExtensionAuthorityKeyID   = asn1.ObjectIdentifier{2, 5, 29, 35}
)

// Extended key usage OIDs.
var (
	OIDExtKeyUsageServerAuth      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	OIDExtKeyUsageClientAuth      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	OIDExtKeyUsageCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	OIDExtKeyUsageEmailProtection = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	OIDExtKeyUsageTimeStamping    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	OIDExtKeyUsageOCSPSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
)

// oidToTag maps X.509 OIDs to Matter TLV context tags for DN attributes.
var oidToTag = map[string]uint8{
	OIDCommonName.String():          TagDNCommonName,
	OIDSurname.String():             TagDNSurname,
	OIDSerialNumber.String():        TagDNSerialNum,
	OIDCountryName.String():         TagDNCountryName,
	OIDLocalityName.String():        TagDNLocalityName,
	OIDStateOrProvinceName.String(): TagDNStateOrProvinceName,
	OIDOrganizationName.String():    TagDNOrgName,
	OIDOrganizationalUnit.String():  TagDNOrgUnitName,
	OIDTitle.String():               TagDNTitle,
	OIDName.String():                TagDNName,
	OIDGivenName.String():           TagDNGivenName,
	OIDInitials.String():            TagDNInitials,
	OIDGenerationQualifier.String(): TagDNGenQualifier,
	OIDDNQualifier.String():         TagDNDNQualifier,
	OIDPseudonym.String():           TagDNPseudonym,
	OIDDomainComponent.String():     TagDNDomainComponent,

	// Matter-specific
	OIDMatterNodeID.String():            TagDNMatterNodeID,
	OIDMatterFirmwareSigningID.String(): TagDNMatterFirmwareSigningID,
	OIDMatterICACID.String():            TagDNMatterICACID,
	OIDMatterRCACID.String():            TagDNMatterRCACID,
	OIDMatterFabricID.String():          TagDNMatterFabricID,
	OIDMatterNOCCAT.String():            TagDNMatterNOCCAT,
	OIDMatterVVSID.String():             TagDNMatterVVSID,
}

// tagToOID maps Matter TLV context tags to X.509 OIDs for DN attributes.
var tagToOID = map[uint8]asn1.ObjectIdentifier{
	TagDNCommonName:          OIDCommonName,
	TagDNSurname:             OIDSurname,
	TagDNSerialNum:           OIDSerialNumber,
	TagDNCountryName:         OIDCountryName,
	TagDNLocalityName:        OIDLocalityName,
	TagDNStateOrProvinceName: OIDStateOrProvinceName,
	TagDNOrgName:             OIDOrganizationName,
	TagDNOrgUnitName:         OIDOrganizationalUnit,
	TagDNTitle:               OIDTitle,
	TagDNName:                OIDName,
	TagDNGivenName:           OIDGivenName,
	TagDNInitials:            OIDInitials,
	TagDNGenQualifier:        OIDGenerationQualifier,
	TagDNDNQualifier:         OIDDNQualifier,
	TagDNPseudonym:           OIDPseudonym,
	TagDNDomainComponent:     OIDDomainComponent,

	// Matter-specific
	TagDNMatterNodeID:            OIDMatterNodeID,
	TagDNMatterFirmwareSigningID: OIDMatterFirmwareSigningID,
	TagDNMatterICACID:            OIDMatterICACID,
	TagDNMatterRCACID:            OIDMatterRCACID,
	TagDNMatterFabricID:          OIDMatterFabricID,
	TagDNMatterNOCCAT:            OIDMatterNOCCAT,
	TagDNMatterVVSID:             OIDMatterVVSID,
}

// keyPurposeToOID maps Matter key purpose IDs to X.509 OIDs.
var keyPurposeToOID = map[KeyPurposeID]asn1.ObjectIdentifier{
	KeyPurposeServerAuth:      OIDExtKeyUsageServerAuth,
	KeyPurposeClientAuth:      OIDExtKeyUsageClientAuth,
	KeyPurposeCodeSigning:     OIDExtKeyUsageCodeSigning,
	KeyPurposeEmailProtection: OIDExtKeyUsageEmailProtection,
	KeyPurposeTimeStamping:    OIDExtKeyUsageTimeStamping,
	KeyPurposeOCSPSigning:     OIDExtKeyUsageOCSPSigning,
}

// oidToKeyPurpose maps X.509 extended key usage OIDs to Matter key purpose IDs.
var oidToKeyPurpose = map[string]KeyPurposeID{
	OIDExtKeyUsageServerAuth.String():      KeyPurposeServerAuth,
	OIDExtKeyUsageClientAuth.String():      KeyPurposeClientAuth,
	OIDExtKeyUsageCodeSigning.String():     KeyPurposeCodeSigning,
	OIDExtKeyUsageEmailProtection.String(): KeyPurposeEmailProtection,
	OIDExtKeyUsageTimeStamping.String():    KeyPurposeTimeStamping,
	OIDExtKeyUsageOCSPSigning.String():     KeyPurposeOCSPSigning,
}

// OIDToTag returns the Matter TLV tag for a given X.509 OID.
// Returns 0 if the OID is not recognized.
func OIDToTag(oid asn1.ObjectIdentifier) uint8 {
	if tag, ok := oidToTag[oid.String()]; ok {
		return tag
	}
	return 0
}

// TagToOID returns the X.509 OID for a given Matter TLV tag.
// Returns nil if the tag is not recognized.
func TagToOID(tag uint8) asn1.ObjectIdentifier {
	// Handle PrintableString tags by stripping the offset
	baseTag := tag
	if tag >= TagDNPrintableStringOffset {
		baseTag = tag - TagDNPrintableStringOffset
	}
	return tagToOID[baseTag]
}

// IsMatterSpecificTag returns true if the tag is for a Matter-specific DN attribute.
func IsMatterSpecificTag(tag uint8) bool {
	baseTag := tag
	if tag >= TagDNPrintableStringOffset {
		baseTag = tag - TagDNPrintableStringOffset
	}
	return baseTag >= TagDNMatterNodeID && baseTag <= TagDNMatterVVSID
}

// IsPrintableStringTag returns true if the tag indicates PrintableString encoding.
func IsPrintableStringTag(tag uint8) bool {
	return tag >= TagDNPrintableStringOffset
}

// KeyPurposeToOID returns the X.509 OID for a Matter key purpose ID.
func KeyPurposeToOID(kp KeyPurposeID) asn1.ObjectIdentifier {
	return keyPurposeToOID[kp]
}

// OIDToKeyPurpose returns the Matter key purpose ID for an X.509 OID.
func OIDToKeyPurpose(oid asn1.ObjectIdentifier) KeyPurposeID {
	if kp, ok := oidToKeyPurpose[oid.String()]; ok {
		return kp
	}
	return KeyPurposeUnknown
}
