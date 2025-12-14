package credentials

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// MatterToX509 converts a Matter TLV Certificate to X.509 DER format.
func MatterToX509(cert *Certificate) ([]byte, error) {
	// Build the TBSCertificate structure
	tbs, err := buildTBSCertificate(cert)
	if err != nil {
		return nil, err
	}

	// Build the full Certificate structure
	x509Cert := x509Certificate{
		TBSCertificate:     tbs,
		SignatureAlgorithm: getSignatureAlgoIdentifier(cert.SigAlgo),
		SignatureValue:     asn1.BitString{Bytes: convertSignatureToASN1(cert.Signature), BitLength: len(cert.Signature) * 8},
	}

	// Re-encode the signature as ASN.1
	sigASN1, err := convertRawSignatureToASN1(cert.Signature)
	if err != nil {
		return nil, err
	}
	x509Cert.SignatureValue = asn1.BitString{Bytes: sigASN1, BitLength: len(sigASN1) * 8}

	der, err := asn1.Marshal(x509Cert)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrX509EncodeFailed, err)
	}

	return der, nil
}

// MatterToX509PEM converts a Matter TLV Certificate to PEM format.
func MatterToX509PEM(cert *Certificate) ([]byte, error) {
	der, err := MatterToX509(cert)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}

	return pem.EncodeToMemory(block), nil
}

// x509Certificate is the ASN.1 structure for an X.509 certificate.
type x509Certificate struct {
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// tbsCertificate is the ASN.1 structure for the TBSCertificate.
type tbsCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKeyInfo      publicKeyInfo
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

// validity represents the certificate validity period.
type validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// publicKeyInfo represents the SubjectPublicKeyInfo structure.
type publicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// buildTBSCertificate builds the TBSCertificate from a Matter certificate.
func buildTBSCertificate(cert *Certificate) (tbsCertificate, error) {
	tbs := tbsCertificate{
		Version:            2, // X.509 v3
		SerialNumber:       new(big.Int).SetBytes(cert.SerialNum),
		SignatureAlgorithm: getSignatureAlgoIdentifier(cert.SigAlgo),
	}

	// Issuer
	issuerDN, err := buildX509DN(cert.Issuer)
	if err != nil {
		return tbs, fmt.Errorf("issuer: %w", err)
	}
	issuerRaw, err := asn1.Marshal(issuerDN)
	if err != nil {
		return tbs, fmt.Errorf("issuer marshal: %w", err)
	}
	tbs.Issuer = asn1.RawValue{FullBytes: issuerRaw}

	// Validity
	tbs.Validity = validity{
		NotBefore: matterEpochToTime(cert.NotBefore),
		NotAfter:  matterEpochToTime(cert.NotAfter),
	}

	// Subject
	subjectDN, err := buildX509DN(cert.Subject)
	if err != nil {
		return tbs, fmt.Errorf("subject: %w", err)
	}
	subjectRaw, err := asn1.Marshal(subjectDN)
	if err != nil {
		return tbs, fmt.Errorf("subject marshal: %w", err)
	}
	tbs.Subject = asn1.RawValue{FullBytes: subjectRaw}

	// Public key
	tbs.PublicKeyInfo = publicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  OIDPublicKeyECDSA,
			Parameters: asn1.RawValue{FullBytes: mustMarshal(OIDNamedCurvePrime256v1)},
		},
		PublicKey: asn1.BitString{Bytes: cert.ECPubKey, BitLength: len(cert.ECPubKey) * 8},
	}

	// Extensions
	exts, err := buildX509Extensions(cert)
	if err != nil {
		return tbs, err
	}
	tbs.Extensions = exts

	return tbs, nil
}

// buildX509DN builds an X.509 Distinguished Name from Matter DN.
func buildX509DN(dn DistinguishedName) ([]pkix.RelativeDistinguishedNameSET, error) {
	var rdns []pkix.RelativeDistinguishedNameSET

	for _, attr := range dn {
		var atv pkix.AttributeTypeAndValue

		// Get OID for the tag
		baseTag := attr.BaseTag()
		oid := TagToOID(baseTag)
		if oid == nil {
			return nil, fmt.Errorf("%w: unknown tag %d", ErrUnsupportedOID, attr.Tag)
		}
		atv.Type = oid

		if attr.IsMatterSpecific() {
			// Convert uint64 to hex string for X.509
			byteLen := attr.MatterSpecificByteLength()
			atv.Value = MatterSpecificToHexString(attr.Uint64Value(), byteLen)
		} else {
			atv.Value = attr.StringValue()
		}

		rdns = append(rdns, pkix.RelativeDistinguishedNameSET{atv})
	}

	return rdns, nil
}

// buildX509Extensions builds X.509 extensions from Matter extensions.
func buildX509Extensions(cert *Certificate) ([]pkix.Extension, error) {
	var exts []pkix.Extension

	// Basic Constraints
	if cert.Extensions.BasicConstraints != nil {
		bc := cert.Extensions.BasicConstraints
		var bcValue struct {
			IsCA       bool `asn1:"optional"`
			MaxPathLen int  `asn1:"optional,default:-1"`
		}
		bcValue.IsCA = bc.IsCA
		if bc.PathLenConstraint != nil {
			bcValue.MaxPathLen = int(*bc.PathLenConstraint)
		} else {
			bcValue.MaxPathLen = -1
		}

		value, err := asn1.Marshal(bcValue)
		if err != nil {
			return nil, fmt.Errorf("basic constraints: %w", err)
		}

		exts = append(exts, pkix.Extension{
			Id:       OIDExtensionBasicConstraints,
			Critical: true,
			Value:    value,
		})
	}

	// Key Usage
	if cert.Extensions.KeyUsage != nil {
		ku := cert.Extensions.KeyUsage.Usage
		bits := keyUsageToBitString(ku)
		value, err := asn1.Marshal(bits)
		if err != nil {
			return nil, fmt.Errorf("key usage: %w", err)
		}

		exts = append(exts, pkix.Extension{
			Id:       OIDExtensionKeyUsage,
			Critical: true,
			Value:    value,
		})
	}

	// Extended Key Usage
	if cert.Extensions.ExtendedKeyUsage != nil {
		var oids []asn1.ObjectIdentifier
		for _, kp := range cert.Extensions.ExtendedKeyUsage.KeyPurposes {
			oid := KeyPurposeToOID(kp)
			if oid != nil {
				oids = append(oids, oid)
			}
		}

		value, err := asn1.Marshal(oids)
		if err != nil {
			return nil, fmt.Errorf("extended key usage: %w", err)
		}

		exts = append(exts, pkix.Extension{
			Id:       OIDExtensionExtKeyUsage,
			Critical: true,
			Value:    value,
		})
	}

	// Subject Key Identifier
	if cert.Extensions.SubjectKeyID != nil {
		value, err := asn1.Marshal(cert.Extensions.SubjectKeyID.KeyID[:])
		if err != nil {
			return nil, fmt.Errorf("subject key ID: %w", err)
		}

		exts = append(exts, pkix.Extension{
			Id:       OIDExtensionSubjectKeyID,
			Critical: false,
			Value:    value,
		})
	}

	// Authority Key Identifier
	if cert.Extensions.AuthorityKeyID != nil {
		// AuthorityKeyIdentifier with just keyIdentifier field
		aki := struct {
			KeyIdentifier []byte `asn1:"optional,tag:0"`
		}{
			KeyIdentifier: cert.Extensions.AuthorityKeyID.KeyID[:],
		}

		value, err := asn1.Marshal(aki)
		if err != nil {
			return nil, fmt.Errorf("authority key ID: %w", err)
		}

		exts = append(exts, pkix.Extension{
			Id:       OIDExtensionAuthorityKeyID,
			Critical: false,
			Value:    value,
		})
	}

	// Future extensions (pass through as-is)
	for _, fe := range cert.Extensions.FutureExtensions {
		// The future extension data should be the raw extension value
		// We don't know the OID, so we can't properly reconstruct it
		// This is a limitation - future extensions need special handling
		_ = fe
	}

	return exts, nil
}

// getSignatureAlgoIdentifier returns the AlgorithmIdentifier for the signature algorithm.
func getSignatureAlgoIdentifier(algo SignatureAlgo) pkix.AlgorithmIdentifier {
	switch algo {
	case SignatureAlgoECDSASHA256:
		return pkix.AlgorithmIdentifier{Algorithm: OIDSignatureECDSAWithSHA256}
	default:
		return pkix.AlgorithmIdentifier{}
	}
}

// convertRawSignatureToASN1 converts raw r||s signature to ASN.1 DER format.
func convertRawSignatureToASN1(raw []byte) ([]byte, error) {
	if len(raw) != SignatureSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidSignature, SignatureSize, len(raw))
	}

	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])

	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

// convertSignatureToASN1 is a helper that panics on error (for use in struct literals).
func convertSignatureToASN1(raw []byte) []byte {
	der, err := convertRawSignatureToASN1(raw)
	if err != nil {
		return nil
	}
	return der
}

// matterEpochToTime converts Matter epoch seconds to time.Time.
func matterEpochToTime(epochSecs uint32) time.Time {
	if epochSecs == 0 {
		// Special value for "no well-defined expiration"
		return time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	}
	return MatterEpochStart.Add(time.Duration(epochSecs) * time.Second)
}

// keyUsageToBitString converts Matter KeyUsage to ASN.1 bit string.
func keyUsageToBitString(ku KeyUsage) asn1.BitString {
	// Calculate the number of bits needed
	var bytes []byte
	var bitLen int

	// Key usage bits in ASN.1 order
	// Bit 0 = digitalSignature, Bit 1 = nonRepudiation, etc.
	var bits uint16
	if ku&KeyUsageDigitalSignature != 0 {
		bits |= 0x8000
	}
	if ku&KeyUsageNonRepudiation != 0 {
		bits |= 0x4000
	}
	if ku&KeyUsageKeyEncipherment != 0 {
		bits |= 0x2000
	}
	if ku&KeyUsageDataEncipherment != 0 {
		bits |= 0x1000
	}
	if ku&KeyUsageKeyAgreement != 0 {
		bits |= 0x0800
	}
	if ku&KeyUsageKeyCertSign != 0 {
		bits |= 0x0400
	}
	if ku&KeyUsageCRLSign != 0 {
		bits |= 0x0200
	}
	if ku&KeyUsageEncipherOnly != 0 {
		bits |= 0x0100
	}
	if ku&KeyUsageDecipherOnly != 0 {
		bits |= 0x0080
	}

	// Determine minimum bytes needed
	if bits&0x00FF != 0 {
		bytes = []byte{byte(bits >> 8), byte(bits)}
		bitLen = 16 - trailingZeroBits(uint16(bits))
	} else if bits != 0 {
		bytes = []byte{byte(bits >> 8)}
		bitLen = 8 - trailingZeroBits(uint16(bits>>8))
	} else {
		bytes = []byte{0}
		bitLen = 0
	}

	return asn1.BitString{Bytes: bytes, BitLength: bitLen}
}

// trailingZeroBits counts trailing zero bits in a uint16.
func trailingZeroBits(v uint16) int {
	if v == 0 {
		return 16
	}
	n := 0
	for v&1 == 0 {
		v >>= 1
		n++
	}
	return n
}

// mustMarshal marshals v and panics on error.
func mustMarshal(v interface{}) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
