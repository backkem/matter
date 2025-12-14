package credentials

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// X509ToMatter converts an X.509 DER certificate to a Matter TLV Certificate.
func X509ToMatter(der []byte) (*Certificate, error) {
	x509Cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrX509ParseFailed, err)
	}

	return x509CertToMatter(x509Cert)
}

// X509PEMToMatter converts a PEM-encoded X.509 certificate to a Matter TLV Certificate.
func X509PEMToMatter(pemData []byte) (*Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", ErrX509ParseFailed)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: expected CERTIFICATE, got %s", ErrX509ParseFailed, block.Type)
	}
	return X509ToMatter(block.Bytes)
}

// x509CertToMatter converts a parsed x509.Certificate to a Matter Certificate.
func x509CertToMatter(x509Cert *x509.Certificate) (*Certificate, error) {
	cert := &Certificate{}

	// Serial number
	cert.SerialNum = x509Cert.SerialNumber.Bytes()
	if len(cert.SerialNum) > MaxSerialNumSize {
		return nil, ErrInvalidSerialNumber
	}

	// Signature algorithm
	sigAlgo, err := convertSignatureAlgo(x509Cert.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}
	cert.SigAlgo = sigAlgo

	// Issuer
	issuer, err := convertDN(x509Cert.Issuer)
	if err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	cert.Issuer = issuer

	// Validity
	cert.NotBefore = timeToMatterEpoch(x509Cert.NotBefore)
	cert.NotAfter = timeToMatterEpoch(x509Cert.NotAfter)

	// Subject
	subject, err := convertDN(x509Cert.Subject)
	if err != nil {
		return nil, fmt.Errorf("subject: %w", err)
	}
	cert.Subject = subject

	// Public key algorithm and curve
	pubKeyAlgo, curveID, err := convertPublicKeyAlgo(x509Cert)
	if err != nil {
		return nil, err
	}
	cert.PubKeyAlgo = pubKeyAlgo
	cert.ECCurveID = curveID

	// Public key
	pubKey, err := extractPublicKey(x509Cert)
	if err != nil {
		return nil, err
	}
	cert.ECPubKey = pubKey

	// Extensions
	extensions, err := convertExtensions(x509Cert)
	if err != nil {
		return nil, err
	}
	cert.Extensions = extensions

	// Signature (convert from ASN.1 to raw r||s format)
	sig, err := convertSignatureToRaw(x509Cert.Signature)
	if err != nil {
		return nil, err
	}
	cert.Signature = sig

	return cert, nil
}

// convertSignatureAlgo converts X.509 signature algorithm to Matter enum.
func convertSignatureAlgo(algo x509.SignatureAlgorithm) (SignatureAlgo, error) {
	switch algo {
	case x509.ECDSAWithSHA256:
		return SignatureAlgoECDSASHA256, nil
	default:
		return SignatureAlgoUnknown, fmt.Errorf("%w: %v", ErrInvalidSignatureAlgo, algo)
	}
}

// convertPublicKeyAlgo extracts the public key algorithm and curve from X.509.
func convertPublicKeyAlgo(x509Cert *x509.Certificate) (PublicKeyAlgo, EllipticCurveID, error) {
	switch x509Cert.PublicKeyAlgorithm {
	case x509.ECDSA:
		// Verify it's P-256
		// The curve is determined by the key parameters
		// For Matter, only prime256v1 is supported
		return PublicKeyAlgoEC, EllipticCurvePrime256v1, nil
	default:
		return PublicKeyAlgoUnknown, EllipticCurveUnknown,
			fmt.Errorf("%w: %v", ErrInvalidPublicKeyAlgo, x509Cert.PublicKeyAlgorithm)
	}
}

// extractPublicKey extracts the uncompressed EC public key from the certificate.
func extractPublicKey(x509Cert *x509.Certificate) ([]byte, error) {
	// The raw public key is in SubjectPublicKeyInfo
	// We need to extract just the key bytes (65 bytes for uncompressed P-256)
	pubKeyInfo := x509Cert.RawSubjectPublicKeyInfo

	// Parse SubjectPublicKeyInfo
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(pubKeyInfo, &spki); err != nil {
		return nil, fmt.Errorf("%w: failed to parse public key info: %v", ErrInvalidPublicKey, err)
	}

	pubKey := spki.PublicKey.Bytes
	if len(pubKey) != PublicKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidPublicKey, PublicKeySize, len(pubKey))
	}
	if pubKey[0] != 0x04 {
		return nil, fmt.Errorf("%w: expected uncompressed format (0x04)", ErrInvalidPublicKey)
	}

	return pubKey, nil
}

// convertDN converts an X.509 Distinguished Name to Matter format.
func convertDN(name pkix.Name) (DistinguishedName, error) {
	var dn DistinguishedName

	// Process all RDN sequences in order
	for _, rdn := range name.Names {
		attr, err := convertRDN(rdn)
		if err != nil {
			return nil, err
		}
		dn = append(dn, attr)
	}

	return dn, nil
}

// convertRDN converts a single X.509 RDN to a Matter DN attribute.
func convertRDN(rdn pkix.AttributeTypeAndValue) (DNAttribute, error) {
	oid := rdn.Type
	tag := OIDToTag(oid)

	if tag == 0 {
		return DNAttribute{}, fmt.Errorf("%w: %v", ErrUnsupportedOID, oid)
	}

	// Check if this is a Matter-specific attribute
	if IsMatterSpecificTag(tag) {
		// Value should be a hex string, convert to uint64
		strVal, ok := rdn.Value.(string)
		if !ok {
			return DNAttribute{}, fmt.Errorf("%w: matter-specific attribute must be string", ErrInvalidDN)
		}

		u64, err := HexStringToMatterSpecific(strVal)
		if err != nil {
			return DNAttribute{}, fmt.Errorf("%w: %v", ErrInvalidDN, err)
		}

		return NewDNUint64(tag, u64), nil
	}

	// Standard attribute - check encoding type for PrintableString vs UTF8String
	// We need to check the raw ASN.1 to determine the string type
	strVal, ok := rdn.Value.(string)
	if !ok {
		return DNAttribute{}, fmt.Errorf("%w: DN attribute must be string", ErrInvalidDN)
	}

	// Default to UTF8String encoding
	// TODO: Check actual ASN.1 encoding to determine if PrintableString
	return NewDNString(tag, strVal), nil
}

// convertExtensions converts X.509 extensions to Matter format.
func convertExtensions(x509Cert *x509.Certificate) (Extensions, error) {
	var ext Extensions

	// Process extensions in the order they appear
	for _, x509Ext := range x509Cert.Extensions {
		switch {
		case x509Ext.Id.Equal(OIDExtensionBasicConstraints):
			bc, err := parseBasicConstraints(x509Ext.Value)
			if err != nil {
				return ext, err
			}
			ext.BasicConstraints = bc

		case x509Ext.Id.Equal(OIDExtensionKeyUsage):
			ku, err := parseKeyUsage(x509Ext.Value)
			if err != nil {
				return ext, err
			}
			ext.KeyUsage = ku

		case x509Ext.Id.Equal(OIDExtensionExtKeyUsage):
			eku, err := parseExtKeyUsage(x509Ext.Value)
			if err != nil {
				return ext, err
			}
			ext.ExtendedKeyUsage = eku

		case x509Ext.Id.Equal(OIDExtensionSubjectKeyID):
			ski, err := parseSubjectKeyID(x509Ext.Value)
			if err != nil {
				return ext, err
			}
			ext.SubjectKeyID = ski

		case x509Ext.Id.Equal(OIDExtensionAuthorityKeyID):
			aki, err := parseAuthorityKeyID(x509Ext.Value)
			if err != nil {
				return ext, err
			}
			ext.AuthorityKeyID = aki

		default:
			// Store as future extension (raw DER including OID)
			ext.FutureExtensions = append(ext.FutureExtensions, FutureExtensionExt{
				Data: x509Ext.Value,
			})
		}
	}

	return ext, nil
}

// parseBasicConstraints parses the BasicConstraints extension value.
func parseBasicConstraints(value []byte) (*BasicConstraints, error) {
	var bc struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}

	if _, err := asn1.Unmarshal(value, &bc); err != nil {
		return nil, fmt.Errorf("%w: basic constraints: %v", ErrInvalidExtension, err)
	}

	result := &BasicConstraints{
		IsCA: bc.IsCA,
	}

	if bc.MaxPathLen >= 0 {
		pl := uint8(bc.MaxPathLen)
		result.PathLenConstraint = &pl
	}

	return result, nil
}

// parseKeyUsage parses the KeyUsage extension value.
func parseKeyUsage(value []byte) (*KeyUsageExt, error) {
	var bits asn1.BitString
	if _, err := asn1.Unmarshal(value, &bits); err != nil {
		return nil, fmt.Errorf("%w: key usage: %v", ErrInvalidExtension, err)
	}

	// Convert ASN.1 bit string to Matter key usage flags
	// ASN.1 bit string has bits in reverse order within each byte
	var usage KeyUsage
	if bits.At(0) != 0 {
		usage |= KeyUsageDigitalSignature
	}
	if bits.At(1) != 0 {
		usage |= KeyUsageNonRepudiation
	}
	if bits.At(2) != 0 {
		usage |= KeyUsageKeyEncipherment
	}
	if bits.At(3) != 0 {
		usage |= KeyUsageDataEncipherment
	}
	if bits.At(4) != 0 {
		usage |= KeyUsageKeyAgreement
	}
	if bits.At(5) != 0 {
		usage |= KeyUsageKeyCertSign
	}
	if bits.At(6) != 0 {
		usage |= KeyUsageCRLSign
	}
	if bits.At(7) != 0 {
		usage |= KeyUsageEncipherOnly
	}
	if bits.At(8) != 0 {
		usage |= KeyUsageDecipherOnly
	}

	return &KeyUsageExt{Usage: usage}, nil
}

// parseExtKeyUsage parses the ExtendedKeyUsage extension value.
func parseExtKeyUsage(value []byte) (*ExtendedKeyUsageExt, error) {
	var oids []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(value, &oids); err != nil {
		return nil, fmt.Errorf("%w: extended key usage: %v", ErrInvalidExtension, err)
	}

	var purposes []KeyPurposeID
	for _, oid := range oids {
		kp := OIDToKeyPurpose(oid)
		if kp == KeyPurposeUnknown {
			return nil, fmt.Errorf("%w: unknown key purpose OID: %v", ErrInvalidExtension, oid)
		}
		purposes = append(purposes, kp)
	}

	return &ExtendedKeyUsageExt{KeyPurposes: purposes}, nil
}

// parseSubjectKeyID parses the SubjectKeyIdentifier extension value.
func parseSubjectKeyID(value []byte) (*SubjectKeyIDExt, error) {
	var keyID []byte
	if _, err := asn1.Unmarshal(value, &keyID); err != nil {
		return nil, fmt.Errorf("%w: subject key ID: %v", ErrInvalidExtension, err)
	}

	if len(keyID) != 20 {
		return nil, fmt.Errorf("%w: subject key ID must be 20 bytes, got %d", ErrInvalidExtension, len(keyID))
	}

	ski := &SubjectKeyIDExt{}
	copy(ski.KeyID[:], keyID)
	return ski, nil
}

// parseAuthorityKeyID parses the AuthorityKeyIdentifier extension value.
func parseAuthorityKeyID(value []byte) (*AuthorityKeyIDExt, error) {
	// AuthorityKeyIdentifier has optional fields: keyIdentifier, authorityCertIssuer, authorityCertSerialNumber
	// Matter only supports keyIdentifier
	var aki struct {
		KeyIdentifier             []byte `asn1:"optional,tag:0"`
		AuthorityCertIssuer       asn1.RawValue `asn1:"optional,tag:1"`
		AuthorityCertSerialNumber *big.Int `asn1:"optional,tag:2"`
	}

	if _, err := asn1.Unmarshal(value, &aki); err != nil {
		return nil, fmt.Errorf("%w: authority key ID: %v", ErrInvalidExtension, err)
	}

	if len(aki.KeyIdentifier) != 20 {
		return nil, fmt.Errorf("%w: authority key ID must be 20 bytes, got %d", ErrInvalidExtension, len(aki.KeyIdentifier))
	}

	result := &AuthorityKeyIDExt{}
	copy(result.KeyID[:], aki.KeyIdentifier)
	return result, nil
}

// convertSignatureToRaw converts an ASN.1 DER ECDSA signature to raw r||s format.
func convertSignatureToRaw(sig []byte) ([]byte, error) {
	// ASN.1 structure: SEQUENCE { INTEGER r, INTEGER s }
	var ecdsaSig struct {
		R, S *big.Int
	}

	if _, err := asn1.Unmarshal(sig, &ecdsaSig); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignatureConversionFailed, err)
	}

	// Convert to fixed-size r || s format (32 bytes each)
	raw := make([]byte, SignatureSize)
	rBytes := ecdsaSig.R.Bytes()
	sBytes := ecdsaSig.S.Bytes()

	// Zero-pad and copy (right-aligned)
	copy(raw[32-len(rBytes):32], rBytes)
	copy(raw[64-len(sBytes):64], sBytes)

	return raw, nil
}

// timeToMatterEpoch converts a time.Time to Matter epoch seconds.
// Special handling for the "no expiration" time 99991231235959Z.
func timeToMatterEpoch(t time.Time) uint32 {
	// Check for special "no expiration" time (year 9999)
	if t.Year() == 9999 {
		return 0
	}

	if t.Before(MatterEpochStart) {
		return 0
	}

	secs := t.Sub(MatterEpochStart).Seconds()
	if secs > float64(^uint32(0)) {
		// Overflow - treat as no expiration
		return 0
	}

	return uint32(secs)
}
