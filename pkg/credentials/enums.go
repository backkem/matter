package credentials

// SignatureAlgo represents the signature algorithm used in Matter certificates.
// Spec Section 6.5.5
type SignatureAlgo uint8

const (
	// SignatureAlgoUnknown is an unknown or invalid signature algorithm.
	SignatureAlgoUnknown SignatureAlgo = 0
	// SignatureAlgoECDSASHA256 is ECDSA with SHA-256 (the only supported algorithm).
	SignatureAlgoECDSASHA256 SignatureAlgo = 1
)

func (s SignatureAlgo) String() string {
	switch s {
	case SignatureAlgoECDSASHA256:
		return "ecdsa-with-SHA256"
	default:
		return "unknown"
	}
}

// PublicKeyAlgo represents the public key algorithm used in Matter certificates.
// Spec Section 6.5.8
type PublicKeyAlgo uint8

const (
	// PublicKeyAlgoUnknown is an unknown or invalid public key algorithm.
	PublicKeyAlgoUnknown PublicKeyAlgo = 0
	// PublicKeyAlgoEC is Elliptic Curve public key (the only supported algorithm).
	PublicKeyAlgoEC PublicKeyAlgo = 1
)

func (p PublicKeyAlgo) String() string {
	switch p {
	case PublicKeyAlgoEC:
		return "id-ecPublicKey"
	default:
		return "unknown"
	}
}

// EllipticCurveID represents the elliptic curve used in Matter certificates.
// Spec Section 6.5.9
type EllipticCurveID uint8

const (
	// EllipticCurveUnknown is an unknown or invalid elliptic curve.
	EllipticCurveUnknown EllipticCurveID = 0
	// EllipticCurvePrime256v1 is the NIST P-256 curve (the only supported curve).
	EllipticCurvePrime256v1 EllipticCurveID = 1
)

func (e EllipticCurveID) String() string {
	switch e {
	case EllipticCurvePrime256v1:
		return "prime256v1"
	default:
		return "unknown"
	}
}

// KeyUsage represents the key usage extension flags.
// Spec Section 6.5.11.2
type KeyUsage uint16

const (
	KeyUsageDigitalSignature KeyUsage = 0x0001
	KeyUsageNonRepudiation   KeyUsage = 0x0002
	KeyUsageKeyEncipherment  KeyUsage = 0x0004
	KeyUsageDataEncipherment KeyUsage = 0x0008
	KeyUsageKeyAgreement     KeyUsage = 0x0010
	KeyUsageKeyCertSign      KeyUsage = 0x0020
	KeyUsageCRLSign          KeyUsage = 0x0040
	KeyUsageEncipherOnly     KeyUsage = 0x0080
	KeyUsageDecipherOnly     KeyUsage = 0x0100
)

func (k KeyUsage) String() string {
	var s string
	if k&KeyUsageDigitalSignature != 0 {
		s += "digitalSignature,"
	}
	if k&KeyUsageNonRepudiation != 0 {
		s += "nonRepudiation,"
	}
	if k&KeyUsageKeyEncipherment != 0 {
		s += "keyEncipherment,"
	}
	if k&KeyUsageDataEncipherment != 0 {
		s += "dataEncipherment,"
	}
	if k&KeyUsageKeyAgreement != 0 {
		s += "keyAgreement,"
	}
	if k&KeyUsageKeyCertSign != 0 {
		s += "keyCertSign,"
	}
	if k&KeyUsageCRLSign != 0 {
		s += "cRLSign,"
	}
	if k&KeyUsageEncipherOnly != 0 {
		s += "encipherOnly,"
	}
	if k&KeyUsageDecipherOnly != 0 {
		s += "decipherOnly,"
	}
	if len(s) > 0 {
		s = s[:len(s)-1] // Remove trailing comma
	}
	return s
}

// HasFlag returns true if the given flag is set.
func (k KeyUsage) HasFlag(flag KeyUsage) bool {
	return k&flag != 0
}

// KeyPurposeID represents extended key usage purpose identifiers.
// Spec Section 6.5.11.3
type KeyPurposeID uint8

const (
	KeyPurposeUnknown         KeyPurposeID = 0
	KeyPurposeServerAuth      KeyPurposeID = 1
	KeyPurposeClientAuth      KeyPurposeID = 2
	KeyPurposeCodeSigning     KeyPurposeID = 3
	KeyPurposeEmailProtection KeyPurposeID = 4
	KeyPurposeTimeStamping    KeyPurposeID = 5
	KeyPurposeOCSPSigning     KeyPurposeID = 6
)

func (k KeyPurposeID) String() string {
	switch k {
	case KeyPurposeServerAuth:
		return "serverAuth"
	case KeyPurposeClientAuth:
		return "clientAuth"
	case KeyPurposeCodeSigning:
		return "codeSigning"
	case KeyPurposeEmailProtection:
		return "emailProtection"
	case KeyPurposeTimeStamping:
		return "timeStamping"
	case KeyPurposeOCSPSigning:
		return "OCSPSigning"
	default:
		return "unknown"
	}
}

// CertificateType represents the type of Matter certificate.
type CertificateType int

const (
	CertTypeUnknown CertificateType = iota
	CertTypeRCAC                    // Root CA Certificate
	CertTypeICAC                    // Intermediate CA Certificate
	CertTypeNOC                     // Node Operational Certificate
	CertTypeVVSC                    // Vendor Verification Signer Certificate
	CertTypeFirmwareSigning         // Firmware Signing Certificate
)

func (c CertificateType) String() string {
	switch c {
	case CertTypeRCAC:
		return "RCAC"
	case CertTypeICAC:
		return "ICAC"
	case CertTypeNOC:
		return "NOC"
	case CertTypeVVSC:
		return "VVSC"
	case CertTypeFirmwareSigning:
		return "FirmwareSigning"
	default:
		return "Unknown"
	}
}
