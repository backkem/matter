package credentials

import "errors"

// Certificate parsing and encoding errors.
var (
	// ErrInvalidCertificate indicates a malformed certificate structure.
	ErrInvalidCertificate = errors.New("invalid certificate")

	// ErrInvalidSerialNumber indicates the serial number is invalid.
	ErrInvalidSerialNumber = errors.New("serial number must be 1-20 bytes")

	// ErrInvalidSignatureAlgo indicates an unsupported signature algorithm.
	ErrInvalidSignatureAlgo = errors.New("unsupported signature algorithm")

	// ErrInvalidPublicKeyAlgo indicates an unsupported public key algorithm.
	ErrInvalidPublicKeyAlgo = errors.New("unsupported public key algorithm")

	// ErrInvalidEllipticCurve indicates an unsupported elliptic curve.
	ErrInvalidEllipticCurve = errors.New("unsupported elliptic curve")

	// ErrInvalidPublicKey indicates the public key is malformed.
	ErrInvalidPublicKey = errors.New("invalid public key")

	// ErrInvalidSignature indicates the signature is malformed.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrInvalidDN indicates a malformed Distinguished Name.
	ErrInvalidDN = errors.New("invalid distinguished name")

	// ErrInvalidExtension indicates a malformed extension.
	ErrInvalidExtension = errors.New("invalid extension")

	// ErrMissingExtension indicates a required extension is missing.
	ErrMissingExtension = errors.New("missing required extension")

	// ErrInvalidKeyUsage indicates invalid key usage flags.
	ErrInvalidKeyUsage = errors.New("invalid key usage")

	// ErrInvalidTime indicates an invalid time value.
	ErrInvalidTime = errors.New("invalid time value")

	// ErrCertificateTooLarge indicates the certificate exceeds size limits.
	ErrCertificateTooLarge = errors.New("certificate exceeds maximum size")

	// ErrUnsupportedOID indicates an unsupported OID was encountered.
	ErrUnsupportedOID = errors.New("unsupported OID")
)

// Certificate validation errors.
var (
	// ErrInvalidCertType indicates the certificate type cannot be determined.
	ErrInvalidCertType = errors.New("cannot determine certificate type")

	// ErrMissingNodeID indicates a NOC is missing the matter-node-id attribute.
	ErrMissingNodeID = errors.New("NOC must have matter-node-id")

	// ErrMissingFabricID indicates a NOC is missing the matter-fabric-id attribute.
	ErrMissingFabricID = errors.New("NOC must have matter-fabric-id")

	// ErrMissingRCACID indicates an RCAC is missing the matter-rcac-id attribute.
	ErrMissingRCACID = errors.New("RCAC must have matter-rcac-id")

	// ErrMissingICACID indicates an ICAC is missing the matter-icac-id attribute.
	ErrMissingICACID = errors.New("ICAC must have matter-icac-id")

	// ErrInvalidNodeID indicates an invalid node ID value.
	ErrInvalidNodeID = errors.New("invalid node ID")

	// ErrInvalidFabricID indicates an invalid fabric ID value.
	ErrInvalidFabricID = errors.New("fabric ID must not be 0")

	// ErrTooManyDNAttributes indicates too many DN attributes.
	ErrTooManyDNAttributes = errors.New("DN must have at most 5 attributes")

	// ErrTooManyNOCCATs indicates too many CASE Authenticated Tags.
	ErrTooManyNOCCATs = errors.New("NOC must have at most 3 matter-noc-cat attributes")

	// ErrDuplicateNOCCAT indicates duplicate CAT identifiers.
	ErrDuplicateNOCCAT = errors.New("duplicate CAT identifier")

	// ErrForbiddenAttribute indicates a DN attribute that is not allowed.
	ErrForbiddenAttribute = errors.New("forbidden DN attribute for certificate type")

	// ErrBasicConstraintsMismatch indicates wrong basic constraints for cert type.
	ErrBasicConstraintsMismatch = errors.New("basic constraints mismatch for certificate type")

	// ErrKeyUsageMismatch indicates wrong key usage for certificate type.
	ErrKeyUsageMismatch = errors.New("key usage mismatch for certificate type")

	// ErrExtKeyUsageMismatch indicates wrong extended key usage for certificate type.
	ErrExtKeyUsageMismatch = errors.New("extended key usage mismatch for certificate type")

	// ErrMissingSubjectKeyID indicates missing subject key identifier.
	ErrMissingSubjectKeyID = errors.New("missing subject key identifier extension")

	// ErrMissingAuthorityKeyID indicates missing authority key identifier.
	ErrMissingAuthorityKeyID = errors.New("missing authority key identifier extension")

	// ErrSelfSignedMismatch indicates RCAC SKID doesn't match AKID.
	ErrSelfSignedMismatch = errors.New("RCAC subject key ID must match authority key ID")

	// ErrFabricIDMismatch indicates fabric IDs don't match in certificate chain.
	ErrFabricIDMismatch = errors.New("fabric ID mismatch in certificate chain")
)

// X.509 conversion errors.
var (
	// ErrX509ParseFailed indicates X.509 parsing failed.
	ErrX509ParseFailed = errors.New("failed to parse X.509 certificate")

	// ErrX509EncodeFailed indicates X.509 encoding failed.
	ErrX509EncodeFailed = errors.New("failed to encode X.509 certificate")

	// ErrUnsupportedX509Feature indicates an unsupported X.509 feature.
	ErrUnsupportedX509Feature = errors.New("unsupported X.509 feature")

	// ErrSignatureConversionFailed indicates signature format conversion failed.
	ErrSignatureConversionFailed = errors.New("failed to convert signature format")
)
