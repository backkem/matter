package credentials

import (
	"bytes"
	"fmt"
	"time"

	"github.com/backkem/matter/pkg/tlv"
)

// Certificate size limits from spec Section 6.1.3.
const (
	// MaxDERCertSize is the maximum X.509 DER certificate size (600 bytes).
	MaxDERCertSize = 600
	// MaxTLVCertSize is the maximum Matter TLV certificate size (400 bytes).
	MaxTLVCertSize = 400
	// MaxSerialNumSize is the maximum serial number size (20 bytes).
	MaxSerialNumSize = 20
	// PublicKeySize is the uncompressed P-256 public key size (65 bytes).
	PublicKeySize = 65
	// SignatureSize is the raw ECDSA signature size (64 bytes = r || s).
	SignatureSize = 64
)

// MatterEpochStart is the Matter epoch start time (2000-01-01 00:00:00 UTC).
var MatterEpochStart = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// Certificate represents a Matter certificate in TLV format.
// Spec Section 6.5.2
type Certificate struct {
	SerialNum   []byte            // [1] Serial number (1-20 bytes)
	SigAlgo     SignatureAlgo     // [2] Signature algorithm
	Issuer      DistinguishedName // [3] Issuer DN
	NotBefore   uint32            // [4] Not before (epoch-s)
	NotAfter    uint32            // [5] Not after (epoch-s, 0 = no expiration)
	Subject     DistinguishedName // [6] Subject DN
	PubKeyAlgo  PublicKeyAlgo     // [7] Public key algorithm
	ECCurveID   EllipticCurveID   // [8] Elliptic curve ID
	ECPubKey    []byte            // [9] EC public key (65 bytes uncompressed)
	Extensions  Extensions        // [10] Extensions
	Signature   []byte            // [11] Signature (64 bytes = r || s)
}

// Type determines the certificate type based on the subject DN.
func (c *Certificate) Type() CertificateType {
	subject := c.Subject

	// Check for Matter-specific attributes in order of precedence
	if subject.HasAttribute(TagDNMatterNodeID) {
		return CertTypeNOC
	}
	if subject.HasAttribute(TagDNMatterICACID) {
		return CertTypeICAC
	}
	if subject.HasAttribute(TagDNMatterRCACID) {
		return CertTypeRCAC
	}
	if subject.HasAttribute(TagDNMatterVVSID) {
		return CertTypeVVSC
	}
	if subject.HasAttribute(TagDNMatterFirmwareSigningID) {
		return CertTypeFirmwareSigning
	}

	return CertTypeUnknown
}

// NotBeforeTime returns the NotBefore time as a Go time.Time.
func (c *Certificate) NotBeforeTime() time.Time {
	return MatterEpochStart.Add(time.Duration(c.NotBefore) * time.Second)
}

// NotAfterTime returns the NotAfter time as a Go time.Time.
// Returns a zero time if NotAfter is 0 (no well-defined expiration).
func (c *Certificate) NotAfterTime() time.Time {
	if c.NotAfter == 0 {
		return time.Time{}
	}
	return MatterEpochStart.Add(time.Duration(c.NotAfter) * time.Second)
}

// TimeToMatterEpoch converts a Go time.Time to Matter epoch seconds.
func TimeToMatterEpoch(t time.Time) uint32 {
	if t.IsZero() || t.Before(MatterEpochStart) {
		return 0
	}
	return uint32(t.Sub(MatterEpochStart).Seconds())
}

// EncodeTLV encodes the certificate to TLV bytes.
func (c *Certificate) EncodeTLV() ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := c.WriteTLV(w); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// WriteTLV writes the certificate to a TLV writer.
func (c *Certificate) WriteTLV(w *tlv.Writer) error {
	// Start the top-level structure (anonymous tag)
	if err := w.StartStructure(tlv.Anonymous()); err != nil {
		return err
	}

	// [1] serial-num
	if err := w.PutBytes(tlv.ContextTag(TagSerialNum), c.SerialNum); err != nil {
		return err
	}

	// [2] sig-algo
	if err := w.PutUint(tlv.ContextTag(TagSigAlgo), uint64(c.SigAlgo)); err != nil {
		return err
	}

	// [3] issuer
	if err := c.Issuer.EncodeTLV(w, tlv.ContextTag(TagIssuer)); err != nil {
		return err
	}

	// [4] not-before
	if err := w.PutUintWithWidth(tlv.ContextTag(TagNotBefore), uint64(c.NotBefore), 4); err != nil {
		return err
	}

	// [5] not-after
	if err := w.PutUintWithWidth(tlv.ContextTag(TagNotAfter), uint64(c.NotAfter), 4); err != nil {
		return err
	}

	// [6] subject
	if err := c.Subject.EncodeTLV(w, tlv.ContextTag(TagSubject)); err != nil {
		return err
	}

	// [7] pub-key-algo
	if err := w.PutUint(tlv.ContextTag(TagPubKeyAlgo), uint64(c.PubKeyAlgo)); err != nil {
		return err
	}

	// [8] ec-curve-id
	if err := w.PutUint(tlv.ContextTag(TagECCurveID), uint64(c.ECCurveID)); err != nil {
		return err
	}

	// [9] ec-pub-key
	if err := w.PutBytes(tlv.ContextTag(TagECPubKey), c.ECPubKey); err != nil {
		return err
	}

	// [10] extensions
	if err := c.Extensions.EncodeTLV(w); err != nil {
		return err
	}

	// [11] signature
	if err := w.PutBytes(tlv.ContextTag(TagSignature), c.Signature); err != nil {
		return err
	}

	// End the structure
	return w.EndContainer()
}

// DecodeTLV decodes a certificate from TLV bytes.
func DecodeTLV(data []byte) (*Certificate, error) {
	r := tlv.NewReader(bytes.NewReader(data))

	if err := r.Next(); err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	return ReadTLV(r)
}

// ReadTLV reads a certificate from a TLV reader.
// The reader must be positioned at the structure element.
func ReadTLV(r *tlv.Reader) (*Certificate, error) {
	if r.Type() != tlv.ElementTypeStruct {
		return nil, fmt.Errorf("expected structure, got %v", r.Type())
	}

	if err := r.EnterContainer(); err != nil {
		return nil, err
	}

	cert := &Certificate{}

	for {
		if err := r.Next(); err != nil {
			return nil, err
		}
		if r.IsEndOfContainer() {
			break
		}

		tag := r.Tag()
		if !tag.IsContext() {
			// Skip unknown tags
			if err := r.Skip(); err != nil {
				return nil, err
			}
			continue
		}

		var err error
		switch uint8(tag.TagNumber()) {
		case TagSerialNum:
			cert.SerialNum, err = r.Bytes()
			if err != nil {
				return nil, fmt.Errorf("failed to read serial-num: %w", err)
			}

		case TagSigAlgo:
			u, err := r.Uint()
			if err != nil {
				return nil, fmt.Errorf("failed to read sig-algo: %w", err)
			}
			cert.SigAlgo = SignatureAlgo(u)

		case TagIssuer:
			cert.Issuer, err = DecodeDistinguishedName(r)
			if err != nil {
				return nil, fmt.Errorf("failed to read issuer: %w", err)
			}

		case TagNotBefore:
			u, err := r.Uint()
			if err != nil {
				return nil, fmt.Errorf("failed to read not-before: %w", err)
			}
			cert.NotBefore = uint32(u)

		case TagNotAfter:
			u, err := r.Uint()
			if err != nil {
				return nil, fmt.Errorf("failed to read not-after: %w", err)
			}
			cert.NotAfter = uint32(u)

		case TagSubject:
			cert.Subject, err = DecodeDistinguishedName(r)
			if err != nil {
				return nil, fmt.Errorf("failed to read subject: %w", err)
			}

		case TagPubKeyAlgo:
			u, err := r.Uint()
			if err != nil {
				return nil, fmt.Errorf("failed to read pub-key-algo: %w", err)
			}
			cert.PubKeyAlgo = PublicKeyAlgo(u)

		case TagECCurveID:
			u, err := r.Uint()
			if err != nil {
				return nil, fmt.Errorf("failed to read ec-curve-id: %w", err)
			}
			cert.ECCurveID = EllipticCurveID(u)

		case TagECPubKey:
			cert.ECPubKey, err = r.Bytes()
			if err != nil {
				return nil, fmt.Errorf("failed to read ec-pub-key: %w", err)
			}

		case TagExtensions:
			cert.Extensions, err = DecodeExtensions(r)
			if err != nil {
				return nil, fmt.Errorf("failed to read extensions: %w", err)
			}

		case TagSignature:
			cert.Signature, err = r.Bytes()
			if err != nil {
				return nil, fmt.Errorf("failed to read signature: %w", err)
			}

		default:
			// Unknown tag, skip
			if err := r.Skip(); err != nil {
				return nil, err
			}
		}
	}

	return cert, nil
}

// NodeID returns the node ID from the subject, or 0 if not a NOC.
func (c *Certificate) NodeID() uint64 {
	return c.Subject.GetNodeID()
}

// FabricID returns the fabric ID from the subject, or 0 if not present.
func (c *Certificate) FabricID() uint64 {
	return c.Subject.GetFabricID()
}

// RCACID returns the RCAC ID from the subject, or 0 if not an RCAC.
func (c *Certificate) RCACID() uint64 {
	return c.Subject.GetRCACID()
}

// ICACID returns the ICAC ID from the subject, or 0 if not an ICAC.
func (c *Certificate) ICACID() uint64 {
	return c.Subject.GetICACID()
}

// NOCCATs returns the CASE Authenticated Tags from the subject.
func (c *Certificate) NOCCATs() []uint32 {
	return c.Subject.GetNOCCATs()
}

// IsCA returns true if the certificate is a CA certificate.
func (c *Certificate) IsCA() bool {
	if c.Extensions.BasicConstraints == nil {
		return false
	}
	return c.Extensions.BasicConstraints.IsCA
}

// SubjectKeyID returns the subject key identifier, or nil if not present.
func (c *Certificate) SubjectKeyID() []byte {
	if c.Extensions.SubjectKeyID == nil {
		return nil
	}
	return c.Extensions.SubjectKeyID.KeyID[:]
}

// AuthorityKeyID returns the authority key identifier, or nil if not present.
func (c *Certificate) AuthorityKeyID() []byte {
	if c.Extensions.AuthorityKeyID == nil {
		return nil
	}
	return c.Extensions.AuthorityKeyID.KeyID[:]
}
