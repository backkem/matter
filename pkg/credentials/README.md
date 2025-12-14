# credentials

Package `credentials` implements Matter Certificate encoding, decoding, and validation (Spec Section 6).

It bridges the gap between Matter's TLV-encoded certificates and internal Go structures, and provides utilities for X.509 conversion.

## Key Types

*   `Certificate`: The Go representation of a Matter certificate (Spec 6.5.2).
*   `CertificateType`: Helper to identify certificate role (NOC, ICAC, RCAC).
*   `Builder`: (If applicable) Utilities for constructing certificates.

## Field Mapping (Spec 6.5.2)

The `Certificate` struct fields map directly to the Spec:

| Struct Field | TLV Tag | Description |
|--------------|---------|-------------|
| `SerialNum`  | 1       | Certificate serial number |
| `SigAlgo`    | 2       | Signature algorithm (ECDSA-With-SHA256) |
| `Issuer`     | 3       | Issuer Distinguished Name (DN) |
| `NotBefore`  | 4       | Validity start (Matter Epoch Seconds) |
| `NotAfter`   | 5       | Validity end (Matter Epoch Seconds) |
| `Subject`    | 6       | Subject Distinguished Name (DN) |
| `PubKeyAlgo` | 7       | Public key algorithm (EC) |
| `ECCurveID`  | 8       | Elliptic curve identifier (prime256v1) |
| `ECPubKey`   | 9       | Public key bytes |
| `Extensions` | 10      | Basic Constraints, Key Usage, etc. |
| `Signature`  | 11      | The signature over the structure |

## Usage

### Decode a TLV Certificate

```go
import "github.com/backkem/matter/pkg/credentials"

// Decode raw TLV bytes (e.g., from an Operational Credentials command)
cert, err := credentials.DecodeTLV(tlvBytes)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Subject Node ID: %x\n", cert.NodeID())
fmt.Printf("Fabric ID: %x\n", cert.FabricID())
```

### Encode a Certificate

```go
tlvBytes, err := cert.EncodeTLV()
```