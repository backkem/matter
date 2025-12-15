# commissioning

Commissioner for Matter device commissioning (Spec Section 5.5).

## Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                        Commissioner                                │
│                                                                    │
│  CommissionFromPayload(ctx, payload)                              │
│          │                                                         │
│          ▼                                                         │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                 Commissioning Flow                           │  │
│  │  1. Discovery (DNS-SD)                                       │  │
│  │  2. PASE Session                                             │  │
│  │  3. ArmFailSafe                                              │  │
│  │  4. Device Attestation                                       │  │
│  │  5. CSR + AddNOC                                             │  │
│  │  6. Network Config                                           │  │
│  │  7. Operational Discovery                                    │  │
│  │  8. CASE Session                                             │  │
│  │  9. CommissioningComplete                                    │  │
│  └─────────────────────────────────────────────────────────────┘  │
│          │                                                         │
└──────────┼─────────────────────────────────────────────────────────┘
           │
┌──────────┼──────────────────────────────────────────────────────────┐
▼          ▼                   ▼               ▼                      ▼
pkg/discovery         pkg/securechannel    pkg/im           pkg/clusters
(Resolver)            (PASE/CASE)          (Client)         (Commands)
```

## Usage

### Parse Setup Payload

```go
// From QR code
payload, err := payload.ParseQRCode("MT:Y.K90...")

// From manual code
payload, err := payload.ParseManualCode("34970112332")
```

### Commission Device

```go
c := commissioning.NewCommissioner(commissioning.CommissionerConfig{
    Resolver:       resolver,
    SecureChannel:  scMgr,
    SessionManager: sessMgr,
    ExchangeManager: exchMgr,
    FabricInfo:     fabricInfo,
    AttestationVerifier: commissioning.NewAcceptAllVerifier(),
})

err := c.CommissionFromQRCode(ctx, "MT:Y.K90...")
// or
err := c.CommissionFromPayload(ctx, payload)
```

### Callbacks

```go
c := commissioning.NewCommissioner(commissioning.CommissionerConfig{
    // ... other config ...
    Callbacks: commissioning.CommissionerCallbacks{
        OnProgress: func(percent int, msg string) {
            fmt.Printf("%d%%: %s\n", percent, msg)
        },
        OnDeviceAttestationResult: func(result *AttestationResult) bool {
            return result.Verified // Accept verified devices
        },
        OnCommissioningComplete: func(nodeID fabric.NodeID) {
            fmt.Printf("Commissioned node: %x\n", nodeID)
        },
    },
})
```

## Pluggable Attestation

Device attestation is designed as a pluggable interface:

```go
type AttestationVerifier interface {
    Verify(ctx context.Context, info *AttestationInfo) (*AttestationResult, error)
}
```

Built-in verifiers:
- `AcceptAllVerifier`: Accepts all devices (testing only)

Future verifiers:
- `DCLVerifier`: Validates against Distributed Compliance Ledger

See `docs/pkgs/attestation.md` for design rationale.

## Commissioning States

| State | Description |
|-------|-------------|
| Idle | No commissioning in progress |
| Discovering | Searching for device via DNS-SD |
| PASE | Establishing PASE session |
| ArmingFailSafe | Arming fail-safe timer |
| DeviceAttestation | Verifying device attestation |
| CSRRequest | Requesting CSR and adding NOC |
| NetworkConfig | Configuring operational network |
| OperationalDiscovery | Finding device on operational network |
| CASE | Establishing CASE session |
| Complete | Commissioning succeeded |
| Failed | Commissioning failed |

## Subpackages

- `payload/`: Setup payload parsing (QR codes, manual codes)
