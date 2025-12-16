# matter

Top-level facade for building Matter devices (Spec Chapters 2, 5, 7, 8).

## Architecture

```
                    ┌─────────────────────────────────────────────────┐
                    │                   Node                          │
                    │                                                 │
                    │   ┌─────────────────────────────────────────┐   │
                    │   │            Data Model                   │   │
                    │   │   Endpoint 0 (Root)                     │   │
                    │   │     ├─ Descriptor                       │   │
                    │   │     ├─ Basic Information                │   │
                    │   │     └─ General Commissioning            │   │
                    │   │   Endpoint 1..N (Application)           │   │
                    │   │     └─ Clusters (OnOff, etc.)           │   │
                    │   └─────────────────────────────────────────┘   │
                    │                      │                          │
                    │   ┌──────────────────┼──────────────────┐       │
                    │   ▼                  ▼                  ▼       │
                    │ IM Engine     SecureChannel       Discovery     │
                    │   │           (PASE/CASE)         (mDNS)        │
                    │   └──────────────┬──────────────────┘           │
                    │                  ▼                              │
                    │           Exchange Manager                      │
                    │                  │                              │
                    │                  ▼                              │
                    │           Transport (UDP/TCP)                   │
                    └─────────────────────────────────────────────────┘
```

## Usage

### Create Device

```go
node, _ := matter.NewNode(matter.NodeConfig{
    VendorID:      0xFFF1,
    ProductID:     0x8001,
    Discriminator: 3840,
    Passcode:      20202021,
    Storage:       matter.NewMemoryStorage(),
})

// Add application endpoint
lightEP := matter.NewEndpoint(1).
    WithDeviceType(0x0100, 1).  // On/Off Light
    AddCluster(onoff.New(onoff.Config{EndpointID: 1}))

node.AddEndpoint(lightEP)
```

### Start/Stop

```go
node.Start(ctx)
defer node.Stop()

// Get pairing info
qr := node.OnboardingPayload()      // "MT:-24J0AFN00KA0648G00"
manual := node.ManualPairingCode()  // "34970112332"
```

### Commissioning

```go
// Auto-opens on Start() for uncommissioned devices
// Or manually:
node.OpenCommissioningWindow(3 * time.Minute)
node.CloseCommissioningWindow()

// Check status
node.IsCommissioned()
node.Fabrics()
```

## State Machine

```
    NewNode()           Start()              Commissioned
        │                  │                      │
        ▼                  ▼                      ▼
  Uninitialized ──▶ Initialized ──▶ Uncommissioned ──▶ Commissioned
                                          │                  │
                                          ▼                  │
                                   CommissioningOpen ────────┘
                                          │
                                     Stop()
                                          │
                                          ▼
                                       Stopped
```

## Testing

```go
// In-memory storage
storage := matter.NewMemoryStorage()

// Virtual transport (no network I/O)
factory1, factory2 := matter.NewPipeTransportPair()
config.TransportFactory = factory1

// Pre-configured test config
config := matter.TestNodeConfig()
```
