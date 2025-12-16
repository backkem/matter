# clusters

Matter cluster implementations (Spec Section 7).

## Architecture

```
                        ┌─────────────────────────────────────┐
                        │          datamodel.Cluster          │
                        │                                     │
                        │   ReadAttribute()                   │
                        │   WriteAttribute()                  │
                        │   InvokeCommand()                   │
                        └─────────────────────────────────────┘
                                         ▲
                                         │ implements
                        ┌────────────────┼────────────────┐
                        │                │                │
              ┌─────────┴───┐    ┌───────┴─────┐   ┌──────┴──────┐
              │ ClusterBase │    │ EventSource │   │   Storage   │
              │  (embed)    │    │   (mixin)   │   │ (interface) │
              └─────────────┘    └─────────────┘   └─────────────┘
                        │                │                │
                        └────────────────┼────────────────┘
                                         │ compose
                        ┌────────────────┴────────────────┐
                        │       Concrete Cluster          │
                        │  (descriptor, basic, onoff...)  │
                        └─────────────────────────────────┘
```

## Subpackages

| Package | Cluster ID | Name | Endpoint |
|---------|------------|------|----------|
| `descriptor` | 0x001D | Descriptor | All |
| `basic` | 0x0028 | Basic Information | 0 (root) |
| `generalcommissioning` | 0x0030 | General Commissioning | 0 (root) |
| `onoff` | 0x0006 | On/Off | Application |

## Usage

### Implement a Cluster

```go
type MyCluster struct {
    *datamodel.ClusterBase
    *datamodel.EventSource  // optional: for event-emitting clusters
    config Config
}

func New(cfg Config) *MyCluster {
    c := &MyCluster{
        ClusterBase: datamodel.NewClusterBase(ClusterID, cfg.EndpointID, Revision),
        config:      cfg,
    }
    c.EventSource = datamodel.NewEventSource(c)  // if using events
    return c
}
```

### Register with InteractionModel

```go
// Create clusters
desc := descriptor.New(descriptor.Config{EndpointID: 0})
basic := basic.New(basic.Config{...})

// Register with data model
dm.RegisterCluster(desc)
dm.RegisterCluster(basic)
```

### Handle Timed Commands

```go
func (c *Cluster) InvokeCommand(ctx context.Context, req datamodel.InvokeRequest, r *tlv.Reader) ([]byte, error) {
    switch req.Path.Command {
    case CmdTimedAction:
        if err := clusters.RequireTimed(req); err != nil {
            return nil, err
        }
        // Handle command...
    }
}
```

## Helpers

- `RequireTimed(req)` - Enforce timed command requirement
- `EncodeStatusResponse(status)` - Build IM status response
