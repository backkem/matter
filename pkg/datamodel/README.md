# datamodel

Data Model interfaces and types for Matter (Spec Chapter 7).

## Architecture

```
                    ┌──────────────────────────────────────────┐
                    │                 Node                     │
                    │                                          │
                    │   GetEndpoint(id) → Endpoint             │
                    │   GetEndpoints() → []Endpoint            │
                    │                                          │
                    │   ┌────────────────────────────────┐     │
                    │   │         Endpoint 0             │     │
                    │   │   ┌────────┐  ┌────────┐       │     │
                    │   │   │Descrip.│  │Basic   │  ...  │     │
                    │   │   │Cluster │  │Info    │       │     │
                    │   │   └────────┘  └────────┘       │     │
                    │   └────────────────────────────────┘     │
                    │   ┌────────────────────────────────┐     │
                    │   │         Endpoint 1             │     │
                    │   │   ┌────────┐  ┌────────┐       │     │
                    │   │   │ OnOff  │  │ Level  │  ...  │     │
                    │   │   │Cluster │  │Control │       │     │
                    │   │   └────────┘  └────────┘       │     │
                    │   └────────────────────────────────┘     │
                    └──────────────────────────────────────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    ▼                  ▼                  ▼
              pkg/im/message     pkg/fabric         pkg/tlv
              (ID types)         (FabricIndex)      (Encode/Decode)
```

## Usage

### Create a Node with Endpoints

```go
node := datamodel.NewNode()

// Root endpoint (0)
ep0 := datamodel.NewEndpoint(0)
ep0.AddDeviceType(datamodel.DeviceTypeEntry{DeviceTypeID: datamodel.DeviceTypeRootNode, Revision: 1})
ep0.AddCluster(myDescriptorCluster)
node.AddEndpoint(ep0)

// Application endpoint
ep1 := datamodel.NewEndpointWithParent(1, 0)
ep1.AddDeviceType(datamodel.DeviceTypeEntry{DeviceTypeID: datamodel.DeviceTypeOnOffLight, Revision: 1})
ep1.AddCluster(myOnOffCluster)
node.AddEndpoint(ep1)
```

### Implement a Cluster

```go
type MyOnOffCluster struct {
    *datamodel.ClusterBase
    onOff bool
}

func NewOnOffCluster(endpointID datamodel.EndpointID) *MyOnOffCluster {
    return &MyOnOffCluster{
        ClusterBase: datamodel.NewClusterBase(datamodel.ClusterOnOff, endpointID, 4),
    }
}

func (c *MyOnOffCluster) AttributeList() []datamodel.AttributeEntry {
    return datamodel.MergeAttributeLists([]datamodel.AttributeEntry{
        datamodel.NewReadOnlyAttribute(0, 0, datamodel.PrivilegeView), // OnOff
    })
}

func (c *MyOnOffCluster) ReadAttribute(ctx context.Context, req datamodel.ReadAttributeRequest, w *tlv.Writer) error {
    // Handle global attributes
    if handled, err := c.ReadGlobalAttribute(ctx, req.Path.Attribute, w,
        c.AttributeList(), c.AcceptedCommandList(), c.GeneratedCommandList()); handled {
        return err
    }
    // Handle cluster-specific attributes
    switch req.Path.Attribute {
    case 0: // OnOff
        return w.PutBool(tlv.Anonymous(), c.onOff)
    }
    return datamodel.ErrAttributeNotFound
}
```

### Route IM Requests

```go
// Find cluster for a path
ep := node.GetEndpoint(path.Endpoint)
if ep == nil {
    return datamodel.ErrEndpointNotFound
}
cluster := ep.GetCluster(path.Cluster)
if cluster == nil {
    return datamodel.ErrClusterNotFound
}

// Read attribute
err := cluster.ReadAttribute(ctx, req, tlvWriter)
```

## Element Hierarchy

```
Node (addressable entity)
 └── Endpoint (device type instance)
      └── Cluster (functional building block)
           ├── Attributes (data with R/W access)
           ├── Commands (client↔server actions)
           └── Events (historical records)
```

## Key Types

| Type | Description |
|------|-------------|
| `Privilege` | View, Operate, Manage, Administer |
| `AttributeQuality` | Fixed, Nullable, List, FabricScoped, Timed, etc. |
| `CommandQuality` | FabricScoped, Timed, LargeMessage |
| `AttributeEntry` | Attribute metadata (ID, privileges, qualities) |
| `CommandEntry` | Command metadata (ID, invoke privilege, qualities) |
| `ConcreteAttributePath` | Endpoint + Cluster + Attribute |

## Global Attributes (Spec 7.13)

Every cluster instance has these mandatory attributes:

| ID | Name | Type |
|----|------|------|
| 0xFFFD | ClusterRevision | uint16 |
| 0xFFFC | FeatureMap | map32 |
| 0xFFFB | AttributeList | list[attrib-id] |
| 0xFFF9 | AcceptedCommandList | list[command-id] |
| 0xFFF8 | GeneratedCommandList | list[command-id] |

`ClusterBase.ReadGlobalAttribute()` handles these automatically.
