# fabric

Package `fabric` manages the Fabric Table for Matter nodes.

It implements the storage, retrieval, and lifecycle management of fabric information as described in Spec Section 11.18 (Operational Credentials Cluster).

## Architecture

The **Fabric Table** is the central repository for all security domains (Fabrics) a node is a member of.

*   **Fabric Index (1-254)**: A local handle used to reference a fabric throughout the stack (in ACLs, Sessions, etc.).
*   **Fabric Info**: Contains the Root CA public key, Node Operational Certificate (NOC), ICAC, and the Compressed Fabric ID.

```
  Node
    └── FabricTable
         ├── Fabric 1 [Index: 1, Label: "Home"]
         ├── Fabric 2 [Index: 2, Label: "Office"]
         └── ...
```

## Key Constraints

1.  **Unique Fabric Index**: Each fabric has a unique local 8-bit index.
2.  **Unique Identity**: A fabric is uniquely identified by the pair (Root CA Public Key, Fabric ID).
3.  **Capacity**: The table has a fixed maximum capacity (default 5, max 254).

## Usage

### Initialize Manager

```go
import "github.com/backkem/matter/pkg/fabric"

// Create table with default configuration
tbl := fabric.NewTable(fabric.DefaultTableConfig())
```

### Add a Fabric

```go
info := &fabric.FabricInfo{
    FabricIndex:   1,
    FabricID:      0x1234,
    NodeID:        0x5678,
    RootPublicKey: rootPubKeyBytes,
    Label:         "Living Room",
}

if err := tbl.Add(info); err != nil {
    // Handle table full or conflict
}
```

### Querying

```go
// Get by Index
if info, ok := tbl.Get(1); ok {
    fmt.Printf("Fabric %d: %s\n", info.FabricIndex, info.Label)
}

// Iterate all fabrics
tbl.ForEach(func(f *fabric.FabricInfo) error {
    fmt.Printf("Index: %d, NodeID: %x\n", f.FabricIndex, f.NodeID)
    return nil
})
```

```