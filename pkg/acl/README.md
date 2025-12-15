# acl

Access Control List enforcement (Spec Section 6.6, 9.10).

## Architecture

```
                 ┌────────────────────────────────────────────────┐
                 │                   Manager                      │
                 │                                                │
                 │  Check(subject, path, privilege) -> Result     │
                 │         │                                      │
                 │         ▼                                      │
                 │  ┌────────────────────────────────────────┐    │
                 │  │ PASE Commissioning Check (Spec 6.6.2.9)│    │
                 │  │ IsCommissioning? → Implicit Administer │    │
                 │  └────────────────────────────────────────┘    │
                 │         │ No                                   │
                 │         ▼                                      │
                 │  ┌────────────────────────────────────────┐    │
                 │  │ ACL Entry Matching (Spec 6.6.6.2)      │    │
                 │  │ For each entry:                        │    │
                 │  │   FabricIndex match?                   │    │
                 │  │   AuthMode match?                      │    │
                 │  │   Privilege grants?                    │    │
                 │  │   Subject matches?                     │    │
                 │  │   Target matches?                      │    │
                 │  └────────────────────────────────────────┘    │
                 │         │                                      │
                 │    ┌────┴────┐                                 │
                 │    ▼         ▼                                 │
                 │ Allowed   Denied                               │
                 └────────────────────────────────────────────────┘
                        │
       ┌────────────────┼────────────────┐
       ▼                ▼                ▼
  pkg/fabric      pkg/session       pkg/im
  (FabricIndex)   (SubjectDescriptor) (RequestPath)
```

## Usage

### Create Manager

```go
mgr := acl.NewManager(nil, nil) // MemoryStore, no device type resolver
```

### Add ACL Entries

```go
// Admin entry for specific node
mgr.CreateEntry(fabricIndex, acl.Entry{
    Privilege: acl.PrivilegeAdminister,
    AuthMode:  acl.AuthModeCASE,
    Subjects:  []uint64{nodeID},
})

// View for anyone on fabric (wildcard subjects)
mgr.CreateEntry(fabricIndex, acl.Entry{
    Privilege: acl.PrivilegeView,
    AuthMode:  acl.AuthModeCASE,
    Targets:   []acl.Target{acl.NewTargetCluster(0x0006)},
})
```

### Check Access

```go
subject := acl.SubjectDescriptor{
    FabricIndex: 1,
    AuthMode:    acl.AuthModeCASE,
    Subject:     nodeID,
    CATs:        acl.CATValues{cat1, cat2, 0},
}

path := acl.NewRequestPath(clusterID, endpointID, acl.RequestTypeAttributeRead)

result := mgr.Check(subject, path, acl.PrivilegeOperate)
if result == acl.ResultAllowed {
    // proceed
}
```

## Privilege Hierarchy (Spec 9.10.5.2)

| Privilege | Grants | Value |
|-----------|--------|-------|
| Administer | Administer, Manage, Operate, View, ProxyView | 5 |
| Manage | Manage, Operate, View | 4 |
| Operate | Operate, View | 3 |
| ProxyView | ProxyView, View | 2 |
| View | View | 1 |

## Subject Matching (Spec 6.6.6.2)

| Auth Mode | Subject Format | Matching |
|-----------|----------------|----------|
| CASE | Operational NodeID | Exact match |
| CASE | CAT NodeID (0xFFFFFFFD_xxxx_xxxx) | ID match + version ≥ |
| Group | Group NodeID (0xFFFFFFFF_FFFF_xxxx) | Exact match |
| PASE | PAKE NodeID (0xFFFFFFFB_0000_xxxx) | Implicit admin only |

## CAT Version Matching

Entry CAT: `0xABCD_0002` (identifier=0xABCD, version=2)

| Subject CAT | Match? | Reason |
|-------------|--------|--------|
| `0xABCD_0002` | Yes | version 2 ≥ 2 |
| `0xABCD_0008` | Yes | version 8 ≥ 2 |
| `0xABCD_0001` | No | version 1 < 2 |
| `0x1234_0008` | No | different identifier |

## Target Combinations

| Cluster | Endpoint | DeviceType | Valid? |
|---------|----------|------------|--------|
| ✓ | - | - | Yes |
| - | ✓ | - | Yes |
| - | - | ✓ | Yes |
| ✓ | ✓ | - | Yes |
| ✓ | - | ✓ | Yes |
| - | ✓ | ✓ | **No** |
| ✓ | ✓ | ✓ | **No** |
| - | - | - | **No** |

## Entry Validation Rules

- FabricIndex: 1-254 (0 invalid)
- AuthMode: CASE or Group only (PASE not stored)
- Group + Administer: **Invalid**
- Empty subjects: Wildcard (CASE/Group only)
- Empty targets: Wildcard (all resources)
