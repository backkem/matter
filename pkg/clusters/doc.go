// Package clusters provides foundational infrastructure and implementations
// for Matter clusters.
//
// # Architecture
//
// Clusters implement the datamodel.Cluster interface and use composition
// to add optional capabilities:
//
//	type MyCluster struct {
//	    *datamodel.ClusterBase   // Core identity, global attributes
//	    *datamodel.EventSource   // Event emission (optional mixin)
//	}
//
// # Subpackages
//
// Individual cluster implementations are in subpackages:
//   - clusters/descriptor: Descriptor Cluster (0x001D)
//   - clusters/basic: Basic Information Cluster (0x0028)
//   - clusters/generalcommissioning: General Commissioning Cluster (0x0030)
//   - clusters/onoff: On/Off Cluster (0x0006)
//
// # Helpers
//
// This package provides common helpers for cluster implementations:
//   - Timed command enforcement (timed.go)
//   - Command TLV encoding/decoding (encoding.go)
//   - Status response builders
package clusters
