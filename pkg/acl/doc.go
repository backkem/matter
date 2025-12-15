// Package acl implements Access Control List (ACL) enforcement for Matter.
//
// The ACL module determines whether a given subject (identified by a session's
// authentication mode and identity) has sufficient privilege to perform an
// operation on a target (identified by endpoint and cluster).
//
// The core function is Check(subject, target, privilege) which returns whether
// access is allowed, denied, or restricted.
//
// Key concepts:
//   - Privilege: View < Operate < Manage < Administer (hierarchy)
//   - AuthMode: PASE (commissioning), CASE (operational), Group
//   - Subject: NodeID, CASE Authenticated Tag (CAT), or GroupID
//   - Target: Cluster + Endpoint, with optional DeviceType matching
//
// The algorithm (Spec 6.6.6.2):
//  1. PASE sessions during commissioning get implicit Administer privilege
//  2. For each ACL entry matching fabric and auth mode:
//     - Check if entry's privilege covers the required privilege
//     - Check if any subject matches (exact or CAT version match)
//     - Check if any target matches (cluster/endpoint/device type)
//  3. First matching entry grants access; no match means denied
//
// Spec References:
//   - Section 6.6: Access Control
//   - Section 6.6.2: Model (Privileges, Subjects, Targets)
//   - Section 6.6.6: Conceptual Access Control Algorithm
//   - Section 9.10.5: Access Control Cluster Data Types
package acl
