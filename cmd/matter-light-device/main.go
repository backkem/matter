// matter-light-device is a Matter On/Off Light device example.
//
// This binary demonstrates a simple Matter-compliant light that can be
// commissioned and controlled using any Matter controller (e.g., chip-tool).
//
// Usage:
//
//	matter-light-device [options]
//
// Options:
//
//	-port          UDP/TCP port (default: 5540)
//	-discriminator 12-bit discriminator (default: 3840)
//	-passcode      Setup passcode (default: 20202021)
//	-storage       Path for persistent storage (default: in-memory)
//	-name          Device name (default: "Matter Light")
//	-vendor        Vendor ID (default: 0xFFF1)
//	-product       Product ID (default: 0x8001)
//
// Example:
//
//	matter-light-device -port 5540 -discriminator 1234 -passcode 20202021
package main

import (
	"log"

	"github.com/backkem/matter/examples/common"
	"github.com/backkem/matter/examples/light"
)

func main() {
	// Parse command-line flags
	opts := common.ParseFlags()

	// Create the light device
	device, err := light.NewDevice(opts)
	if err != nil {
		log.Fatalf("Failed to create light device: %v", err)
	}

	// Run the device (blocks until interrupted)
	if err := common.RunDevice(device.Node); err != nil {
		log.Fatalf("Device error: %v", err)
	}
}
