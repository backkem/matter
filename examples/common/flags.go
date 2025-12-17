// Package common provides shared utilities for Matter device examples.
package common

import (
	"flag"
	"fmt"
	"os"
)

// Options holds standard CLI flags for Matter device examples.
type Options struct {
	// Port is the UDP/TCP port for Matter communication.
	Port int

	// Discriminator is the 12-bit discriminator for device pairing.
	Discriminator uint16

	// Passcode is the setup passcode (20000001-99999998).
	Passcode uint32

	// StoragePath is the path for persistent storage.
	// If empty, in-memory storage is used.
	StoragePath string

	// DeviceName is the human-readable device name.
	DeviceName string

	// VendorID is the vendor ID (default: 0xFFF1 test vendor).
	VendorID uint16

	// ProductID is the product ID.
	ProductID uint16
}

// DefaultOptions returns Options with sensible defaults for testing.
func DefaultOptions() Options {
	return Options{
		Port:          5540,
		Discriminator: 3840,
		Passcode:      20202021,
		DeviceName:    "Matter Device",
		VendorID:      0xFFF1, // Test Vendor 1
		ProductID:     0x8001, // Test Product
	}
}

// ParseFlags parses standard CLI flags and returns Options.
// Flags are standardized across all examples:
//
//	-port          UDP/TCP port (default: 5540)
//	-discriminator 12-bit discriminator (default: 3840)
//	-passcode      Setup passcode (default: 20202021)
//	-storage       Path for persistent storage (default: in-memory)
//	-name          Device name (default: "Matter Device")
//	-vendor        Vendor ID (default: 0xFFF1)
//	-product       Product ID (default: 0x8001)
func ParseFlags() Options {
	defaults := DefaultOptions()
	o := Options{}

	flag.IntVar(&o.Port, "port", defaults.Port, "UDP/TCP port")
	flag.Func("discriminator", fmt.Sprintf("12-bit discriminator (default: %d)", defaults.Discriminator), func(s string) error {
		var v uint16
		_, err := fmt.Sscanf(s, "%d", &v)
		if err != nil {
			return err
		}
		if v > 4095 {
			return fmt.Errorf("discriminator must be 0-4095, got %d", v)
		}
		o.Discriminator = v
		return nil
	})
	flag.Func("passcode", fmt.Sprintf("Setup passcode (default: %d)", defaults.Passcode), func(s string) error {
		var v uint32
		_, err := fmt.Sscanf(s, "%d", &v)
		if err != nil {
			return err
		}
		o.Passcode = v
		return nil
	})
	flag.StringVar(&o.StoragePath, "storage", "", "Path for persistent storage (empty = in-memory)")
	flag.StringVar(&o.DeviceName, "name", defaults.DeviceName, "Device name")
	flag.Func("vendor", fmt.Sprintf("Vendor ID (default: 0x%04X)", defaults.VendorID), func(s string) error {
		var v uint16
		_, err := fmt.Sscanf(s, "%d", &v)
		if err != nil {
			// Try hex format
			_, err = fmt.Sscanf(s, "0x%x", &v)
			if err != nil {
				return err
			}
		}
		o.VendorID = v
		return nil
	})
	flag.Func("product", fmt.Sprintf("Product ID (default: 0x%04X)", defaults.ProductID), func(s string) error {
		var v uint16
		_, err := fmt.Sscanf(s, "%d", &v)
		if err != nil {
			// Try hex format
			_, err = fmt.Sscanf(s, "0x%x", &v)
			if err != nil {
				return err
			}
		}
		o.ProductID = v
		return nil
	})

	flag.Parse()

	// Apply defaults for unset values
	if o.Discriminator == 0 && !isFlagSet("discriminator") {
		o.Discriminator = defaults.Discriminator
	}
	if o.Passcode == 0 && !isFlagSet("passcode") {
		o.Passcode = defaults.Passcode
	}
	if o.VendorID == 0 && !isFlagSet("vendor") {
		o.VendorID = defaults.VendorID
	}
	if o.ProductID == 0 && !isFlagSet("product") {
		o.ProductID = defaults.ProductID
	}

	return o
}

// isFlagSet checks if a flag was explicitly set.
func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// PrintUsage prints usage information to stderr.
func PrintUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\nOptions:\n")
	flag.PrintDefaults()
}
