package common

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/matter"
)

// CreateNode creates a Matter node from Options.
// This is the common bootstrap for all device examples.
func CreateNode(opts Options) (*matter.Node, error) {
	// Create storage
	var storage matter.Storage
	if opts.StoragePath != "" {
		// File-based storage (to be implemented)
		// For now, fall back to memory storage
		storage = matter.NewMemoryStorage()
	} else {
		storage = matter.NewMemoryStorage()
	}

	// Create node configuration
	config := matter.NodeConfig{
		VendorID:      fabric.VendorID(opts.VendorID),
		ProductID:     opts.ProductID,
		DeviceName:    opts.DeviceName,
		Discriminator: opts.Discriminator,
		Passcode:      opts.Passcode,
		Port:          opts.Port,
		Storage:       storage,

		// Add callbacks for visibility
		OnStateChanged: func(state matter.NodeState) {
			log.Printf("State changed: %s", state)
		},
	}

	// Create node
	node, err := matter.NewNode(config)
	if err != nil {
		return nil, fmt.Errorf("create node: %w", err)
	}

	return node, nil
}

// WaitForSignal blocks until SIGINT or SIGTERM is received.
// Use this in main() to keep the device running until interrupted.
func WaitForSignal() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("Received signal: %v", sig)
}

// RunDevice starts a Matter node and blocks until interrupted.
// This is a convenience function that combines Start, WaitForSignal, and Stop.
func RunDevice(node *matter.Node) error {
	// Create context that cancels on interrupt
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start the node
	if err := node.Start(ctx); err != nil {
		return fmt.Errorf("start node: %w", err)
	}

	// Print onboarding information
	printOnboardingInfo(node)

	// Wait for context cancellation (signal)
	<-ctx.Done()

	// Stop the node
	log.Println("Shutting down...")
	if err := node.Stop(); err != nil {
		return fmt.Errorf("stop node: %w", err)
	}

	return nil
}

// printOnboardingInfo prints commissioning information to the console.
func printOnboardingInfo(node *matter.Node) {
	info := node.GetSetupInfo()

	fmt.Println("\n========================================")
	fmt.Println("          Matter Device Ready")
	fmt.Println("========================================")
	fmt.Printf("Device Name:    %s\n", node.State())
	fmt.Printf("Port:           %d\n", info.Port)
	fmt.Printf("Discriminator:  %d\n", info.Discriminator)
	fmt.Printf("Passcode:       %d\n", info.Passcode)
	fmt.Println("----------------------------------------")
	fmt.Printf("QR Code:        %s\n", info.QRCode)
	fmt.Printf("Manual Code:    %s\n", info.ManualCode)
	fmt.Println("========================================")
}
