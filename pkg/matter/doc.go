// Package matter provides a high-level API for building Matter devices and controllers.
//
// This package is the top-level facade that ties together all the lower-level
// Matter stack components (transport, session, exchange, secure channel, interaction
// model, etc.) into an ergonomic, idiomatic Go API.
//
// # Creating a Device
//
// To create a Matter device, use NewNode with a NodeConfig:
//
//	node, err := matter.NewNode(matter.NodeConfig{
//	    VendorID:      0xFFF1,
//	    ProductID:     0x8001,
//	    DeviceName:    "Go Light",
//	    Discriminator: 3840,
//	    Passcode:      20202021,
//	    Storage:       matter.NewMemoryStorage(),
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Add application endpoints
//	lightEP := matter.NewEndpoint(1).
//	    WithDeviceType(0x0100, 1).  // On/Off Light
//	    AddCluster(onoff.NewServer())
//	node.AddEndpoint(lightEP)
//
//	// Start the node
//	if err := node.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
// # Commissioning
//
// Uncommissioned devices automatically advertise via DNS-SD. To open a
// commissioning window manually:
//
//	node.OpenCommissioningWindow(3 * time.Minute)
//	fmt.Println("QR Code:", node.OnboardingPayload())
//
// # Testing
//
// For testing, use MemoryStorage and the virtual network helpers:
//
//	// Create a pair of nodes connected via a bridge
//	device, controller, bridge, _ := matter.TestNodePair()
//	device.Start(ctx)
//	controller.Start(ctx)
//
//	// Process messages between nodes
//	bridge.Process()
//
// See the examples/ directory for complete working examples.
package matter
