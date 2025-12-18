package matter

import (
	"fmt"
	"testing"
	"time"

	"github.com/backkem/matter/pkg/clusters/onoff"
	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/transport"
)

func TestNewNode(t *testing.T) {
	storage := NewMemoryStorage()

	node, err := NewNode(NodeConfig{
		VendorID:              0xFFF1,
		ProductID:             0x8001,
		DeviceName:            "Test Device",
		SerialNumber:          "TEST-001",
		Discriminator:         3840,
		Passcode:              20202021,
		HardwareVersion:       1,
		SoftwareVersion:       1,
		SoftwareVersionString: "1.0.0",
		Storage:               storage,
	})
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}

	if node.State() != NodeStateInitialized {
		t.Errorf("expected state %v, got %v", NodeStateInitialized, node.State())
	}
}

func TestNodeAddEndpoint(t *testing.T) {
	storage := NewMemoryStorage()

	node, err := NewNode(NodeConfig{
		VendorID:              0xFFF1,
		ProductID:             0x8001,
		DeviceName:            "Test Device",
		SerialNumber:          "TEST-001",
		Discriminator:         3840,
		Passcode:              20202021,
		HardwareVersion:       1,
		SoftwareVersion:       1,
		SoftwareVersionString: "1.0.0",
		Storage:               storage,
	})
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}

	// Create an on/off light endpoint
	lightEP := NewEndpoint(1).
		WithDeviceType(0x0100, 1) // On/Off Light

	// Add on/off cluster
	onOffCluster := onoff.New(onoff.Config{
		EndpointID: 1,
	})
	lightEP.AddCluster(onOffCluster)

	err = node.AddEndpoint(lightEP)
	if err != nil {
		t.Fatalf("AddEndpoint failed: %v", err)
	}

	// Verify endpoint was added
	ep := node.GetEndpoint(1)
	if ep == nil {
		t.Fatal("GetEndpoint returned nil")
	}

	if ep.ID() != 1 {
		t.Errorf("expected endpoint ID 1, got %d", ep.ID())
	}
}

func TestNodeRootEndpointReserved(t *testing.T) {
	storage := NewMemoryStorage()

	node, err := NewNode(NodeConfig{
		VendorID:              0xFFF1,
		ProductID:             0x8001,
		DeviceName:            "Test Device",
		SerialNumber:          "TEST-001",
		Discriminator:         3840,
		Passcode:              20202021,
		HardwareVersion:       1,
		SoftwareVersion:       1,
		SoftwareVersionString: "1.0.0",
		Storage:               storage,
	})
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}

	// Try to add endpoint 0 (root) - should fail
	rootEP := NewEndpoint(0)
	err = node.AddEndpoint(rootEP)
	if err != ErrRootEndpointReserved {
		t.Errorf("expected ErrRootEndpointReserved, got %v", err)
	}
}

func TestNodeDuplicateEndpoint(t *testing.T) {
	storage := NewMemoryStorage()

	node, err := NewNode(NodeConfig{
		VendorID:              0xFFF1,
		ProductID:             0x8001,
		DeviceName:            "Test Device",
		SerialNumber:          "TEST-001",
		Discriminator:         3840,
		Passcode:              20202021,
		HardwareVersion:       1,
		SoftwareVersion:       1,
		SoftwareVersionString: "1.0.0",
		Storage:               storage,
	})
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}

	// Add endpoint 1
	ep1 := NewEndpoint(1)
	err = node.AddEndpoint(ep1)
	if err != nil {
		t.Fatalf("AddEndpoint failed: %v", err)
	}

	// Try to add another endpoint 1 - should fail
	ep1Dup := NewEndpoint(1)
	err = node.AddEndpoint(ep1Dup)
	if err != ErrEndpointExists {
		t.Errorf("expected ErrEndpointExists, got %v", err)
	}
}

func TestOnboardingPayload(t *testing.T) {
	storage := NewMemoryStorage()

	node, err := NewNode(NodeConfig{
		VendorID:              0xFFF1,
		ProductID:             0x8001,
		DeviceName:            "Test Device",
		SerialNumber:          "TEST-001",
		Discriminator:         3840,
		Passcode:              20202021,
		HardwareVersion:       1,
		SoftwareVersion:       1,
		SoftwareVersionString: "1.0.0",
		Storage:               storage,
	})
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}

	// Get QR code payload
	payload := node.OnboardingPayload()
	if payload == "" {
		t.Error("OnboardingPayload returned empty string")
	}

	// Should start with MT: prefix
	if len(payload) < 3 || payload[:3] != "MT:" {
		t.Errorf("expected QR payload to start with 'MT:', got %q", payload)
	}

	t.Logf("QR Payload: %s", payload)
}

func TestManualPairingCode(t *testing.T) {
	storage := NewMemoryStorage()

	node, err := NewNode(NodeConfig{
		VendorID:              0xFFF1,
		ProductID:             0x8001,
		DeviceName:            "Test Device",
		SerialNumber:          "TEST-001",
		Discriminator:         3840,
		Passcode:              20202021,
		HardwareVersion:       1,
		SoftwareVersion:       1,
		SoftwareVersionString: "1.0.0",
		Storage:               storage,
	})
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}

	// Get manual pairing code
	code := node.ManualPairingCode()
	if code == "" {
		t.Error("ManualPairingCode returned empty string")
	}

	// Manual code should be 11 or 21 digits
	if len(code) != 11 && len(code) != 21 {
		t.Errorf("expected manual code length 11 or 21, got %d", len(code))
	}

	t.Logf("Manual Code: %s", code)
}

func TestGetSetupInfo(t *testing.T) {
	storage := NewMemoryStorage()

	node, err := NewNode(NodeConfig{
		VendorID:              0xFFF1,
		ProductID:             0x8001,
		DeviceName:            "Test Device",
		SerialNumber:          "TEST-001",
		Discriminator:         3840,
		Passcode:              20202021,
		HardwareVersion:       1,
		SoftwareVersion:       1,
		SoftwareVersionString: "1.0.0",
		Port:                  5540,
		Storage:               storage,
	})
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}

	info := node.GetSetupInfo()

	if info.VendorID != 0xFFF1 {
		t.Errorf("expected VendorID 0xFFF1, got 0x%X", info.VendorID)
	}
	if info.ProductID != 0x8001 {
		t.Errorf("expected ProductID 0x8001, got 0x%X", info.ProductID)
	}
	if info.Discriminator != 3840 {
		t.Errorf("expected Discriminator 3840, got %d", info.Discriminator)
	}
	if info.Passcode != 20202021 {
		t.Errorf("expected Passcode 20202021, got %d", info.Passcode)
	}
	if info.Port != 5540 {
		t.Errorf("expected Port 5540, got %d", info.Port)
	}
	if info.QRCode == "" {
		t.Error("QRCode is empty")
	}
	if info.ManualCode == "" {
		t.Error("ManualCode is empty")
	}
}

func TestIsCommissioned(t *testing.T) {
	storage := NewMemoryStorage()

	node, err := NewNode(NodeConfig{
		VendorID:              0xFFF1,
		ProductID:             0x8001,
		DeviceName:            "Test Device",
		SerialNumber:          "TEST-001",
		Discriminator:         3840,
		Passcode:              20202021,
		HardwareVersion:       1,
		SoftwareVersion:       1,
		SoftwareVersionString: "1.0.0",
		Storage:               storage,
	})
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}

	// New node should not be commissioned
	if node.IsCommissioned() {
		t.Error("new node should not be commissioned")
	}
}

func TestMemoryStorage(t *testing.T) {
	storage := NewMemoryStorage()

	// Test fabric storage
	fabricInfo := &fabric.FabricInfo{
		FabricIndex: 1,
		FabricID:    0x123456789ABC,
		NodeID:      0x0102030405060708,
		VendorID:    0xFFF1,
		Label:       "Test Fabric",
	}

	err := storage.SaveFabric(fabricInfo)
	if err != nil {
		t.Fatalf("SaveFabric failed: %v", err)
	}

	fabrics, err := storage.LoadFabrics()
	if err != nil {
		t.Fatalf("LoadFabrics failed: %v", err)
	}

	if len(fabrics) != 1 {
		t.Errorf("expected 1 fabric, got %d", len(fabrics))
	}

	if fabrics[0].FabricIndex != 1 {
		t.Errorf("expected FabricIndex 1, got %d", fabrics[0].FabricIndex)
	}

	err = storage.DeleteFabric(1)
	if err != nil {
		t.Fatalf("DeleteFabric failed: %v", err)
	}

	fabrics, err = storage.LoadFabrics()
	if err != nil {
		t.Fatalf("LoadFabrics failed: %v", err)
	}

	if len(fabrics) != 0 {
		t.Errorf("expected 0 fabrics after delete, got %d", len(fabrics))
	}
}

func TestPasscodeValidation(t *testing.T) {
	tests := []struct {
		passcode uint32
		valid    bool
	}{
		{0, false},              // Invalid: 0
		{11111111, false},       // Invalid: all same digit
		{12345678, false},       // Invalid: sequential ascending
		{87654321, false},       // Invalid: sequential descending
		{20000001, true},        // Valid: min allowed
		{99999998, true},        // Valid: max allowed
		{20202021, true},        // Valid: common test value
		{100000000, false},      // Invalid: too large
	}

	for _, tc := range tests {
		result := IsValidPasscode(tc.passcode)
		if result != tc.valid {
			t.Errorf("IsValidPasscode(%d) = %v, want %v", tc.passcode, result, tc.valid)
		}
	}
}

func TestInvalidPasscodeConfig(t *testing.T) {
	storage := NewMemoryStorage()

	_, err := NewNode(NodeConfig{
		VendorID:              0xFFF1,
		ProductID:             0x8001,
		DeviceName:            "Test Device",
		SerialNumber:          "TEST-001",
		Discriminator:         3840,
		Passcode:              0, // Invalid passcode
		HardwareVersion:       1,
		SoftwareVersion:       1,
		SoftwareVersionString: "1.0.0",
		Storage:               storage,
	})
	if err != ErrInvalidPasscode {
		t.Errorf("expected ErrInvalidPasscode, got %v", err)
	}
}

func TestPipeFactory(t *testing.T) {
	factory1, factory2 := transport.NewPipeFactoryPair()

	if factory1 == nil || factory2 == nil {
		t.Fatal("NewPipeFactoryPair returned nil")
	}

	// Both factories share the same pipe
	if factory1.Pipe() != factory2.Pipe() {
		t.Error("Factories should share the same pipe")
	}

	// Create UDP connections from both factories
	conn1, err := factory1.CreateUDPConn(5540)
	if err != nil {
		t.Fatalf("CreateUDPConn failed for factory1: %v", err)
	}
	if conn1 == nil {
		t.Fatal("Expected non-nil connection from factory1")
	}

	conn2, err := factory2.CreateUDPConn(5540)
	if err != nil {
		t.Fatalf("CreateUDPConn failed for factory2: %v", err)
	}
	if conn2 == nil {
		t.Fatal("Expected non-nil connection from factory2")
	}

	// Test message flow: factory1 -> factory2
	testMsg := []byte("hello from conn1")
	done := make(chan error, 1)

	// Start reader on conn2
	go func() {
		buf := make([]byte, 1024)
		n, addr, err := conn2.ReadFrom(buf)
		if err != nil {
			done <- err
			return
		}
		if n != len(testMsg) {
			done <- fmt.Errorf("expected %d bytes, got %d", len(testMsg), n)
			return
		}
		if string(buf[:n]) != string(testMsg) {
			done <- fmt.Errorf("message mismatch: %q vs %q", buf[:n], testMsg)
			return
		}
		t.Logf("Received from %v: %s", addr, buf[:n])
		done <- nil
	}()

	// Give reader time to block
	time.Sleep(10 * time.Millisecond)

	// Write from conn1 - auto-process delivers messages automatically!
	_, err = conn1.WriteTo(testMsg, conn2.LocalAddr())
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	// Wait for reader
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Reader error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for message")
	}

	// TCP listener is now supported
	listener, err := factory1.CreateTCPListener(5540)
	if err != nil {
		t.Fatalf("CreateTCPListener failed: %v", err)
	}
	if listener == nil {
		t.Error("Expected non-nil TCP listener")
	} else {
		listener.Close()
	}
}

func TestNodeStateTransitions(t *testing.T) {
	tests := []struct {
		state    NodeState
		canStart bool
		canStop  bool
		running  bool
	}{
		{NodeStateUninitialized, false, false, false},
		{NodeStateInitialized, true, false, false},
		{NodeStateStarting, false, true, false}, // CanStop is true during Starting
		{NodeStateUncommissioned, false, true, true},
		{NodeStateCommissioningOpen, false, true, true},
		{NodeStateCommissioned, false, true, true},
		{NodeStateStopping, false, false, false},
		{NodeStateStopped, false, false, false},
	}

	for _, tc := range tests {
		if tc.state.CanStart() != tc.canStart {
			t.Errorf("state %v CanStart() = %v, want %v", tc.state, tc.state.CanStart(), tc.canStart)
		}
		if tc.state.CanStop() != tc.canStop {
			t.Errorf("state %v CanStop() = %v, want %v", tc.state, tc.state.CanStop(), tc.canStop)
		}
		if tc.state.IsRunning() != tc.running {
			t.Errorf("state %v IsRunning() = %v, want %v", tc.state, tc.state.IsRunning(), tc.running)
		}
	}
}

func TestNodeStateString(t *testing.T) {
	tests := []struct {
		state    NodeState
		expected string
	}{
		{NodeStateUninitialized, "Uninitialized"},
		{NodeStateInitialized, "Initialized"},
		{NodeStateStarting, "Starting"},
		{NodeStateUncommissioned, "Uncommissioned"},
		{NodeStateCommissioningOpen, "CommissioningOpen"},
		{NodeStateCommissioned, "Commissioned"},
		{NodeStateStopping, "Stopping"},
		{NodeStateStopped, "Stopped"},
		{NodeState(99), "Unknown"},
	}

	for _, tc := range tests {
		result := tc.state.String()
		if result != tc.expected {
			t.Errorf("state %d String() = %q, want %q", tc.state, result, tc.expected)
		}
	}
}

func TestEndpointBuilder(t *testing.T) {
	ep := NewEndpoint(1).
		WithDeviceType(0x0100, 1). // On/Off Light
		WithDeviceType(0x0010, 1)  // On/Off

	if ep.ID() != 1 {
		t.Errorf("expected endpoint ID 1, got %d", ep.ID())
	}

	deviceTypes := ep.DeviceTypes()
	if len(deviceTypes) != 2 {
		t.Errorf("expected 2 device types, got %d", len(deviceTypes))
	}

	if deviceTypes[0].DeviceTypeID != 0x0100 {
		t.Errorf("expected first device type 0x0100, got 0x%X", deviceTypes[0].DeviceTypeID)
	}
	if deviceTypes[1].DeviceTypeID != 0x0010 {
		t.Errorf("expected second device type 0x0010, got 0x%X", deviceTypes[1].DeviceTypeID)
	}
}

func TestNodeStopWithoutStart(t *testing.T) {
	storage := NewMemoryStorage()

	node, err := NewNode(NodeConfig{
		VendorID:              0xFFF1,
		ProductID:             0x8001,
		DeviceName:            "Test Device",
		SerialNumber:          "TEST-001",
		Discriminator:         3840,
		Passcode:              20202021,
		HardwareVersion:       1,
		SoftwareVersion:       1,
		SoftwareVersionString: "1.0.0",
		Storage:               storage,
	})
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}

	// Try to stop without starting - should fail
	err = node.Stop()
	if err != ErrNotStarted {
		t.Errorf("expected ErrNotStarted, got %v", err)
	}
}

// Note: TestNodeStartWithPipeTransport is commented out because it requires
// proper transport mocking. Full start/stop integration tests will be added
// in test/integration/ with proper virtual network support.
