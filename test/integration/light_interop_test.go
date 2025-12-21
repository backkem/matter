//go:build interop

// Package integration contains integration tests for Matter devices.
//
// This file (light_interop_test.go) contains interop tests with chip-tool.
// These tests require chip-tool to be installed and available in PATH.
//
// Build with: go test -tags=interop ./test/integration/...
package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/backkem/matter/test/integration/framework"
)

const (
	// Test node ID for commissioning
	testNodeID = uint64(1234)

	// Test endpoint ID for the light
	testEndpointID = uint16(1)

	// Default setup PIN code
	testPinCode = uint32(20202021)
)

// TestInterop_LightCommissioning tests commissioning a light device with chip-tool.
func TestInterop_LightCommissioning(t *testing.T) {
	// Create temporary storage directories
	deviceStorage := t.TempDir()
	chipToolStorage := t.TempDir()

	// Start the light device
	config := framework.DeviceProcessConfig{
		BinaryPath:  filepath.Join("..", "..", "cmd", "matter-light-device"),
		Port:        5540,
		StoragePath: deviceStorage,
	}

	// Check for log file via environment variable
	// Usage: INTEROP_LOG_FILE=/tmp/interop.log go test -tags=interop -v ./test/integration -run TestInterop_LightCommissioning
	if logFile := os.Getenv("INTEROP_LOG_FILE"); logFile != "" {
		config.LogFile = logFile
		t.Logf("Logging to file: %s", logFile)
	}

	device := framework.NewDeviceProcess(config)

	if err := device.Start(); err != nil {
		t.Fatalf("Failed to start device: %v", err)
	}
	defer device.Stop()

	// Create chip-tool wrapper
	chipToolConfig := framework.ChipToolConfig{
		StorageDir: chipToolStorage,
	}
	if logFile := os.Getenv("INTEROP_LOG_FILE"); logFile != "" {
		chipToolConfig.LogFile = logFile
	}
	chipTool := framework.NewChipTool(t, chipToolConfig)
	defer chipTool.Close()

	// Clean any previous pairing state
	if err := chipTool.CleanStorage(); err != nil {
		t.Logf("Warning: Failed to clean chip-tool storage: %v", err)
	}

	// Wait for device to be ready
	time.Sleep(2 * time.Second)

	// Pair with the device using manual pairing code
	// Note: Using manual code instead of onnetwork because mDNS may not work in WSL
	manualCode := device.OnboardingPayload()
	t.Logf("Using manual pairing code: %s", manualCode)

	if err := chipTool.PairWithCode(testNodeID, manualCode); err != nil {
		t.Fatalf("Failed to pair with device: %v", err)
	}

	t.Log("Successfully commissioned light device with chip-tool")

	// Clean up - unpair the device
	if err := chipTool.Unpair(testNodeID); err != nil {
		t.Logf("Warning: Failed to unpair device: %v", err)
	}
}

// TestInterop_LightOnOffControl tests controlling the light with chip-tool OnOff commands.
func TestInterop_LightOnOffControl(t *testing.T) {
	// Create temporary storage directories
	deviceStorage := t.TempDir()
	chipToolStorage := t.TempDir()

	// Start the light device
	device := framework.NewDeviceProcess(framework.DeviceProcessConfig{
		BinaryPath:  filepath.Join("..", "..", "cmd", "matter-light-device"),
		Port:        5540,
		StoragePath: deviceStorage,
	})

	if err := device.Start(); err != nil {
		t.Fatalf("Failed to start device: %v", err)
	}
	defer device.Stop()

	// Create chip-tool wrapper
	chipToolConfig := framework.ChipToolConfig{
		StorageDir: chipToolStorage,
	}
	if logFile := os.Getenv("INTEROP_LOG_FILE"); logFile != "" {
		chipToolConfig.LogFile = logFile
	}
	chipTool := framework.NewChipTool(t, chipToolConfig)
	defer chipTool.Close()

	// Clean any previous pairing state
	if err := chipTool.CleanStorage(); err != nil {
		t.Logf("Warning: Failed to clean chip-tool storage: %v", err)
	}

	// Wait for device to be ready
	time.Sleep(2 * time.Second)

	// Pair with the device using manual pairing code
	// Note: Using manual code instead of onnetwork because mDNS may not work in WSL
	manualCode := device.OnboardingPayload()
	t.Logf("Using manual pairing code: %s", manualCode)

	if err := chipTool.PairWithCode(testNodeID, manualCode); err != nil {
		t.Fatalf("Failed to pair with device: %v", err)
	}
	defer chipTool.Unpair(testNodeID)

	t.Log("Device commissioned, testing OnOff commands...")

	// Test On command
	t.Log("Sending On command...")
	if err := chipTool.OnOffOn(testNodeID, testEndpointID); err != nil {
		t.Fatalf("Failed to send On command: %v", err)
	}

	// Wait for command to propagate
	time.Sleep(500 * time.Millisecond)

	// Test Off command
	t.Log("Sending Off command...")
	if err := chipTool.OnOffOff(testNodeID, testEndpointID); err != nil {
		t.Fatalf("Failed to send Off command: %v", err)
	}

	// Wait for command to propagate
	time.Sleep(500 * time.Millisecond)

	// Test Toggle command
	t.Log("Sending Toggle command...")
	if err := chipTool.OnOffToggle(testNodeID, testEndpointID); err != nil {
		t.Fatalf("Failed to send Toggle command: %v", err)
	}

	t.Log("Successfully controlled light with chip-tool OnOff commands")
}

// TestInterop_LightReadAttributes tests reading attributes from the light with chip-tool.
func TestInterop_LightReadAttributes(t *testing.T) {
	// Create temporary storage directories
	deviceStorage := t.TempDir()
	chipToolStorage := t.TempDir()

	// Start the light device
	device := framework.NewDeviceProcess(framework.DeviceProcessConfig{
		BinaryPath:  filepath.Join("..", "..", "cmd", "matter-light-device"),
		Port:        5540,
		StoragePath: deviceStorage,
	})

	if err := device.Start(); err != nil {
		t.Fatalf("Failed to start device: %v", err)
	}
	defer device.Stop()

	// Create chip-tool wrapper
	chipToolConfig := framework.ChipToolConfig{
		StorageDir: chipToolStorage,
	}
	if logFile := os.Getenv("INTEROP_LOG_FILE"); logFile != "" {
		chipToolConfig.LogFile = logFile
	}
	chipTool := framework.NewChipTool(t, chipToolConfig)
	defer chipTool.Close()

	// Clean any previous pairing state
	if err := chipTool.CleanStorage(); err != nil {
		t.Logf("Warning: Failed to clean chip-tool storage: %v", err)
	}

	// Wait for device to be ready
	time.Sleep(2 * time.Second)

	// Pair with the device using manual pairing code
	// Note: Using manual code instead of onnetwork because mDNS may not work in WSL
	manualCode := device.OnboardingPayload()
	t.Logf("Using manual pairing code: %s", manualCode)

	if err := chipTool.PairWithCode(testNodeID, manualCode); err != nil {
		t.Fatalf("Failed to pair with device: %v", err)
	}
	defer chipTool.Unpair(testNodeID)

	t.Log("Device commissioned, testing attribute reads...")

	// Read basic information
	t.Log("Reading basic information attributes...")
	basicInfo, err := chipTool.ReadBasicInformation(testNodeID, 0)
	if err != nil {
		t.Fatalf("Failed to read basic information: %v", err)
	}

	t.Logf("Basic Information:")
	for key, value := range basicInfo {
		t.Logf("  %s: %s", key, value)
	}

	// Read OnOff attribute
	t.Log("Reading OnOff attribute...")
	onOffValue, err := chipTool.ReadAttribute(testNodeID, testEndpointID, "onoff", "on-off")
	if err != nil {
		t.Fatalf("Failed to read OnOff attribute: %v", err)
	}

	t.Logf("OnOff attribute value: %s", onOffValue)

	t.Log("Successfully read attributes from light with chip-tool")
}

// TestMain sets up and tears down for interop tests.
func TestMain(m *testing.M) {
	// Check if chip-tool is available (in PATH or repo root)
	chipToolPath, err := exec.LookPath("chip-tool")
	if err != nil {
		// Try chip-tool in repo root (../../chip-tool from test/integration)
		repoRoot := filepath.Join("..", "..")
		if _, err := os.Stat(filepath.Join(repoRoot, "chip-tool")); err != nil {
			println("chip-tool not found in PATH or repo root, skipping interop tests")
			println("Install chip-tool or add it to PATH to run these tests")
			os.Exit(0)
		}
		chipToolPath = filepath.Join(repoRoot, "chip-tool")
	}
	println("Using chip-tool:", chipToolPath)

	// Run tests
	os.Exit(m.Run())
}
