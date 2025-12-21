# Matter Integration Tests

This directory contains integration tests for the Matter Go stack.

## Test Types

### 1. Basic Tests (`light_basic_test.go`)

Basic tests verify device functionality without network I/O.

**Run with:**

```bash
go test ./test/integration -run TestBasic
```

### 2. End-to-End Tests (`light_e2e_test.go`, `commissioning_e2e_test.go`)

End-to-end tests verify full controller ↔ device communication over a virtual pipe network.

**Run with:**

```bash
go test ./test/integration -run TestE2E
```

### 3. Interop Tests (`light_interop_test.go`)

Interop tests verify compatibility with the official C++ SDK chip-tool.

These tests:

- Build and run the actual device binary (`cmd/matter-light-device`)
- Use chip-tool to commission and control the device
- Test real UDP network communication

**Prerequisites:**

- chip-tool must be installed and available in PATH
- Install from snap: `sudo snap install chip-tool`
- Or build from source: https://github.com/project-chip/connectedhomeip

**Run with:**

```bash
go test -tags=interop ./test/integration -run TestInterop
```

**Run specific test:**

```bash
go test -tags=interop ./test/integration -run TestInterop_LightOnOffControl -v
```

## Test Infrastructure

### Framework Package (`framework/`)

The framework package provides utilities for integration testing:

#### `process.go` - Device Process Management

Manages the lifecycle of Matter device binaries:

```go
device := framework.NewDeviceProcess(framework.DeviceProcessConfig{
    BinaryPath:  "cmd/matter-light-device",
    Port:        5540,
    StoragePath: "/tmp/device-storage",
})

if err := device.Start(); err != nil {
    t.Fatal(err)
}
defer device.Stop()
```

Features:

- Automatic building with `go build`
- Process lifecycle management (start, stop, graceful shutdown)
- Log capture and forwarding
- Port management

#### `chiptool.go` - chip-tool Wrapper

Wraps chip-tool commands for easy testing:

```go
chipTool := framework.NewChipTool(t, framework.ChipToolConfig{
    StorageDir: "/tmp/chip-tool-storage",
})

// Commission device
err := chipTool.PairOnNetwork(nodeID, pinCode)

// Send commands
err = chipTool.OnOffToggle(nodeID, endpointID)

// Read attributes
value, err := chipTool.ReadAttribute(nodeID, endpoint, "onoff", "on-off")
```

Features:

- Commissioning (onnetwork, code-based)
- OnOff cluster commands (on, off, toggle)
- Attribute reads
- Storage management
- Timeout handling

### Test Pair (`testpair.go`)

Helper for creating commissioned device+controller pairs for e2e tests:

```go
pair := NewTestPair(t, light.Factory)
defer pair.Close()

// Use pair.Controller and pair.Device
result, err := pair.Controller.SendCommand(...)
```

## Running All Tests

```bash
# Run all non-interop tests
go test ./test/integration

# Run all tests including interop
go test -tags=interop ./test/integration

# Run with verbose output
go test -tags=interop ./test/integration -v

# Run a specific test
go test -tags=interop ./test/integration -run TestInterop_LightOnOffControl -v
```
