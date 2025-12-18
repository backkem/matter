package im

import (
	"context"
	"testing"
	"time"

	imsg "github.com/backkem/matter/pkg/im/message"
)

// =============================================================================
// E2E Tests: IM over Secure Session
// =============================================================================

// TestE2E_InvokeCommand tests command invocation over secure session.
// Flow: Client(0) -> Engine(1) -> MockDispatcher -> Response -> Client(0)
func TestE2E_InvokeCommand(t *testing.T) {
	// Create mock dispatcher to capture calls on server side
	mockDispatcher := NewMockDispatcher()

	// Create IM pair with secure sessions
	pair, err := NewSecureTestIMPair(SecureTestIMPairConfig{
		Dispatchers: [2]Dispatcher{
			nil,           // Client side - not used
			mockDispatcher, // Server side - captures commands
		},
	})
	if err != nil {
		t.Fatalf("NewSecureTestIMPair: %v", err)
	}
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Client sends InvokeRequest to server
	// OnOff cluster (0x0006), On command (0x01) on endpoint 1
	result, err := pair.Client(0).InvokeWithStatus(
		ctx,
		pair.Session(0),     // Client's secure session
		pair.PeerAddress(1), // Server's address
		1,                   // Endpoint ID
		0x0006,              // OnOff cluster
		0x01,                // On command
		nil,                 // No command fields
	)
	if err != nil {
		t.Fatalf("InvokeWithStatus: %v", err)
	}

	// Verify server received the command
	calls := mockDispatcher.InvokeCalls()
	if len(calls) != 1 {
		t.Fatalf("Expected 1 invoke call, got %d", len(calls))
	}

	call := calls[0]
	if call.Path.Endpoint != 1 {
		t.Errorf("Endpoint = %d, want 1", call.Path.Endpoint)
	}
	if call.Path.Cluster != 0x0006 {
		t.Errorf("Cluster = 0x%04x, want 0x0006", call.Path.Cluster)
	}
	if call.Path.Command != 0x01 {
		t.Errorf("Command = 0x%02x, want 0x01", call.Path.Command)
	}

	// Verify response (success status since mock returns nil error)
	if result.HasStatus && result.Status != imsg.StatusSuccess {
		t.Errorf("Status = %s, want Success", result.Status)
	}

	t.Logf("E2E InvokeCommand: path=%+v, status=%s", call.Path, result.Status)
}

// TestE2E_InvokeCommand_WithResponse tests command with response data.
func TestE2E_InvokeCommand_WithResponse(t *testing.T) {
	mockDispatcher := NewMockDispatcher()

	// Configure mock to return response data
	// This simulates a command that returns data (e.g., a query command)
	responseData := []byte{0x15, 0x00, 0x28, 0x01, 0x18} // TLV: struct with bool true
	mockDispatcher.SetInvokeResult(responseData, nil)

	pair, err := NewSecureTestIMPair(SecureTestIMPairConfig{
		Dispatchers: [2]Dispatcher{nil, mockDispatcher},
	})
	if err != nil {
		t.Fatalf("NewSecureTestIMPair: %v", err)
	}
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := pair.Client(0).InvokeWithStatus(
		ctx,
		pair.Session(0),
		pair.PeerAddress(1),
		0,      // Endpoint
		0x003E, // OperationalCredentials cluster
		0x04,   // CSRRequest command
		nil,
	)
	if err != nil {
		t.Fatalf("InvokeWithStatus: %v", err)
	}

	// Verify response data
	if result.HasStatus {
		t.Logf("Got status response: %s", result.Status)
	}
	if len(result.ResponseData) > 0 {
		t.Logf("Got response data: %x", result.ResponseData)
	}

	// Verify dispatcher was called
	calls := mockDispatcher.InvokeCalls()
	if len(calls) != 1 {
		t.Fatalf("Expected 1 invoke call, got %d", len(calls))
	}
}

// TestE2E_InvokeCommand_Error tests command that returns error.
func TestE2E_InvokeCommand_Error(t *testing.T) {
	mockDispatcher := NewMockDispatcher()

	// Configure mock to return error (cluster not found)
	mockDispatcher.SetInvokeResult(nil, ErrClusterNotFound)

	pair, err := NewSecureTestIMPair(SecureTestIMPairConfig{
		Dispatchers: [2]Dispatcher{nil, mockDispatcher},
	})
	if err != nil {
		t.Fatalf("NewSecureTestIMPair: %v", err)
	}
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := pair.Client(0).InvokeWithStatus(
		ctx,
		pair.Session(0),
		pair.PeerAddress(1),
		99,     // Invalid endpoint
		0x9999, // Invalid cluster
		0x01,
		nil,
	)
	if err != nil {
		t.Fatalf("InvokeWithStatus: %v", err)
	}

	// Should have status indicating error
	if !result.HasStatus {
		t.Error("Expected status response for error")
	}
	if result.Status != imsg.StatusUnsupportedCluster {
		t.Errorf("Status = %s, want UnsupportedCluster", result.Status)
	}

	t.Logf("E2E InvokeCommand error: status=%s", result.Status)
}

// TestE2E_ReadAttribute tests attribute read over secure session.
func TestE2E_ReadAttribute(t *testing.T) {
	mockDispatcher := NewMockDispatcher()

	// Configure mock to return a boolean value
	mockDispatcher.SetReadResult(true, nil)

	pair, err := NewSecureTestIMPair(SecureTestIMPairConfig{
		Dispatchers: [2]Dispatcher{nil, mockDispatcher},
	})
	if err != nil {
		t.Fatalf("NewSecureTestIMPair: %v", err)
	}
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Read OnOff attribute from OnOff cluster
	data, err := pair.Client(0).ReadAttribute(
		ctx,
		pair.Session(0),
		pair.PeerAddress(1),
		1,      // Endpoint
		0x0006, // OnOff cluster
		0x0000, // OnOff attribute
	)
	if err != nil {
		t.Fatalf("ReadAttribute: %v", err)
	}

	// Verify server received the read request
	calls := mockDispatcher.ReadCalls()
	if len(calls) != 1 {
		t.Fatalf("Expected 1 read call, got %d", len(calls))
	}

	call := calls[0]
	if call.Path.Endpoint == nil || *call.Path.Endpoint != 1 {
		t.Errorf("Endpoint = %v, want 1", call.Path.Endpoint)
	}
	if call.Path.Cluster == nil || *call.Path.Cluster != 0x0006 {
		t.Errorf("Cluster = %v, want 0x0006", call.Path.Cluster)
	}
	if call.Path.Attribute == nil || *call.Path.Attribute != 0x0000 {
		t.Errorf("Attribute = %v, want 0x0000", call.Path.Attribute)
	}

	t.Logf("E2E ReadAttribute: path=%+v, data=%x", call.Path, data)
}

// TestE2E_ReadAttribute_Error tests attribute read that returns error.
func TestE2E_ReadAttribute_Error(t *testing.T) {
	mockDispatcher := NewMockDispatcher()

	// Configure mock to return error
	mockDispatcher.SetReadResult(nil, ErrAttributeNotFound)

	pair, err := NewSecureTestIMPair(SecureTestIMPairConfig{
		Dispatchers: [2]Dispatcher{nil, mockDispatcher},
	})
	if err != nil {
		t.Fatalf("NewSecureTestIMPair: %v", err)
	}
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = pair.Client(0).ReadAttribute(
		ctx,
		pair.Session(0),
		pair.PeerAddress(1),
		1,
		0x0006,
		0x9999, // Invalid attribute
	)

	// Should return error
	if err == nil {
		t.Error("Expected error for invalid attribute")
	}

	t.Logf("E2E ReadAttribute error: %v", err)
}

// TestE2E_Bidirectional tests bidirectional communication.
func TestE2E_Bidirectional(t *testing.T) {
	// Create mock dispatchers for both sides
	mockClient := NewMockDispatcher()
	mockServer := NewMockDispatcher()

	pair, err := NewSecureTestIMPair(SecureTestIMPairConfig{
		Dispatchers: [2]Dispatcher{mockClient, mockServer},
	})
	if err != nil {
		t.Fatalf("NewSecureTestIMPair: %v", err)
	}
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Client -> Server
	_, err = pair.Client(0).InvokeWithStatus(
		ctx,
		pair.Session(0),
		pair.PeerAddress(1),
		1, 0x0006, 0x01,
		nil,
	)
	if err != nil {
		t.Fatalf("Client->Server: %v", err)
	}

	// Verify server received
	if len(mockServer.InvokeCalls()) != 1 {
		t.Errorf("Server expected 1 call, got %d", len(mockServer.InvokeCalls()))
	}

	// Server -> Client
	_, err = pair.Client(1).InvokeWithStatus(
		ctx,
		pair.Session(1),
		pair.PeerAddress(0),
		1, 0x0006, 0x02,
		nil,
	)
	if err != nil {
		t.Fatalf("Server->Client: %v", err)
	}

	// Verify client received
	if len(mockClient.InvokeCalls()) != 1 {
		t.Errorf("Client expected 1 call, got %d", len(mockClient.InvokeCalls()))
	}

	t.Log("E2E Bidirectional: both directions successful")
}

// TestE2E_MultipleCommands tests sending multiple commands in sequence.
func TestE2E_MultipleCommands(t *testing.T) {
	mockDispatcher := NewMockDispatcher()

	pair, err := NewSecureTestIMPair(SecureTestIMPairConfig{
		Dispatchers: [2]Dispatcher{nil, mockDispatcher},
	})
	if err != nil {
		t.Fatalf("NewSecureTestIMPair: %v", err)
	}
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Send multiple commands
	commands := []struct {
		endpoint uint16
		cluster  uint32
		command  uint32
	}{
		{1, 0x0006, 0x01}, // OnOff.On
		{1, 0x0006, 0x00}, // OnOff.Off
		{1, 0x0006, 0x02}, // OnOff.Toggle
		{2, 0x0008, 0x00}, // LevelControl.MoveToLevel
	}

	for i, cmd := range commands {
		_, err := pair.Client(0).InvokeWithStatus(
			ctx,
			pair.Session(0),
			pair.PeerAddress(1),
			cmd.endpoint,
			cmd.cluster,
			cmd.command,
			nil,
		)
		if err != nil {
			t.Fatalf("Command %d: %v", i, err)
		}
	}

	// Verify all commands received
	calls := mockDispatcher.InvokeCalls()
	if len(calls) != len(commands) {
		t.Fatalf("Expected %d calls, got %d", len(commands), len(calls))
	}

	for i, cmd := range commands {
		call := calls[i]
		if call.Path.Endpoint != imsg.EndpointID(cmd.endpoint) {
			t.Errorf("Command %d: endpoint=%d, want %d", i, call.Path.Endpoint, cmd.endpoint)
		}
		if call.Path.Cluster != imsg.ClusterID(cmd.cluster) {
			t.Errorf("Command %d: cluster=%x, want %x", i, call.Path.Cluster, cmd.cluster)
		}
		if call.Path.Command != imsg.CommandID(cmd.command) {
			t.Errorf("Command %d: command=%x, want %x", i, call.Path.Command, cmd.command)
		}
	}

	t.Logf("E2E MultipleCommands: %d commands successful", len(commands))
}
