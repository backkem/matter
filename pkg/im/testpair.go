package im

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/exchange"
	imsg "github.com/backkem/matter/pkg/im/message"
	"github.com/backkem/matter/pkg/message"
	"github.com/backkem/matter/pkg/session"
	"github.com/backkem/matter/pkg/tlv"
	"github.com/backkem/matter/pkg/transport"
)

// TestIMPairConfig configures a TestIMPair.
type TestIMPairConfig struct {
	// Dispatcher for each side (index 0 = client side, index 1 = server side)
	// If nil, NullDispatcher is used.
	Dispatchers [2]Dispatcher
}

// TestIMPair provides two connected IM engines for E2E testing.
// The client side (index 0) can send requests to the server side (index 1).
//
// Architecture:
//
//	Client (0)                          Server (1)
//	──────────                          ──────────
//	im.Client                           im.Engine
//	    │                                   │
//	    ▼                                   ▼
//	exchange.Manager ◀──── Pipe ────▶ exchange.Manager
type TestIMPair struct {
	exchangePair *exchange.TestManagerPair
	engines      [2]*Engine
	clients      [2]*Client
}

// NewTestIMPair creates a new paired IM test environment.
func NewTestIMPair(config TestIMPairConfig) (*TestIMPair, error) {
	// Create exchange pair
	exchangePair, err := exchange.NewTestManagerPair(exchange.TestManagerPairConfig{
		UDP: true,
	})
	if err != nil {
		return nil, err
	}

	pair := &TestIMPair{
		exchangePair: exchangePair,
	}

	// Create IM engines and register with exchange managers
	for i := 0; i < 2; i++ {
		dispatcher := config.Dispatchers[i]
		if dispatcher == nil {
			dispatcher = NullDispatcher{}
		}

		pair.engines[i] = NewEngine(EngineConfig{
			Dispatcher: dispatcher,
		})

		// Register IM handler with exchange manager using adapter
		adapter := &engineAdapter{engine: pair.engines[i]}
		exchangePair.Manager(i).RegisterProtocol(ProtocolID, adapter)

		// Create IM client
		pair.clients[i] = NewClient(ClientConfig{
			ExchangeManager: exchangePair.Manager(i),
			Timeout:         10 * time.Second,
		})
	}

	return pair, nil
}

// Client returns the IM client at the given index.
func (p *TestIMPair) Client(idx int) *Client {
	return p.clients[idx]
}

// Engine returns the IM engine at the given index.
func (p *TestIMPair) Engine(idx int) *Engine {
	return p.engines[idx]
}

// ExchangePair returns the underlying exchange test pair.
func (p *TestIMPair) ExchangePair() *exchange.TestManagerPair {
	return p.exchangePair
}

// Session returns a test session for the given index.
func (p *TestIMPair) Session(idx int) *exchange.TestUnsecuredSession {
	return p.exchangePair.Session(idx)
}

// PeerAddress returns the peer address for the given index.
func (p *TestIMPair) PeerAddress(idx int) transport.PeerAddress {
	return p.exchangePair.PeerAddress(idx, false) // UDP
}

// Close releases resources.
func (p *TestIMPair) Close() {
	if p.exchangePair != nil {
		p.exchangePair.Close()
	}
}

// engineAdapter adapts im.Engine to exchange.ProtocolHandler.
type engineAdapter struct {
	engine *Engine
}

// OnMessage implements exchange.ProtocolHandler.
func (a *engineAdapter) OnMessage(ctx *exchange.ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	return a.handleIM(ctx, opcode, payload)
}

// OnUnsolicited implements exchange.ProtocolHandler.
func (a *engineAdapter) OnUnsolicited(ctx *exchange.ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	return a.handleIM(ctx, opcode, payload)
}

// handleIM routes IM messages to the engine.
// The engine sends responses directly with correct opcodes (matching C++ SDK).
func (a *engineAdapter) handleIM(ctx *exchange.ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	header := &message.ProtocolHeader{
		ProtocolID:     ProtocolID,
		ProtocolOpcode: opcode,
		ExchangeID:     ctx.ID,
	}

	return a.engine.OnMessage(ctx, header, payload)
}

// ClusterDispatcher routes IM operations to registered clusters.
// This provides a simple data model for testing.
type ClusterDispatcher struct {
	clusters map[clusterKey]datamodel.Cluster
}

type clusterKey struct {
	endpoint datamodel.EndpointID
	cluster  datamodel.ClusterID
}

// NewClusterDispatcher creates a new cluster dispatcher.
func NewClusterDispatcher() *ClusterDispatcher {
	return &ClusterDispatcher{
		clusters: make(map[clusterKey]datamodel.Cluster),
	}
}

// RegisterCluster registers a cluster at an endpoint.
func (d *ClusterDispatcher) RegisterCluster(endpoint datamodel.EndpointID, cluster datamodel.Cluster) {
	key := clusterKey{endpoint: endpoint, cluster: cluster.ID()}
	d.clusters[key] = cluster
}

// ReadAttribute implements Dispatcher.
func (d *ClusterDispatcher) ReadAttribute(ctx context.Context, req *AttributeReadRequest, w *tlv.Writer) error {
	key := clusterKey{
		endpoint: derefEndpoint(req.Path.Endpoint),
		cluster:  derefCluster(req.Path.Cluster),
	}
	cluster, ok := d.clusters[key]
	if !ok {
		return ErrClusterNotFound
	}

	dmReq := req.ToDataModelRequest()
	return cluster.ReadAttribute(ctx, dmReq, w)
}

// WriteAttribute implements Dispatcher.
func (d *ClusterDispatcher) WriteAttribute(ctx context.Context, req *AttributeWriteRequest, r *tlv.Reader) error {
	key := clusterKey{
		endpoint: derefEndpoint(req.Path.Endpoint),
		cluster:  derefCluster(req.Path.Cluster),
	}
	cluster, ok := d.clusters[key]
	if !ok {
		return ErrClusterNotFound
	}

	dmReq := req.ToDataModelRequest()
	return cluster.WriteAttribute(ctx, dmReq, r)
}

// InvokeCommand implements Dispatcher.
func (d *ClusterDispatcher) InvokeCommand(ctx context.Context, req *CommandInvokeRequest, r *tlv.Reader) ([]byte, error) {
	key := clusterKey{
		endpoint: datamodel.EndpointID(req.Path.Endpoint),
		cluster:  datamodel.ClusterID(req.Path.Cluster),
	}
	cluster, ok := d.clusters[key]
	if !ok {
		return nil, ErrClusterNotFound
	}

	dmReq := req.ToDataModelRequest()
	return cluster.InvokeCommand(ctx, dmReq, r)
}

// =============================================================================
// MockDispatcher - Records calls for E2E test verification
// =============================================================================

// MockDispatcher records IM operations for testing verification.
// Thread-safe for concurrent access.
type MockDispatcher struct {
	mu           sync.Mutex
	invokeCalls  []InvokeCall
	readCalls    []ReadCall
	writeCalls   []WriteCall
	invokeResult MockInvokeResult
	readResult   MockReadResult
	writeResult  error
}

// InvokeCall records a command invocation.
type InvokeCall struct {
	Path    imsg.CommandPathIB
	IsTimed bool
	Fields  []byte
}

// ReadCall records an attribute read.
type ReadCall struct {
	Path             imsg.AttributePathIB
	IsFabricFiltered bool
}

// WriteCall records an attribute write.
type WriteCall struct {
	Path    imsg.AttributePathIB
	IsTimed bool
	Data    []byte
}

// MockInvokeResult configures the response for InvokeCommand.
type MockInvokeResult struct {
	Response []byte
	Err      error
}

// MockReadResult configures the response for ReadAttribute.
type MockReadResult struct {
	Value interface{} // Written to TLV
	Err   error
}

// NewMockDispatcher creates a new mock dispatcher.
func NewMockDispatcher() *MockDispatcher {
	return &MockDispatcher{}
}

// SetInvokeResult configures the response for InvokeCommand.
func (d *MockDispatcher) SetInvokeResult(response []byte, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.invokeResult = MockInvokeResult{Response: response, Err: err}
}

// SetReadResult configures the response for ReadAttribute.
// Value will be encoded as TLV.
func (d *MockDispatcher) SetReadResult(value interface{}, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.readResult = MockReadResult{Value: value, Err: err}
}

// SetWriteResult configures the response for WriteAttribute.
func (d *MockDispatcher) SetWriteResult(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.writeResult = err
}

// InvokeCalls returns recorded invoke calls.
func (d *MockDispatcher) InvokeCalls() []InvokeCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	result := make([]InvokeCall, len(d.invokeCalls))
	copy(result, d.invokeCalls)
	return result
}

// ReadCalls returns recorded read calls.
func (d *MockDispatcher) ReadCalls() []ReadCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	result := make([]ReadCall, len(d.readCalls))
	copy(result, d.readCalls)
	return result
}

// WriteCalls returns recorded write calls.
func (d *MockDispatcher) WriteCalls() []WriteCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	result := make([]WriteCall, len(d.writeCalls))
	copy(result, d.writeCalls)
	return result
}

// Reset clears all recorded calls.
func (d *MockDispatcher) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.invokeCalls = nil
	d.readCalls = nil
	d.writeCalls = nil
}

// InvokeCommand implements Dispatcher.
func (d *MockDispatcher) InvokeCommand(ctx context.Context, req *CommandInvokeRequest, r *tlv.Reader) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Read any remaining fields data
	var fields []byte
	if r != nil {
		var buf bytes.Buffer
		// Copy the reader data (simplified - real impl would re-encode)
		fields = buf.Bytes()
	}

	d.invokeCalls = append(d.invokeCalls, InvokeCall{
		Path:    req.Path,
		IsTimed: req.IsTimed,
		Fields:  fields,
	})

	return d.invokeResult.Response, d.invokeResult.Err
}

// ReadAttribute implements Dispatcher.
func (d *MockDispatcher) ReadAttribute(ctx context.Context, req *AttributeReadRequest, w *tlv.Writer) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.readCalls = append(d.readCalls, ReadCall{
		Path:             req.Path,
		IsFabricFiltered: req.IsFabricFiltered,
	})

	if d.readResult.Err != nil {
		return d.readResult.Err
	}

	// Write the configured value
	if d.readResult.Value != nil {
		switch v := d.readResult.Value.(type) {
		case bool:
			return w.PutBool(tlv.Anonymous(), v)
		case int:
			return w.PutInt(tlv.Anonymous(), int64(v))
		case int64:
			return w.PutInt(tlv.Anonymous(), v)
		case uint:
			return w.PutUint(tlv.Anonymous(), uint64(v))
		case uint64:
			return w.PutUint(tlv.Anonymous(), v)
		case string:
			return w.PutString(tlv.Anonymous(), v)
		case []byte:
			return w.PutBytes(tlv.Anonymous(), v)
		}
	}

	return nil
}

// WriteAttribute implements Dispatcher.
func (d *MockDispatcher) WriteAttribute(ctx context.Context, req *AttributeWriteRequest, r *tlv.Reader) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Read the data being written
	var data []byte
	if r != nil {
		var buf bytes.Buffer
		// Copy data (simplified)
		data = buf.Bytes()
	}

	d.writeCalls = append(d.writeCalls, WriteCall{
		Path:    req.Path,
		IsTimed: req.IsTimed,
		Data:    data,
	})

	return d.writeResult
}

// =============================================================================
// SecureTestIMPair - IM pair with encrypted sessions
// =============================================================================

// Test keys (16 bytes each) - same as session package test keys.
var (
	testI2RKey = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	testR2IKey = []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20}
)

// SecureTestIMPairConfig configures a SecureTestIMPair.
type SecureTestIMPairConfig struct {
	// Dispatcher for each side (index 0 = client side, index 1 = server side)
	Dispatchers [2]Dispatcher
}

// SecureTestIMPair provides two connected IM engines with encrypted sessions.
type SecureTestIMPair struct {
	exchangePair   *exchange.TestManagerPair
	engines        [2]*Engine
	clients        [2]*Client
	secureSessions [2]*session.SecureContext
}

// NewSecureTestIMPair creates a new paired IM test environment with secure sessions.
func NewSecureTestIMPair(config SecureTestIMPairConfig) (*SecureTestIMPair, error) {
	// Create exchange pair
	exchangePair, err := exchange.NewTestManagerPair(exchange.TestManagerPairConfig{
		UDP: true,
	})
	if err != nil {
		return nil, err
	}

	pair := &SecureTestIMPair{
		exchangePair: exchangePair,
	}

	// Create secure sessions for both sides
	// Client (0) is initiator, Server (1) is responder
	clientSession, err := session.NewSecureContext(session.SecureContextConfig{
		SessionType:    session.SessionTypePASE,
		Role:           session.SessionRoleInitiator,
		LocalSessionID: 1,
		PeerSessionID:  2,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
		Params: session.Params{
			IdleInterval:    500 * time.Millisecond,
			ActiveInterval:  300 * time.Millisecond,
			ActiveThreshold: 4000 * time.Millisecond,
		},
	})
	if err != nil {
		exchangePair.Close()
		return nil, err
	}

	serverSession, err := session.NewSecureContext(session.SecureContextConfig{
		SessionType:    session.SessionTypePASE,
		Role:           session.SessionRoleResponder,
		LocalSessionID: 2,
		PeerSessionID:  1,
		I2RKey:         testI2RKey,
		R2IKey:         testR2IKey,
		Params: session.Params{
			IdleInterval:    500 * time.Millisecond,
			ActiveInterval:  300 * time.Millisecond,
			ActiveThreshold: 4000 * time.Millisecond,
		},
	})
	if err != nil {
		exchangePair.Close()
		return nil, err
	}

	pair.secureSessions[0] = clientSession
	pair.secureSessions[1] = serverSession

	// Register sessions with session managers for decryption
	// Client (0) receives messages with sessionID=1 (its local ID)
	// Server (1) receives messages with sessionID=2 (its local ID)
	if err := exchangePair.SessionManager(0).AddSecureContext(clientSession); err != nil {
		exchangePair.Close()
		return nil, err
	}
	if err := exchangePair.SessionManager(1).AddSecureContext(serverSession); err != nil {
		exchangePair.Close()
		return nil, err
	}

	// Create IM engines and register with exchange managers
	for i := 0; i < 2; i++ {
		dispatcher := config.Dispatchers[i]
		if dispatcher == nil {
			dispatcher = NullDispatcher{}
		}

		pair.engines[i] = NewEngine(EngineConfig{
			Dispatcher: dispatcher,
		})

		// Register IM handler with exchange manager
		adapter := &engineAdapter{engine: pair.engines[i]}
		exchangePair.Manager(i).RegisterProtocol(ProtocolID, adapter)

		// Create IM client
		pair.clients[i] = NewClient(ClientConfig{
			ExchangeManager: exchangePair.Manager(i),
			Timeout:         10 * time.Second,
		})
	}

	return pair, nil
}

// Client returns the IM client at the given index.
func (p *SecureTestIMPair) Client(idx int) *Client {
	return p.clients[idx]
}

// Engine returns the IM engine at the given index.
func (p *SecureTestIMPair) Engine(idx int) *Engine {
	return p.engines[idx]
}

// ExchangePair returns the underlying exchange test pair.
func (p *SecureTestIMPair) ExchangePair() *exchange.TestManagerPair {
	return p.exchangePair
}

// Session returns the secure session for the given index.
func (p *SecureTestIMPair) Session(idx int) *session.SecureContext {
	return p.secureSessions[idx]
}

// PeerAddress returns the peer address for the given index.
func (p *SecureTestIMPair) PeerAddress(idx int) transport.PeerAddress {
	return p.exchangePair.PeerAddress(idx, false) // UDP
}

// Close releases resources.
func (p *SecureTestIMPair) Close() {
	if p.exchangePair != nil {
		p.exchangePair.Close()
	}
	for i := 0; i < 2; i++ {
		if p.secureSessions[i] != nil {
			p.secureSessions[i].ZeroizeKeys()
		}
	}
}
