package matter

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/backkem/matter/pkg/acl"
	"github.com/backkem/matter/pkg/commissioning"
	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/discovery"
	"github.com/backkem/matter/pkg/exchange"
	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/im"
	"github.com/backkem/matter/pkg/message"
	"github.com/backkem/matter/pkg/securechannel"
	"github.com/backkem/matter/pkg/securechannel/pase"
	"github.com/backkem/matter/pkg/session"
	"github.com/backkem/matter/pkg/transport"
	"github.com/pion/logging"
)

// Node represents a running Matter node (device or controller).
// It coordinates all stack layers and manages the device lifecycle.
type Node struct {
	config NodeConfig
	state  NodeState
	log    logging.LeveledLogger

	// Core managers
	fabricTable  *fabric.Table
	sessionMgr   *session.Manager
	transportMgr *transport.Manager
	exchangeMgr  *exchange.Manager
	scMgr        *securechannel.Manager
	imEngine     *im.Engine
	discoveryMgr *discovery.Manager
	aclMgr       *acl.Manager

	// Data model
	dataModel  *datamodel.BasicNode
	dispatcher *nodeDispatcher

	// Endpoints (including root)
	endpoints map[datamodel.EndpointID]*Endpoint

	// Commissioning
	commWindow *commissioning.CommissioningWindow
	paseInfo   *paseInfo // PASE parameters for commissioning

	// Synchronization
	mu       sync.RWMutex
	stopCh   chan struct{}
	stopOnce sync.Once

	// Context for background operations
	ctx    context.Context
	cancel context.CancelFunc
}

// paseInfo holds PASE parameters derived from the passcode.
type paseInfo struct {
	verifier   *pase.Verifier
	salt       []byte
	iterations uint32
}

// NewNode creates a new Matter node with the given configuration.
// The node is created but not started. Call Start() to begin operation.
func NewNode(config NodeConfig) (*Node, error) {
	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Apply defaults
	config.applyDefaults()

	n := &Node{
		config:    config,
		state:     NodeStateUninitialized,
		endpoints: make(map[datamodel.EndpointID]*Endpoint),
		stopCh:    make(chan struct{}),
	}

	// Initialize logger
	if config.LoggerFactory != nil {
		n.log = config.LoggerFactory.NewLogger("matter")
	}

	// Initialize data model
	n.dataModel = datamodel.NewNode()
	n.dispatcher = newNodeDispatcher(n.dataModel)

	// Load persisted state
	if err := n.loadState(); err != nil {
		return nil, err
	}

	// Initialize managers
	if err := n.initManagers(); err != nil {
		return nil, err
	}

	// Create root endpoint (pass dataModel so descriptor cluster can query endpoints)
	rootEP := createRootEndpoint(&config, n.fabricTable, n.dataModel)
	n.endpoints[RootEndpointID] = rootEP
	n.dataModel.AddEndpoint(rootEP.Inner())

	// Generate PASE verifier from passcode
	if err := n.initPASE(); err != nil {
		return nil, err
	}

	n.state = NodeStateInitialized
	return n, nil
}

// loadState loads persisted state from storage.
func (n *Node) loadState() error {
	// Load fabrics
	fabrics, err := n.config.Storage.LoadFabrics()
	if err != nil {
		return err
	}

	// Create fabric table
	n.fabricTable = fabric.NewTable(fabric.TableConfig{})
	for _, f := range fabrics {
		if err := n.fabricTable.Add(f); err != nil {
			return err
		}
	}

	// Load ACLs
	acls, err := n.config.Storage.LoadACLs()
	if err != nil {
		return err
	}

	// Create ACL store and populate with loaded entries
	store := acl.NewMemoryStore()
	for _, entry := range acls {
		// Store entries by fabric
		store.Save(fabric.FabricIndex(entry.FabricIndex), *entry)
	}

	// Create ACL manager with null device type resolver
	n.aclMgr = acl.NewManager(store, acl.NullDeviceTypeResolver{})

	// Load counters
	counters, err := n.config.Storage.LoadCounters()
	if err != nil {
		return err
	}

	// Initialize message counter if needed
	if counters.LocalCounter == 0 {
		// Generate random initial counter per Spec 4.6.1.1
		var buf [4]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return err
		}
		counters.LocalCounter = binary.LittleEndian.Uint32(buf[:])
	}

	return nil
}

// initManagers initializes the internal managers.
func (n *Node) initManagers() error {
	// Session manager
	n.sessionMgr = session.NewManager(session.ManagerConfig{})

	// Transport manager will be started in Start()
	// Exchange manager depends on transport and session

	return nil
}

// initPASE generates PASE parameters from the passcode.
func (n *Node) initPASE() error {
	// Generate random salt (32 bytes per spec)
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	// Default iterations (per spec minimum is 1000)
	iterations := uint32(1000)

	// Generate verifier
	verifier, err := pase.GenerateVerifier(n.config.Passcode, salt, iterations)
	if err != nil {
		return err
	}

	n.paseInfo = &paseInfo{
		verifier:   verifier,
		salt:       salt,
		iterations: iterations,
	}

	return nil
}

// Start initializes the network stack and begins operation.
// For uncommissioned devices, this enables commissioning discovery.
// For commissioned devices, this enables operational discovery.
func (n *Node) Start(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.state.CanStart() {
		if n.state.IsRunning() {
			return ErrAlreadyStarted
		}
		return ErrNotInitialized
	}

	n.state = NodeStateStarting

	// Create context for background operations
	n.ctx, n.cancel = context.WithCancel(ctx)

	// Start transport
	if err := n.startTransport(); err != nil {
		n.state = NodeStateInitialized
		return err
	}

	// Start exchange manager
	if err := n.startExchange(); err != nil {
		n.stopTransport()
		n.state = NodeStateInitialized
		return err
	}

	// Register protocol handlers
	n.registerProtocols()

	// Start discovery
	if err := n.startDiscovery(); err != nil {
		n.stopExchange()
		n.stopTransport()
		n.state = NodeStateInitialized
		return err
	}

	// Update state based on commissioning status
	if n.fabricTable.Count() > 0 {
		n.state = NodeStateCommissioned
		n.advertiseOperational()
	} else {
		n.state = NodeStateUncommissioned
		// Auto-open commissioning window for uncommissioned devices
		n.openCommissioningWindowLocked(3 * time.Minute)
	}

	if n.log != nil {
		n.log.Infof("node started, state=%s", n.state)
	}

	// Notify callback
	if n.config.OnStateChanged != nil {
		n.config.OnStateChanged(n.state)
	}

	return nil
}

// startTransport initializes the transport layer.
func (n *Node) startTransport() error {
	var udpConn net.PacketConn
	var tcpListener net.Listener
	var err error

	if n.config.TransportFactory != nil {
		// Use injected transport (for testing)
		udpConn, err = n.config.TransportFactory.CreateUDPConn(n.config.Port)
		if err != nil {
			return err
		}
		tcpListener, err = n.config.TransportFactory.CreateTCPListener(n.config.Port)
		if err != nil {
			return err
		}
	}

	// Create message handler that routes to exchange manager
	handler := func(msg *transport.ReceivedMessage) {
		if n.exchangeMgr != nil {
			n.exchangeMgr.OnMessageReceived(msg)
		}
	}

	// Create transport manager
	n.transportMgr, err = transport.NewManager(transport.ManagerConfig{
		Port:           n.config.Port,
		UDPEnabled:     true,
		TCPEnabled:     true,
		UDPConn:        udpConn,
		TCPListener:    tcpListener,
		MessageHandler: handler,
		LoggerFactory:  n.config.LoggerFactory,
	})
	if err != nil {
		return err
	}

	// Start transport
	return n.transportMgr.Start()
}

// stopTransport shuts down the transport layer.
func (n *Node) stopTransport() {
	if n.transportMgr != nil {
		n.transportMgr.Stop()
	}
}

// startExchange initializes the exchange layer.
func (n *Node) startExchange() error {
	n.exchangeMgr = exchange.NewManager(exchange.ManagerConfig{
		SessionManager:   n.sessionMgr,
		TransportManager: n.transportMgr,
		LoggerFactory:    n.config.LoggerFactory,
	})
	return nil
}

// stopExchange shuts down the exchange layer.
func (n *Node) stopExchange() {
	if n.exchangeMgr != nil {
		n.exchangeMgr.Close()
	}
}

// registerProtocols registers protocol handlers with the exchange manager.
func (n *Node) registerProtocols() {
	// Create secure channel manager
	n.scMgr = securechannel.NewManager(securechannel.ManagerConfig{
		SessionManager: n.sessionMgr,
		FabricTable:    n.fabricTable,
		Callbacks: securechannel.Callbacks{
			OnSessionEstablished: n.onSessionEstablished,
			OnSessionError:       n.onSessionError,
			OnSessionClosed:      n.onSessionClosed,
		},
		LoggerFactory: n.config.LoggerFactory,
	})

	// Create ACL checker for IM
	aclChecker := acl.NewChecker(acl.NullDeviceTypeResolver{})

	// Create IM engine
	n.imEngine = im.NewEngine(im.EngineConfig{
		Dispatcher:    n.dispatcher,
		ACLChecker:    aclChecker,
		LoggerFactory: n.config.LoggerFactory,
	})

	// Register with exchange manager
	n.exchangeMgr.RegisterProtocol(message.ProtocolSecureChannel, newSecureChannelAdapter(n.scMgr))
	n.exchangeMgr.RegisterProtocol(im.ProtocolID, newIMAdapter(n.imEngine))
}

// startDiscovery initializes DNS-SD.
func (n *Node) startDiscovery() error {
	var err error
	n.discoveryMgr, err = discovery.NewManager(discovery.ManagerConfig{
		Port:          n.config.Port,
		LoggerFactory: n.config.LoggerFactory,
	})
	return err
}

// stopDiscovery shuts down DNS-SD.
func (n *Node) stopDiscovery() {
	if n.discoveryMgr != nil {
		n.discoveryMgr.Close()
	}
}

// advertiseOperational starts operational DNS-SD advertisement.
func (n *Node) advertiseOperational() {
	if n.discoveryMgr == nil {
		return
	}

	// Advertise for each fabric
	n.fabricTable.ForEach(func(info *fabric.FabricInfo) error {
		txt := discovery.OperationalTXT{}
		n.discoveryMgr.StartOperational(info.CompressedFabricID, info.NodeID, txt)
		return nil
	})
}

// Stop gracefully shuts down the node.
func (n *Node) Stop() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.state.CanStop() {
		if n.state == NodeStateStopped {
			return ErrAlreadyStopped
		}
		return ErrNotStarted
	}

	n.state = NodeStateStopping

	// Signal stop
	n.stopOnce.Do(func() {
		close(n.stopCh)
		if n.cancel != nil {
			n.cancel()
		}
	})

	// Close commissioning window if open
	// Set to nil first so callback sees it's already cleaned up
	if n.commWindow != nil {
		cw := n.commWindow
		n.commWindow = nil
		cw.Close()
	}

	// Stop in reverse order
	n.stopDiscovery()
	n.stopExchange()
	n.stopTransport()

	// Persist state
	n.saveState()

	n.state = NodeStateStopped

	if n.log != nil {
		n.log.Info("node stopped")
	}

	if n.config.OnStateChanged != nil {
		n.config.OnStateChanged(n.state)
	}

	return nil
}

// saveState persists current state to storage.
func (n *Node) saveState() {
	// Save counters
	counters := NewCounterState()
	// TODO: Get counter from message layer
	n.config.Storage.SaveCounters(counters)
}

// State returns the current node state.
func (n *Node) State() NodeState {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.state
}

// AddEndpoint registers an endpoint with the node.
// The Root Endpoint (0) is created automatically and cannot be added manually.
func (n *Node) AddEndpoint(ep *Endpoint) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if ep.ID() == RootEndpointID {
		return ErrRootEndpointReserved
	}

	if _, exists := n.endpoints[ep.ID()]; exists {
		return ErrEndpointExists
	}

	// Ensure endpoint has a descriptor cluster
	updateEndpointDescriptor(ep, n.dataModel)

	n.endpoints[ep.ID()] = ep
	n.dataModel.AddEndpoint(ep.Inner())

	// Update root endpoint's descriptor
	endpoints := make([]*Endpoint, 0, len(n.endpoints))
	for _, e := range n.endpoints {
		endpoints = append(endpoints, e)
	}
	updateDescriptorCluster(n.dataModel, endpoints)

	return nil
}

// RemoveEndpoint removes an endpoint by ID.
func (n *Node) RemoveEndpoint(id datamodel.EndpointID) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if id == RootEndpointID {
		return ErrRootEndpointReserved
	}

	if _, exists := n.endpoints[id]; !exists {
		return ErrEndpointNotFound
	}

	delete(n.endpoints, id)
	n.dataModel.RemoveEndpoint(id)

	// Update root endpoint's descriptor
	endpoints := make([]*Endpoint, 0, len(n.endpoints))
	for _, e := range n.endpoints {
		endpoints = append(endpoints, e)
	}
	updateDescriptorCluster(n.dataModel, endpoints)

	return nil
}

// GetEndpoint returns an endpoint by ID, or nil if not found.
func (n *Node) GetEndpoint(id datamodel.EndpointID) *Endpoint {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.endpoints[id]
}

// IsCommissioned returns true if the node is commissioned to at least one fabric.
func (n *Node) IsCommissioned() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.fabricTable.Count() > 0
}

// Fabrics returns all fabrics the node is commissioned to.
func (n *Node) Fabrics() []*fabric.FabricInfo {
	n.mu.RLock()
	defer n.mu.RUnlock()

	var result []*fabric.FabricInfo
	n.fabricTable.ForEach(func(info *fabric.FabricInfo) error {
		result = append(result, info.Clone())
		return nil
	})
	return result
}

// SessionManager returns the node's session manager.
// Exposed for testing and advanced use cases.
func (n *Node) SessionManager() *session.Manager {
	return n.sessionMgr
}

// SecureChannelManager returns the node's secure channel manager.
// Exposed for testing and advanced use cases.
func (n *Node) SecureChannelManager() *securechannel.Manager {
	return n.scMgr
}

// ExchangeManager returns the node's exchange manager.
// Exposed for testing and advanced use cases.
func (n *Node) ExchangeManager() *exchange.Manager {
	return n.exchangeMgr
}

// TransportManager returns the node's transport manager.
// Exposed for testing and advanced use cases.
func (n *Node) TransportManager() *transport.Manager {
	return n.transportMgr
}

// LoggerFactory returns the node's logger factory.
// Returns nil if no logger factory was configured.
func (n *Node) LoggerFactory() logging.LoggerFactory {
	return n.config.LoggerFactory
}

// RemoveFabric removes the node from a fabric.
func (n *Node) RemoveFabric(index fabric.FabricIndex) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if err := n.fabricTable.Remove(index); err != nil {
		return ErrFabricNotFound
	}

	// Remove from storage
	n.config.Storage.DeleteFabric(index)

	// Update state if no fabrics remain
	if n.fabricTable.Count() == 0 && n.state == NodeStateCommissioned {
		n.state = NodeStateUncommissioned
		if n.config.OnStateChanged != nil {
			n.config.OnStateChanged(n.state)
		}
	}

	return nil
}

// Session callbacks

func (n *Node) onSessionEstablished(ctx *session.SecureContext) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Notify commissioning window if PASE session
	if ctx.SessionType() == session.SessionTypePASE && n.commWindow != nil {
		n.commWindow.OnPASEComplete(ctx)
	}

	if n.config.OnSessionEstablished != nil {
		n.config.OnSessionEstablished(ctx.LocalSessionID(), ctx.SessionType())
	}
}

func (n *Node) onSessionError(err error, stage string) {
	if n.log != nil {
		n.log.Warnf("session error at %s: %v", stage, err)
	}
}

func (n *Node) onSessionClosed(localSessionID uint16) {
	if n.config.OnSessionClosed != nil {
		n.config.OnSessionClosed(localSessionID)
	}
}
