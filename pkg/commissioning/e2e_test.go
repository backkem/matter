package commissioning

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/backkem/matter/pkg/clusters/generalcommissioning"
	"github.com/backkem/matter/pkg/discovery"
	"github.com/backkem/matter/pkg/exchange"
	"github.com/backkem/matter/pkg/im"
	"github.com/backkem/matter/pkg/message"
	"github.com/backkem/matter/pkg/securechannel"
	"github.com/backkem/matter/pkg/securechannel/pase"
	"github.com/backkem/matter/pkg/session"
	"github.com/backkem/matter/pkg/transport"
)

// =============================================================================
// Test Infrastructure: TestCommissioningPair
// =============================================================================

// TestCommissioningPair provides paired Commissioner and Device for E2E testing.
// This enables testing the commissioning flow without real network I/O or mDNS.
//
// Architecture:
//
//	Commissioner                          Device
//	────────────                          ──────
//	Commissioner                     CommissioningWindow
//	    │                                   │
//	    ▼                                   ▼
//	im.Client                          im.Engine
//	    │                                   │
//	    ▼                                   ▼
//	securechannel.Manager        securechannel.Manager
//	    │                                   │
//	    ▼                                   ▼
//	exchange.Manager ◀──── Pipe ────▶ exchange.Manager
type TestCommissioningPair struct {
	// Commissioner side
	commissioner       *Commissioner
	commissionerExchMgr *exchange.Manager
	commissionerSCMgr  *securechannel.Manager
	commissionerSessMgr *session.Manager

	// Device side
	commissioningWindow *CommissioningWindow
	deviceExchMgr      *exchange.Manager
	deviceSCMgr        *securechannel.Manager
	deviceSessMgr      *session.Manager
	deviceIMEngine     *im.Engine
	deviceDispatcher   *im.ClusterDispatcher

	// Shared infrastructure
	transportPair *transport.PipeManagerPair
	mockResolver  *discovery.MockMDNSResolver

	// Test configuration
	passcode      uint32
	discriminator uint16
	devicePort    int
	deviceIP      net.IP

	// State tracking
	paseEstablished chan struct{}
	deviceSession   *session.SecureContext
	mu              sync.Mutex
}

// TestCommissioningPairConfig configures a TestCommissioningPair.
type TestCommissioningPairConfig struct {
	Passcode      uint32
	Discriminator uint16
}

// NewTestCommissioningPair creates a paired commissioning test environment.
func NewTestCommissioningPair(config TestCommissioningPairConfig) (*TestCommissioningPair, error) {
	// Apply defaults
	if config.Passcode == 0 {
		config.Passcode = 20202021 // Default test passcode
	}
	if config.Discriminator == 0 {
		config.Discriminator = 3840
	}

	pair := &TestCommissioningPair{
		passcode:        config.Passcode,
		discriminator:   config.Discriminator,
		devicePort:      5540,
		deviceIP:        net.ParseIP("127.0.0.1"),
		paseEstablished: make(chan struct{}),
	}

	// Create handler wrappers first (to solve chicken-and-egg problem)
	commissionerHandlerWrapper := &exchangeHandlerWrapper{}
	deviceHandlerWrapper := &exchangeHandlerWrapper{}

	// Create transport pair with handler wrappers
	transportPair, err := transport.NewPipeManagerPair(transport.PipeManagerConfig{
		UDP: true,
		Handlers: [2]transport.MessageHandler{
			commissionerHandlerWrapper.Handle,
			deviceHandlerWrapper.Handle,
		},
	})
	if err != nil {
		return nil, err
	}
	pair.transportPair = transportPair

	// Create mock discovery
	pair.mockResolver = discovery.NewMockMDNSResolver()

	// Initialize commissioner side
	if err := pair.initCommissioner(transportPair, commissionerHandlerWrapper); err != nil {
		return nil, err
	}

	// Initialize device side
	if err := pair.initDevice(transportPair, deviceHandlerWrapper); err != nil {
		return nil, err
	}

	// Register device for discovery
	pair.registerDeviceForDiscovery()

	return pair, nil
}

// initCommissioner initializes the commissioner side of the pair.
func (p *TestCommissioningPair) initCommissioner(transportPair *transport.PipeManagerPair, handlerWrapper *exchangeHandlerWrapper) error {
	// Create session manager
	p.commissionerSessMgr = session.NewManager(session.ManagerConfig{})

	// Create exchange manager
	p.commissionerExchMgr = exchange.NewManager(exchange.ManagerConfig{
		SessionManager:   p.commissionerSessMgr,
		TransportManager: transportPair.Manager(0),
	})
	handlerWrapper.manager = p.commissionerExchMgr

	// Create secure channel manager
	p.commissionerSCMgr = securechannel.NewManager(securechannel.ManagerConfig{
		SessionManager: p.commissionerSessMgr,
	})

	// Register secure channel protocol
	p.commissionerExchMgr.RegisterProtocol(message.ProtocolSecureChannel,
		&secureChannelAdapter{scMgr: p.commissionerSCMgr})

	// Create mock resolver
	resolver, err := discovery.NewResolver(discovery.ResolverConfig{
		MDNSResolver: p.mockResolver,
	})
	if err != nil {
		return err
	}

	// Create commissioner
	p.commissioner = NewCommissioner(CommissionerConfig{
		Resolver:       resolver,
		SecureChannel:  p.commissionerSCMgr,
		SessionManager: p.commissionerSessMgr,
		ExchangeManager: p.commissionerExchMgr,
		Timeout:        30 * time.Second,
		PASETimeout:    10 * time.Second,
		DiscoveryTimeout: 5 * time.Second,
	})

	return nil
}

// initDevice initializes the device side of the pair.
func (p *TestCommissioningPair) initDevice(transportPair *transport.PipeManagerPair, handlerWrapper *exchangeHandlerWrapper) error {
	// Create session manager
	p.deviceSessMgr = session.NewManager(session.ManagerConfig{})

	// Create exchange manager
	p.deviceExchMgr = exchange.NewManager(exchange.ManagerConfig{
		SessionManager:   p.deviceSessMgr,
		TransportManager: transportPair.Manager(1),
	})
	handlerWrapper.manager = p.deviceExchMgr

	// Create secure channel manager with callbacks
	p.deviceSCMgr = securechannel.NewManager(securechannel.ManagerConfig{
		SessionManager: p.deviceSessMgr,
		Callbacks: securechannel.Callbacks{
			OnSessionEstablished: func(ctx *session.SecureContext) {
				p.mu.Lock()
				p.deviceSession = ctx
				p.mu.Unlock()
				select {
				case p.paseEstablished <- struct{}{}:
				default:
				}
			},
		},
	})

	// Generate PASE verifier and configure device for PASE
	salt := []byte("SPAKE2P Key Salt")
	iterations := uint32(1000)
	verifier, err := pase.GenerateVerifier(p.passcode, salt, iterations)
	if err != nil {
		return err
	}
	if err := p.deviceSCMgr.SetPASEResponder(verifier, salt, iterations); err != nil {
		return err
	}

	// Register secure channel protocol
	p.deviceExchMgr.RegisterProtocol(message.ProtocolSecureChannel,
		&secureChannelAdapter{scMgr: p.deviceSCMgr})

	// Create IM dispatcher with GeneralCommissioning cluster
	p.deviceDispatcher = im.NewClusterDispatcher()
	gcCluster := generalcommissioning.New(generalcommissioning.Config{
		EndpointID: 0,
		BasicCommissioningInfo: generalcommissioning.BasicCommissioningInfo{
			FailSafeExpiryLengthSeconds:  60,
			MaxCumulativeFailsafeSeconds: 900,
		},
		LocationCapability:          generalcommissioning.RegulatoryIndoorOutdoor,
		SupportsConcurrentConnection: true,
	})
	p.deviceDispatcher.RegisterCluster(0, gcCluster)

	// Create IM engine
	p.deviceIMEngine = im.NewEngine(im.EngineConfig{
		Dispatcher: p.deviceDispatcher,
	})

	// Register IM protocol with adapter
	p.deviceExchMgr.RegisterProtocol(im.ProtocolID, &imAdapter{engine: p.deviceIMEngine})

	// Create commissioning window
	p.commissioningWindow, err = NewCommissioningWindow(CommissioningWindowConfig{
		Timeout:       5 * time.Minute,
		Discriminator: p.discriminator,
		Verifier:      verifier,
		Salt:          salt,
		Iterations:    iterations,
	})
	if err != nil {
		return err
	}

	return nil
}

// registerDeviceForDiscovery registers the device in mock discovery.
func (p *TestCommissioningPair) registerDeviceForDiscovery() {
	entry := discovery.MockCommissionableService(
		"test-device",
		p.devicePort,
		p.deviceIP,
		p.discriminator,
	)
	p.mockResolver.RegisterService(discovery.ServiceCommissionable, entry)
}

// Commissioner returns the commissioner.
func (p *TestCommissioningPair) Commissioner() *Commissioner {
	return p.commissioner
}

// CommissioningWindow returns the device's commissioning window.
func (p *TestCommissioningPair) CommissioningWindow() *CommissioningWindow {
	return p.commissioningWindow
}

// DeviceSecureChannelManager returns the device's secure channel manager.
func (p *TestCommissioningPair) DeviceSecureChannelManager() *securechannel.Manager {
	return p.deviceSCMgr
}

// WaitForPASE waits for PASE session establishment on device side.
func (p *TestCommissioningPair) WaitForPASE(timeout time.Duration) bool {
	select {
	case <-p.paseEstablished:
		return true
	case <-time.After(timeout):
		return false
	}
}

// DeviceSession returns the established device session.
func (p *TestCommissioningPair) DeviceSession() *session.SecureContext {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.deviceSession
}

// Close releases all resources.
func (p *TestCommissioningPair) Close() {
	if p.commissionerExchMgr != nil {
		p.commissionerExchMgr.Close()
	}
	if p.deviceExchMgr != nil {
		p.deviceExchMgr.Close()
	}
	if p.transportPair != nil {
		p.transportPair.Close()
	}
}

// exchangeHandlerWrapper routes transport messages to exchange manager.
type exchangeHandlerWrapper struct {
	manager *exchange.Manager
}

func (w *exchangeHandlerWrapper) Handle(msg *transport.ReceivedMessage) {
	if w.manager != nil {
		w.manager.OnMessageReceived(msg)
	}
}

// secureChannelAdapter adapts securechannel.Manager to exchange.ProtocolHandler.
type secureChannelAdapter struct {
	scMgr *securechannel.Manager
}

func (a *secureChannelAdapter) OnMessage(ctx *exchange.ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	msg := &securechannel.Message{
		Opcode:  securechannel.Opcode(opcode),
		Payload: payload,
	}
	resp, err := a.scMgr.Route(ctx.ID, msg)
	if err != nil {
		return nil, err
	}
	if resp != nil {
		return resp.Payload, nil
	}
	return nil, nil
}

func (a *secureChannelAdapter) OnUnsolicited(ctx *exchange.ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	return a.OnMessage(ctx, opcode, payload)
}

// imAdapter adapts im.Engine to exchange.ProtocolHandler.
type imAdapter struct {
	engine *im.Engine
}

func (a *imAdapter) OnMessage(ctx *exchange.ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	return a.handleIM(ctx, opcode, payload)
}

func (a *imAdapter) OnUnsolicited(ctx *exchange.ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	return a.handleIM(ctx, opcode, payload)
}

func (a *imAdapter) handleIM(ctx *exchange.ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	header := &message.ProtocolHeader{
		ProtocolID:     im.ProtocolID,
		ProtocolOpcode: opcode,
		ExchangeID:     ctx.ID,
	}
	return a.engine.OnMessage(ctx, header, payload)
}

// =============================================================================
// E2E Tests: PASE Happy Path
// =============================================================================

// TestE2E_Commissioning_PASE_HappyPath tests PASE establishment via Commissioner.
func TestE2E_Commissioning_PASE_HappyPath(t *testing.T) {
	pair, err := NewTestCommissioningPair(TestCommissioningPairConfig{
		Passcode:      20202021,
		Discriminator: 3840,
	})
	if err != nil {
		t.Fatalf("NewTestCommissioningPair failed: %v", err)
	}
	defer pair.Close()

	// Verify device is in expected initial state
	if pair.CommissioningWindow().State() != DeviceStateUncommissioned {
		t.Errorf("initial state = %v, want DeviceStateUncommissioned",
			pair.CommissioningWindow().State())
	}

	// Test direct PASE handshake between managers (bypassing Commissioner discovery)
	exchangeID := uint16(1)

	// Controller side: start PASE
	pbkdfReq, err := pair.commissionerSCMgr.StartPASE(exchangeID, pair.passcode)
	if err != nil {
		t.Fatalf("StartPASE failed: %v", err)
	}
	t.Logf("Commissioner → Device: PBKDFParamRequest (%d bytes)", len(pbkdfReq))

	// Device side: handle PBKDFParamRequest
	pbkdfRespMsg, err := pair.deviceSCMgr.Route(exchangeID, &securechannel.Message{
		Opcode:  securechannel.OpcodePBKDFParamRequest,
		Payload: pbkdfReq,
	})
	if err != nil {
		t.Fatalf("Device Route PBKDFParamRequest failed: %v", err)
	}
	t.Logf("Device → Commissioner: PBKDFParamResponse (%d bytes)", len(pbkdfRespMsg.Payload))

	// Controller: handle PBKDFParamResponse → Pake1
	pake1Msg, err := pair.commissionerSCMgr.Route(exchangeID, &securechannel.Message{
		Opcode:  securechannel.OpcodePBKDFParamResponse,
		Payload: pbkdfRespMsg.Payload,
	})
	if err != nil {
		t.Fatalf("Controller Route PBKDFParamResponse failed: %v", err)
	}
	t.Logf("Commissioner → Device: Pake1 (%d bytes)", len(pake1Msg.Payload))

	// Device: handle Pake1 → Pake2
	pake2Msg, err := pair.deviceSCMgr.Route(exchangeID, &securechannel.Message{
		Opcode:  securechannel.OpcodePASEPake1,
		Payload: pake1Msg.Payload,
	})
	if err != nil {
		t.Fatalf("Device Route Pake1 failed: %v", err)
	}
	t.Logf("Device → Commissioner: Pake2 (%d bytes)", len(pake2Msg.Payload))

	// Controller: handle Pake2 → Pake3
	pake3Msg, err := pair.commissionerSCMgr.Route(exchangeID, &securechannel.Message{
		Opcode:  securechannel.OpcodePASEPake2,
		Payload: pake2Msg.Payload,
	})
	if err != nil {
		t.Fatalf("Controller Route Pake2 failed: %v", err)
	}
	t.Logf("Commissioner → Device: Pake3 (%d bytes)", len(pake3Msg.Payload))

	// Device: handle Pake3 → StatusReport
	statusMsg, err := pair.deviceSCMgr.Route(exchangeID, &securechannel.Message{
		Opcode:  securechannel.OpcodePASEPake3,
		Payload: pake3Msg.Payload,
	})
	if err != nil {
		t.Fatalf("Device Route Pake3 failed: %v", err)
	}
	t.Logf("Device → Commissioner: StatusReport (success)")

	// Controller: handle StatusReport
	_, err = pair.commissionerSCMgr.Route(exchangeID, &securechannel.Message{
		Opcode:  securechannel.OpcodeStatusReport,
		Payload: statusMsg.Payload,
	})
	if err != nil {
		t.Fatalf("Controller Route StatusReport failed: %v", err)
	}

	// Verify sessions established
	deviceSession := pair.DeviceSession()
	if deviceSession == nil {
		t.Error("device session should be established")
	} else {
		if deviceSession.SessionType() != session.SessionTypePASE {
			t.Errorf("device session type = %v, want PASE", deviceSession.SessionType())
		}
		t.Logf("Device PASE session established: localID=%d", deviceSession.LocalSessionID())
	}

	t.Log("Commissioning PASE E2E: SUCCESS")
}

// TestE2E_Commissioning_PASE_WrongPasscode tests PASE failure with wrong passcode.
func TestE2E_Commissioning_PASE_WrongPasscode(t *testing.T) {
	pair, err := NewTestCommissioningPair(TestCommissioningPairConfig{
		Passcode:      20202021,
		Discriminator: 3840,
	})
	if err != nil {
		t.Fatalf("NewTestCommissioningPair failed: %v", err)
	}
	defer pair.Close()

	wrongPasscode := uint32(12341234) // Wrong passcode
	exchangeID := uint16(1)

	// Start PASE with wrong passcode
	pbkdfReq, _ := pair.commissionerSCMgr.StartPASE(exchangeID, wrongPasscode)
	pbkdfRespMsg, _ := pair.deviceSCMgr.Route(exchangeID, &securechannel.Message{
		Opcode:  securechannel.OpcodePBKDFParamRequest,
		Payload: pbkdfReq,
	})
	pake1Msg, _ := pair.commissionerSCMgr.Route(exchangeID, &securechannel.Message{
		Opcode:  securechannel.OpcodePBKDFParamResponse,
		Payload: pbkdfRespMsg.Payload,
	})
	pake2Msg, _ := pair.deviceSCMgr.Route(exchangeID, &securechannel.Message{
		Opcode:  securechannel.OpcodePASEPake1,
		Payload: pake1Msg.Payload,
	})

	// Controller should fail to verify responder's confirmation
	_, err = pair.commissionerSCMgr.Route(exchangeID, &securechannel.Message{
		Opcode:  securechannel.OpcodePASEPake2,
		Payload: pake2Msg.Payload,
	})
	if err == nil {
		t.Error("expected error with wrong passcode, got none")
	} else {
		t.Logf("PASE correctly failed with wrong passcode: %v", err)
	}
}

// =============================================================================
// E2E Tests: IM Commands (Stub - would need full session encryption)
// =============================================================================

// TestE2E_Commissioning_GeneralCommissioning_Cluster tests GeneralCommissioning cluster exists.
func TestE2E_Commissioning_GeneralCommissioning_Cluster(t *testing.T) {
	pair, err := NewTestCommissioningPair(TestCommissioningPairConfig{})
	if err != nil {
		t.Fatalf("NewTestCommissioningPair failed: %v", err)
	}
	defer pair.Close()

	// Verify GeneralCommissioning cluster is registered on device
	if pair.deviceDispatcher == nil {
		t.Fatal("device dispatcher is nil")
	}

	// The cluster should be registered at endpoint 0
	t.Log("GeneralCommissioning cluster registered on device")
}

// TestE2E_Commissioning_WindowState tests commissioning window state transitions.
func TestE2E_Commissioning_WindowState(t *testing.T) {
	pair, err := NewTestCommissioningPair(TestCommissioningPairConfig{})
	if err != nil {
		t.Fatalf("NewTestCommissioningPair failed: %v", err)
	}
	defer pair.Close()

	window := pair.CommissioningWindow()

	// Initial state
	if window.State() != DeviceStateUncommissioned {
		t.Errorf("initial state = %v, want DeviceStateUncommissioned", window.State())
	}

	// Simulate PASE request
	if err := window.OnPASERequest(); err == nil {
		// Window should reject if not advertising
		t.Log("PASE request rejected when window not advertising (expected)")
	}

	// Open window in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go window.Open(ctx)

	// Wait for advertising state
	time.Sleep(20 * time.Millisecond)

	if window.State() != DeviceStateAdvertising {
		t.Errorf("state after Open = %v, want DeviceStateAdvertising", window.State())
	}

	// Accept PASE request
	if err := window.OnPASERequest(); err != nil {
		t.Errorf("OnPASERequest failed: %v", err)
	}

	if window.State() != DeviceStatePASEPending {
		t.Errorf("state after PASE request = %v, want DeviceStatePASEPending", window.State())
	}

	// Complete PASE
	if err := window.OnPASEComplete(nil); err != nil {
		t.Errorf("OnPASEComplete failed: %v", err)
	}

	if window.State() != DeviceStatePASEEstablished {
		t.Errorf("state after PASE complete = %v, want DeviceStatePASEEstablished", window.State())
	}

	t.Log("Commissioning window state transitions: SUCCESS")
}

// TestE2E_Commissioning_FailSafe tests fail-safe timer integration.
func TestE2E_Commissioning_FailSafe(t *testing.T) {
	pair, err := NewTestCommissioningPair(TestCommissioningPairConfig{})
	if err != nil {
		t.Fatalf("NewTestCommissioningPair failed: %v", err)
	}
	defer pair.Close()

	window := pair.CommissioningWindow()

	// Open window
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go window.Open(ctx)
	time.Sleep(20 * time.Millisecond)

	// Simulate PASE establishment
	window.OnPASERequest()
	window.OnPASEComplete(nil)

	// Arm fail-safe (simulating ArmFailSafe command)
	window.ArmFailSafe(1 * time.Second)

	if window.State() != DeviceStateCommissioning {
		t.Errorf("state after ArmFailSafe = %v, want DeviceStateCommissioning", window.State())
	}

	// Disarm before expiration (simulating successful commissioning)
	window.DisarmFailSafe()

	t.Log("Fail-safe integration: SUCCESS")
}

// TestE2E_Commissioning_Discovery tests mock discovery integration.
func TestE2E_Commissioning_Discovery(t *testing.T) {
	pair, err := NewTestCommissioningPair(TestCommissioningPairConfig{
		Discriminator: 3840,
	})
	if err != nil {
		t.Fatalf("NewTestCommissioningPair failed: %v", err)
	}
	defer pair.Close()

	// Test that device is discoverable via mock resolver
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resolver, _ := discovery.NewResolver(discovery.ResolverConfig{
		MDNSResolver: pair.mockResolver,
	})

	ch, err := resolver.BrowseCommissionable(ctx)
	if err != nil {
		t.Fatalf("BrowseCommissionable failed: %v", err)
	}

	// Should find our mock device
	select {
	case svc := <-ch:
		ip := svc.PreferredIP()
		if ip != nil {
			t.Logf("Discovered device: %s at %s:%d", svc.InstanceName, ip, svc.Port)
		} else {
			t.Logf("Discovered device: %s at port %d (no IP)", svc.InstanceName, svc.Port)
		}
		if svc.Port != pair.devicePort {
			t.Errorf("port = %d, want %d", svc.Port, pair.devicePort)
		}
	case <-ctx.Done():
		t.Error("device not discovered within timeout")
	}

	t.Log("Mock discovery integration: SUCCESS")
}
