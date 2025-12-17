package transport

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/pion/transport/v3/test"
)

// Factory creates transport connections.
// Implementations can provide real network connections or virtual pipes for testing.
type Factory interface {
	// CreateUDPConn creates a UDP-like packet connection.
	// The port parameter is used for address assignment.
	CreateUDPConn(port int) (net.PacketConn, error)

	// CreateTCPListener creates a TCP-like listener.
	// The port parameter is used for address assignment.
	// Returns nil if TCP is not supported.
	CreateTCPListener(port int) (net.Listener, error)
}

// NetworkCondition configures network behavior simulation.
// Use this to test protocol behavior under adverse network conditions.
type NetworkCondition struct {
	// DropRate is the probability of dropping a packet (0.0 - 1.0).
	DropRate float64

	// DelayMin is the minimum delay to add to each packet.
	DelayMin time.Duration

	// DelayMax is the maximum delay to add to each packet.
	// Actual delay is uniformly distributed between DelayMin and DelayMax.
	DelayMax time.Duration

	// DuplicateRate is the probability of duplicating a packet (0.0 - 1.0).
	DuplicateRate float64

	// ReorderRate is the probability of reordering packets (0.0 - 1.0).
	// When triggered, the packet is delayed by an additional ReorderDelay.
	ReorderRate float64

	// ReorderDelay is the additional delay for reordered packets.
	ReorderDelay time.Duration
}

// PipeConfig configures a Pipe.
type PipeConfig struct {
	// AutoProcess enables automatic message delivery in a background goroutine.
	// Default: true
	AutoProcess bool

	// ProcessInterval is how often the auto-processor checks for messages.
	// Default: 1ms
	ProcessInterval time.Duration
}

// DefaultPipeConfig returns the default pipe configuration.
func DefaultPipeConfig() PipeConfig {
	return PipeConfig{
		AutoProcess:     true,
		ProcessInterval: 1 * time.Millisecond,
	}
}

// Pipe provides bidirectional in-memory packet communication between two endpoints.
// It wraps pion's test.Bridge and adds network condition simulation.
//
// By default, Pipe automatically delivers messages in a background goroutine.
// Use SetAutoProcess(false) or NewPipeWithConfig for manual control.
//
// This follows the "Virtual Network" testing pattern from docs/style.md.
// Use Pipe for deterministic, flaky-free tests without real network I/O.
type Pipe struct {
	bridge *test.Bridge

	mu              sync.RWMutex
	condition       NetworkCondition
	closed          bool
	rng             *rand.Rand
	autoProcess     bool
	processInterval time.Duration
	stopCh          chan struct{}
	wg              sync.WaitGroup
}

// NewPipe creates a new bidirectional pipe with auto-processing enabled.
// Messages are automatically delivered in a background goroutine.
func NewPipe() *Pipe {
	return NewPipeWithConfig(DefaultPipeConfig())
}

// NewPipeWithConfig creates a new pipe with the given configuration.
func NewPipeWithConfig(config PipeConfig) *Pipe {
	p := &Pipe{
		bridge:          test.NewBridge(),
		rng:             rand.New(rand.NewSource(time.Now().UnixNano())),
		autoProcess:     config.AutoProcess,
		processInterval: config.ProcessInterval,
		stopCh:          make(chan struct{}),
	}

	if config.ProcessInterval == 0 {
		p.processInterval = 1 * time.Millisecond
	}

	if p.autoProcess {
		p.startAutoProcess()
	}

	return p
}

// startAutoProcess starts the background message delivery goroutine.
func (p *Pipe) startAutoProcess() {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ticker := time.NewTicker(p.processInterval)
		defer ticker.Stop()

		for {
			select {
			case <-p.stopCh:
				return
			case <-ticker.C:
				p.bridge.Tick()
			}
		}
	}()
}

// SetAutoProcess enables or disables automatic message delivery.
// When disabled, you must call Tick() or Process() manually.
// This is useful for deterministic testing of specific packet orderings.
func (p *Pipe) SetAutoProcess(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}

	if p.autoProcess == enabled {
		return
	}

	p.autoProcess = enabled

	if enabled {
		// Start the goroutine
		p.stopCh = make(chan struct{})
		p.startAutoProcess()
	} else {
		// Stop the goroutine
		close(p.stopCh)
		p.wg.Wait()
	}
}

// AutoProcess returns whether auto-processing is enabled.
func (p *Pipe) AutoProcess() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.autoProcess
}

// SetCondition configures network condition simulation.
// The conditions apply to packets in both directions.
func (p *Pipe) SetCondition(cond NetworkCondition) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.condition = cond
}

// Condition returns the current network condition configuration.
func (p *Pipe) Condition() NetworkCondition {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.condition
}

// Conn0 returns the connection for endpoint 0.
func (p *Pipe) Conn0() net.Conn {
	return p.bridge.GetConn0()
}

// Conn1 returns the connection for endpoint 1.
func (p *Pipe) Conn1() net.Conn {
	return p.bridge.GetConn1()
}

// Tick delivers one packet in each direction (if available).
// Returns the number of packets delivered (0, 1, or 2).
//
// Note: When AutoProcess is enabled (default), you typically don't need
// to call this manually. Use SetAutoProcess(false) for manual control.
func (p *Pipe) Tick() int {
	return p.bridge.Tick()
}

// Process delivers all queued packets.
// Returns the number of packets delivered.
//
// Note: When AutoProcess is enabled (default), you typically don't need
// to call this manually. Use SetAutoProcess(false) for manual control.
func (p *Pipe) Process() int {
	count := 0
	for {
		n := p.Tick()
		if n == 0 {
			break
		}
		count += n
	}
	return count
}

// Close closes both endpoints of the pipe and stops auto-processing.
func (p *Pipe) Close() error {
	p.mu.Lock()

	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true

	// Stop auto-processing
	if p.autoProcess {
		close(p.stopCh)
	}
	p.mu.Unlock()

	// Wait for goroutine outside lock
	p.wg.Wait()

	// Close both connections
	var errs []error
	if err := p.bridge.GetConn0().Close(); err != nil {
		errs = append(errs, err)
	}
	if err := p.bridge.GetConn1().Close(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// PipeAddr implements net.Addr for pipe endpoints.
type PipeAddr struct {
	ID   int // Endpoint ID (0 or 1)
	Port int // Logical port number
}

// Network returns "pipe".
func (a PipeAddr) Network() string { return "pipe" }

// String returns a string representation of the address.
func (a PipeAddr) String() string { return fmt.Sprintf("pipe:%d:%d", a.ID, a.Port) }

// PipePacketConn wraps a Pipe endpoint to implement net.PacketConn.
// This allows pipes to be used with Matter's UDP transport layer.
type PipePacketConn struct {
	conn     net.Conn
	localID  int
	port     int
	peerAddr net.Addr
	pipe     *Pipe
}

// ReadFrom reads a packet from the pipe.
// The returned address is the peer's address.
func (c *PipePacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, err = c.conn.Read(b)
	return n, c.peerAddr, err
}

// WriteTo writes a packet to the pipe.
// The addr parameter is ignored since the pipe has only one peer.
func (c *PipePacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	// Apply network conditions if configured
	if c.pipe != nil {
		c.pipe.mu.RLock()
		cond := c.pipe.condition
		rng := c.pipe.rng
		c.pipe.mu.RUnlock()

		// Check for drop
		if cond.DropRate > 0 && rng.Float64() < cond.DropRate {
			return len(b), nil // Silently drop
		}

		// Apply delay
		if cond.DelayMax > 0 {
			delay := cond.DelayMin
			if cond.DelayMax > cond.DelayMin {
				delay += time.Duration(rng.Int63n(int64(cond.DelayMax - cond.DelayMin)))
			}
			if delay > 0 {
				time.Sleep(delay)
			}
		}

		// Check for duplicate - send twice
		if cond.DuplicateRate > 0 && rng.Float64() < cond.DuplicateRate {
			// Send first copy
			if _, err := c.conn.Write(b); err != nil {
				return 0, err
			}
			// Fall through to send second copy
		}
	}

	return c.conn.Write(b)
}

// Close closes the pipe connection.
func (c *PipePacketConn) Close() error {
	return c.conn.Close()
}

// LocalAddr returns the local address.
func (c *PipePacketConn) LocalAddr() net.Addr {
	return PipeAddr{ID: c.localID, Port: c.port}
}

// SetDeadline sets the read and write deadlines.
func (c *PipePacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (c *PipePacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (c *PipePacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// Verify PipePacketConn implements net.PacketConn.
var _ net.PacketConn = (*PipePacketConn)(nil)

// PipeTCPListener implements net.Listener for pipe-based TCP testing.
// It accepts exactly one connection (the pipe's endpoint), making it suitable
// for point-to-point testing scenarios.
type PipeTCPListener struct {
	localAddr  PipeAddr
	remoteAddr PipeAddr
	conn       net.Conn
	acceptCh   chan struct{}
	closeCh    chan struct{}

	mu       sync.Mutex
	accepted bool
	closed   bool
}

// Accept waits for and returns the next connection to the listener.
// Since a pipe only has two endpoints, Accept will return exactly one
// connection (the peer's endpoint). Subsequent calls block until Close.
func (l *PipeTCPListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, &net.OpError{Op: "accept", Net: "pipe", Addr: l.localAddr, Err: net.ErrClosed}
	}
	if l.accepted {
		l.mu.Unlock()
		// Block until closed - pipe only supports one connection
		<-l.closeCh
		return nil, &net.OpError{Op: "accept", Net: "pipe", Addr: l.localAddr, Err: net.ErrClosed}
	}
	l.accepted = true
	l.mu.Unlock()

	// Return a wrapped connection with proper addresses
	return &PipeTCPConn{
		conn:       l.conn,
		localAddr:  l.localAddr,
		remoteAddr: l.remoteAddr,
	}, nil
}

// Close closes the listener.
func (l *PipeTCPListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}
	l.closed = true
	close(l.closeCh)
	return nil
}

// Addr returns the listener's network address.
func (l *PipeTCPListener) Addr() net.Addr {
	return l.localAddr
}

// Verify PipeTCPListener implements net.Listener.
var _ net.Listener = (*PipeTCPListener)(nil)

// PipeTCPConn wraps a net.Conn with pipe-specific addresses.
// This provides proper LocalAddr and RemoteAddr for pipe-based TCP connections.
type PipeTCPConn struct {
	conn       net.Conn
	localAddr  PipeAddr
	remoteAddr PipeAddr
}

// Read reads data from the connection.
func (c *PipeTCPConn) Read(b []byte) (n int, err error) {
	return c.conn.Read(b)
}

// Write writes data to the connection.
func (c *PipeTCPConn) Write(b []byte) (n int, err error) {
	return c.conn.Write(b)
}

// Close closes the connection.
func (c *PipeTCPConn) Close() error {
	return c.conn.Close()
}

// LocalAddr returns the local network address.
func (c *PipeTCPConn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr returns the remote network address.
func (c *PipeTCPConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// SetDeadline sets the read and write deadlines.
func (c *PipeTCPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (c *PipeTCPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (c *PipeTCPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// Verify PipeTCPConn implements net.Conn.
var _ net.Conn = (*PipeTCPConn)(nil)

// PipeFactory creates transports that use a Pipe for communication.
// Use this for in-memory testing without real network I/O.
//
// By default, messages are automatically delivered in a background goroutine.
// Use Pipe().SetAutoProcess(false) for manual control over message delivery.
type PipeFactory struct {
	mu          sync.Mutex
	peerFactory *PipeFactory
	pipe        *Pipe
	localID     int // 0 or 1
	udpConn     *PipePacketConn
	tcpListener *PipeTCPListener
}

// NewPipeFactoryPair creates a pair of PipeFactory instances
// connected to each other via a Pipe with auto-processing enabled.
//
// Example:
//
//	f0, f1 := transport.NewPipeFactoryPair()
//	// Use f0 for device, f1 for controller
//	// Messages flow automatically - no manual pumping needed!
func NewPipeFactoryPair() (*PipeFactory, *PipeFactory) {
	return NewPipeFactoryPairWithConfig(DefaultPipeConfig())
}

// NewPipeFactoryPairWithConfig creates a pair of PipeFactory instances
// with the given configuration.
//
// For manual message control (deterministic testing):
//
//	f0, f1 := transport.NewPipeFactoryPairWithConfig(transport.PipeConfig{
//	    AutoProcess: false,
//	})
//	// ... do work ...
//	f0.Pipe().Process() // manually deliver messages
func NewPipeFactoryPairWithConfig(config PipeConfig) (*PipeFactory, *PipeFactory) {
	pipe := NewPipeWithConfig(config)

	f0 := &PipeFactory{
		pipe:    pipe,
		localID: 0,
	}
	f1 := &PipeFactory{
		pipe:    pipe,
		localID: 1,
	}
	f0.peerFactory = f1
	f1.peerFactory = f0

	return f0, f1
}

// Pipe returns the underlying pipe for configuration and manual message control.
//
// To disable auto-processing for deterministic tests:
//
//	f.Pipe().SetAutoProcess(false)
//
// To configure network conditions:
//
//	f.Pipe().SetCondition(transport.NetworkCondition{
//	    DropRate: 0.1, // 10% packet loss
//	})
func (f *PipeFactory) Pipe() *Pipe {
	return f.pipe
}

// LocalAddr returns the local address for this side of the pipe.
func (f *PipeFactory) LocalAddr() net.Addr {
	return PipeAddr{ID: f.localID, Port: DefaultPort}
}

// PeerAddr returns the peer address for this side of the pipe.
func (f *PipeFactory) PeerAddr() net.Addr {
	peerID := 1 - f.localID
	return PipeAddr{ID: peerID, Port: DefaultPort}
}

// CreateUDPConn creates a UDP-like connection using the pipe.
func (f *PipeFactory) CreateUDPConn(port int) (net.PacketConn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.udpConn != nil {
		return f.udpConn, nil
	}

	// Get the appropriate connection from the pipe
	var conn net.Conn
	if f.localID == 0 {
		conn = f.pipe.Conn0()
	} else {
		conn = f.pipe.Conn1()
	}

	// Determine peer address
	peerID := 1 - f.localID
	peerAddr := PipeAddr{ID: peerID, Port: port}

	f.udpConn = &PipePacketConn{
		conn:     conn,
		localID:  f.localID,
		port:     port,
		peerAddr: peerAddr,
		pipe:     f.pipe,
	}

	return f.udpConn, nil
}

// CreateTCPListener creates a TCP listener using a pipe.
// The listener will accept exactly one connection (the pipe's endpoint).
// This is suitable for point-to-point testing scenarios.
func (f *PipeFactory) CreateTCPListener(port int) (net.Listener, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.tcpListener != nil {
		return f.tcpListener, nil
	}

	// Get the appropriate connection from the pipe
	var conn net.Conn
	if f.localID == 0 {
		conn = f.pipe.Conn0()
	} else {
		conn = f.pipe.Conn1()
	}

	// Determine peer address
	peerID := 1 - f.localID

	f.tcpListener = &PipeTCPListener{
		localAddr:  PipeAddr{ID: f.localID, Port: port},
		remoteAddr: PipeAddr{ID: peerID, Port: port},
		conn:       conn,
		acceptCh:   make(chan struct{}, 1),
		closeCh:    make(chan struct{}),
	}

	return f.tcpListener, nil
}

// SetCondition configures network condition simulation for this factory's pipe.
func (f *PipeFactory) SetCondition(cond NetworkCondition) {
	f.pipe.SetCondition(cond)
}

// GetTCPClientConn returns a TCP client connection for connecting to the peer's listener.
// This is the counterpart to CreateTCPListener - use it on the "client" side of the pipe.
//
// Example:
//
//	f0, f1 := NewPipeFactoryPair()
//	listener, _ := f0.CreateTCPListener(5540)  // Server side
//	clientConn := f1.GetTCPClientConn(5540)    // Client side
//	serverConn, _ := listener.Accept()
//	// Now clientConn and serverConn are connected via the pipe
func (f *PipeFactory) GetTCPClientConn(port int) net.Conn {
	// Get the appropriate connection from the pipe
	var conn net.Conn
	if f.localID == 0 {
		conn = f.pipe.Conn0()
	} else {
		conn = f.pipe.Conn1()
	}

	// Determine peer address
	peerID := 1 - f.localID

	return &PipeTCPConn{
		conn:       conn,
		localAddr:  PipeAddr{ID: f.localID, Port: port},
		remoteAddr: PipeAddr{ID: peerID, Port: port},
	}
}

// Verify PipeFactory implements Factory.
var _ Factory = (*PipeFactory)(nil)

// PipeManagerConfig configures a PipeManagerPair.
type PipeManagerConfig struct {
	// UDP enables UDP transport (default: true if both UDP and TCP are false).
	UDP bool

	// TCP enables TCP transport (default: true if both UDP and TCP are false).
	TCP bool

	// Handlers are the message handlers for each manager.
	// Handlers[0] is for Manager(0), Handlers[1] is for Manager(1).
	Handlers [2]MessageHandler

	// PipeConfig configures the underlying pipe (optional).
	PipeConfig PipeConfig
}

// PipeAddresses contains the addresses needed to reach a manager over the pipe.
type PipeAddresses struct {
	// UDP is the UDP peer address, or invalid if UDP is not enabled.
	UDP PeerAddress

	// TCP is the TCP peer address, or invalid if TCP is not enabled.
	TCP PeerAddress
}

// PipeManagerPair provides two connected Manager instances for testing.
// Messages sent from one manager arrive at the other via in-memory pipes.
//
// Example:
//
//	pair := transport.NewPipeManagerPair(transport.PipeManagerConfig{
//	    UDP: true,
//	    TCP: true,
//	    Handlers: [2]transport.MessageHandler{handler0, handler1},
//	})
//	defer pair.Close()
//
//	// Send from manager 0 to manager 1
//	pair.Manager(0).Send(data, pair.PeerAddresses(1).UDP)
//
//	// Send from manager 1 to manager 0 over TCP
//	pair.Manager(1).Send(data, pair.PeerAddresses(0).TCP)
type PipeManagerPair struct {
	managers [2]*Manager
	pipe     *Pipe       // for UDP and auto-processing
	tcpPipe  *Pipe       // separate pipe for TCP (stream-based)
	port     int
	udp      bool
	tcp      bool
}

// NewPipeManagerPair creates a pair of connected Manager instances for testing.
// Both managers are started automatically and ready to use.
func NewPipeManagerPair(config PipeManagerConfig) (*PipeManagerPair, error) {
	// Apply defaults
	if !config.UDP && !config.TCP {
		config.UDP = true
		config.TCP = true
	}
	if config.PipeConfig.ProcessInterval == 0 {
		config.PipeConfig = DefaultPipeConfig()
	}

	port := DefaultPort

	pair := &PipeManagerPair{
		port: port,
		udp:  config.UDP,
		tcp:  config.TCP,
	}

	// Create UDP pipe if enabled
	var udpConns [2]net.PacketConn
	if config.UDP {
		pair.pipe = NewPipeWithConfig(config.PipeConfig)
		f0, f1 := newPipeFactoryPairFromPipe(pair.pipe)
		var err error
		udpConns[0], err = f0.CreateUDPConn(port)
		if err != nil {
			pair.pipe.Close()
			return nil, err
		}
		udpConns[1], err = f1.CreateUDPConn(port)
		if err != nil {
			pair.pipe.Close()
			return nil, err
		}
	}

	// Create TCP pipe if enabled (separate pipe for stream semantics)
	// TCP uses a single bidirectional pipe:
	// - mgr0 uses conn0: writes to queue0→1, reads from queue1→0
	// - mgr1 uses conn1: writes to queue1→0, reads from queue0→1
	var tcpListeners [2]net.Listener
	var tcpClientConns [2]net.Conn
	if config.TCP {
		pair.tcpPipe = NewPipeWithConfig(config.PipeConfig)

		// Create dummy listeners to prevent Manager from creating real TCP listeners.
		// We use AddConnection instead for the actual pipe communication.
		tcpListeners[0] = newDummyTCPListener(PipeAddr{ID: 0, Port: port})
		tcpListeners[1] = newDummyTCPListener(PipeAddr{ID: 1, Port: port})

		// Create the actual TCP connections using the pipe.
		// Each manager gets its own side of the pipe:
		// - tcpClientConns[0] wraps conn0, RemoteAddr=pipe:1 (to send TO mgr1)
		// - tcpClientConns[1] wraps conn1, RemoteAddr=pipe:0 (to send TO mgr0)
		tcpClientConns[0] = &PipeTCPConn{
			conn:       pair.tcpPipe.Conn0(),
			localAddr:  PipeAddr{ID: 0, Port: port},
			remoteAddr: PipeAddr{ID: 1, Port: port},
		}
		tcpClientConns[1] = &PipeTCPConn{
			conn:       pair.tcpPipe.Conn1(),
			localAddr:  PipeAddr{ID: 1, Port: port},
			remoteAddr: PipeAddr{ID: 0, Port: port},
		}
	}

	// Create managers
	for i := 0; i < 2; i++ {
		mgr, err := NewManager(ManagerConfig{
			Port:           port,
			UDPEnabled:     config.UDP,
			TCPEnabled:     config.TCP,
			MessageHandler: config.Handlers[i],
			UDPConn:        udpConns[i],
			TCPListener:    tcpListeners[i],
		})
		if err != nil {
			pair.Close()
			return nil, err
		}
		pair.managers[i] = mgr

		// Add TCP pipe connection for communication.
		// This starts a read loop on the connection, enabling bidirectional communication.
		if config.TCP && mgr.TCP() != nil {
			mgr.TCP().AddConnection(tcpClientConns[i])
		}

		// Start the manager
		if err := mgr.Start(); err != nil {
			pair.Close()
			return nil, err
		}
	}

	return pair, nil
}

// dummyTCPListener is a no-op TCP listener that prevents Manager from creating
// real TCP listeners. Accept blocks forever until Close is called.
type dummyTCPListener struct {
	addr    net.Addr
	closeCh chan struct{}
	closed  bool
	mu      sync.Mutex
}

func newDummyTCPListener(addr net.Addr) *dummyTCPListener {
	return &dummyTCPListener{
		addr:    addr,
		closeCh: make(chan struct{}),
	}
}

func (l *dummyTCPListener) Accept() (net.Conn, error) {
	<-l.closeCh
	return nil, net.ErrClosed
}

func (l *dummyTCPListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.closed = true
		close(l.closeCh)
	}
	return nil
}

func (l *dummyTCPListener) Addr() net.Addr {
	return l.addr
}

// newPipeFactoryPairFromPipe creates factory pair from an existing pipe.
func newPipeFactoryPairFromPipe(pipe *Pipe) (*PipeFactory, *PipeFactory) {
	f0 := &PipeFactory{
		pipe:    pipe,
		localID: 0,
	}
	f1 := &PipeFactory{
		pipe:    pipe,
		localID: 1,
	}
	f0.peerFactory = f1
	f1.peerFactory = f0
	return f0, f1
}

// Manager returns the manager at the given index (0 or 1).
func (p *PipeManagerPair) Manager(id int) *Manager {
	if id < 0 || id > 1 {
		return nil
	}
	return p.managers[id]
}

// PeerAddresses returns the addresses needed to send messages TO the manager at the given index.
// Use these addresses when sending from the other manager.
//
// Example:
//
//	// Send from manager 0 to manager 1
//	pair.Manager(0).Send(data, pair.PeerAddresses(1).UDP)
func (p *PipeManagerPair) PeerAddresses(id int) PipeAddresses {
	if id < 0 || id > 1 {
		return PipeAddresses{}
	}

	addrs := PipeAddresses{}

	if p.udp {
		addrs.UDP = NewUDPPeerAddress(PipeAddr{ID: id, Port: p.port})
	}

	if p.tcp {
		addrs.TCP = NewTCPPeerAddress(PipeAddr{ID: id, Port: p.port})
	}

	return addrs
}

// Pipe returns the underlying UDP pipe for configuration (e.g., network conditions).
// Returns nil if UDP is not enabled.
func (p *PipeManagerPair) Pipe() *Pipe {
	return p.pipe
}

// TCPPipe returns the underlying TCP pipe for configuration.
// Returns nil if TCP is not enabled.
func (p *PipeManagerPair) TCPPipe() *Pipe {
	return p.tcpPipe
}

// Close stops both managers and closes all pipes.
func (p *PipeManagerPair) Close() error {
	for i := 0; i < 2; i++ {
		if p.managers[i] != nil {
			// Ignore errors - manager may already be stopped
			p.managers[i].Stop()
		}
	}

	// Close pipes - ignore "already closed" errors since managers may have
	// closed the underlying connections during Stop()
	if p.pipe != nil {
		p.pipe.Close()
	}

	if p.tcpPipe != nil {
		p.tcpPipe.Close()
	}

	return nil
}
