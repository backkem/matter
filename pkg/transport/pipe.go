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
// For now, TCP is not supported over pipes - returns nil.
func (f *PipeFactory) CreateTCPListener(port int) (net.Listener, error) {
	// TCP support would require a custom Listener implementation.
	// For now, Matter E2E tests use UDP primarily.
	return nil, nil
}

// SetCondition configures network condition simulation for this factory's pipe.
func (f *PipeFactory) SetCondition(cond NetworkCondition) {
	f.pipe.SetCondition(cond)
}

// Verify PipeFactory implements Factory.
var _ Factory = (*PipeFactory)(nil)
