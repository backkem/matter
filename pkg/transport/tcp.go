package transport

import (
	"io"
	"net"
	"sync"

	"github.com/backkem/matter/pkg/message"
	"github.com/pion/logging"
)

// TCP provides TCP transport for Matter messages.
// It wraps a net.Listener and manages persistent connections with peers.
// Messages are framed with a 4-byte length prefix per Spec Section 4.5.
type TCP struct {
	listener net.Listener
	handler  MessageHandler
	closeCh  chan struct{}
	wg       sync.WaitGroup
	log      logging.LeveledLogger

	// Connection tracking
	connsMu sync.RWMutex
	conns   map[string]*tcpConn // Key: remote address string

	mu      sync.RWMutex
	started bool
	closed  bool
}

// tcpConn wraps a TCP connection with framing support.
type tcpConn struct {
	conn   net.Conn
	reader *message.StreamReader
	writer *message.StreamWriter
	mu     sync.Mutex // Protects writes
}

// TCPConfig configures the TCP transport.
type TCPConfig struct {
	// Listener is an optional pre-existing Listener to use.
	// If nil, a new listener will be created using ListenAddr.
	Listener net.Listener

	// ListenAddr is the address to listen on (e.g., ":5540").
	// Ignored if Listener is provided.
	ListenAddr string

	// MessageHandler is called for each received message.
	// Required.
	MessageHandler MessageHandler

	// LoggerFactory is the factory for creating loggers.
	// If nil, logging is disabled.
	LoggerFactory logging.LoggerFactory
}

// NewTCP creates a new TCP transport with the given configuration.
func NewTCP(config TCPConfig) (*TCP, error) {
	if config.MessageHandler == nil {
		return nil, ErrNoHandler
	}

	t := &TCP{
		listener: config.Listener,
		handler:  config.MessageHandler,
		closeCh:  make(chan struct{}),
		conns:    make(map[string]*tcpConn),
	}

	// Create logger
	if config.LoggerFactory != nil {
		t.log = config.LoggerFactory.NewLogger("transport-tcp")
	}

	// Create listener if not provided
	if t.listener == nil {
		addr := config.ListenAddr
		if addr == "" {
			addr = ":0" // Use ephemeral port
		}

		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		t.listener = listener
	}

	return t, nil
}

// Start begins accepting connections and receiving messages.
func (t *TCP) Start() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrClosed
	}
	if t.started {
		t.mu.Unlock()
		return ErrAlreadyStarted
	}
	t.started = true
	t.mu.Unlock()

	if t.log != nil {
		t.log.Infof("starting TCP transport on %s", t.listener.Addr())
	}

	t.wg.Add(1)
	go t.acceptLoop()

	return nil
}

// Stop closes all connections and the listener.
func (t *TCP) Stop() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrClosed
	}
	t.closed = true
	t.mu.Unlock()

	if t.log != nil {
		t.log.Info("stopping TCP transport")
	}

	close(t.closeCh)
	t.listener.Close()

	// Close all connections
	t.connsMu.Lock()
	for _, tc := range t.conns {
		tc.conn.Close()
	}
	t.conns = make(map[string]*tcpConn)
	t.connsMu.Unlock()

	t.wg.Wait()
	return nil
}

// Send sends a message to the specified address over TCP.
// If no connection exists, one will be established.
func (t *TCP) Send(data []byte, addr net.Addr) error {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return ErrClosed
	}
	t.mu.RUnlock()

	if addr == nil {
		return ErrInvalidAddress
	}

	tc, err := t.getOrCreateConn(addr)
	if err != nil {
		return err
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()

	return tc.writer.WriteFrame(&message.RawFrame{
		Header:           message.MessageHeader{},
		EncryptedPayload: data,
	})
}

// SendRaw sends raw data with length prefix to the specified address.
func (t *TCP) SendRaw(data []byte, addr net.Addr) error {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return ErrClosed
	}
	t.mu.RUnlock()

	if addr == nil {
		return ErrInvalidAddress
	}

	tc, err := t.getOrCreateConn(addr)
	if err != nil {
		return err
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()

	_, err = tc.writer.Write(data)
	return err
}

// LocalAddr returns the local address the transport is listening on.
func (t *TCP) LocalAddr() net.Addr {
	return t.listener.Addr()
}

// acceptLoop accepts incoming connections.
func (t *TCP) acceptLoop() {
	defer t.wg.Done()

	for {
		conn, err := t.listener.Accept()
		if err != nil {
			select {
			case <-t.closeCh:
				return
			default:
				continue
			}
		}

		t.wg.Add(1)
		go t.handleConn(conn)
	}
}

// handleConn handles a single TCP connection.
func (t *TCP) handleConn(conn net.Conn) {
	defer t.wg.Done()

	tc := &tcpConn{
		conn:   conn,
		reader: message.NewStreamReader(conn),
		writer: message.NewStreamWriter(conn),
	}

	// Track the connection
	remoteAddr := conn.RemoteAddr().String()
	t.connsMu.Lock()
	t.conns[remoteAddr] = tc
	t.connsMu.Unlock()

	defer func() {
		conn.Close()
		t.connsMu.Lock()
		delete(t.conns, remoteAddr)
		t.connsMu.Unlock()
	}()

	for {
		select {
		case <-t.closeCh:
			return
		default:
		}

		data, err := tc.reader.Read()
		if err != nil {
			if err == io.EOF {
				return
			}
			select {
			case <-t.closeCh:
				return
			default:
				// Connection error, close it
				return
			}
		}

		msg := &ReceivedMessage{
			Data:     data,
			PeerAddr: NewTCPPeerAddress(conn.RemoteAddr()),
		}

		t.handler(msg)
	}
}

// getOrCreateConn gets an existing connection or creates a new one.
func (t *TCP) getOrCreateConn(addr net.Addr) (*tcpConn, error) {
	addrStr := addr.String()

	// Try to get existing connection
	t.connsMu.RLock()
	tc, ok := t.conns[addrStr]
	t.connsMu.RUnlock()
	if ok {
		return tc, nil
	}

	// Create new connection
	conn, err := net.Dial("tcp", addrStr)
	if err != nil {
		return nil, err
	}

	tc = &tcpConn{
		conn:   conn,
		reader: message.NewStreamReader(conn),
		writer: message.NewStreamWriter(conn),
	}

	// Track the connection
	t.connsMu.Lock()
	// Check again in case another goroutine created it
	if existing, ok := t.conns[addrStr]; ok {
		t.connsMu.Unlock()
		conn.Close()
		return existing, nil
	}
	t.conns[addrStr] = tc
	t.connsMu.Unlock()

	// Start read loop for outbound connections
	t.wg.Add(1)
	go t.handleConn(conn)

	return tc, nil
}

// AddConnection adds an existing connection to the transport.
// This is useful for testing with net.Pipe().
func (t *TCP) AddConnection(conn net.Conn) {
	tc := &tcpConn{
		conn:   conn,
		reader: message.NewStreamReader(conn),
		writer: message.NewStreamWriter(conn),
	}

	remoteAddr := conn.RemoteAddr().String()
	t.connsMu.Lock()
	t.conns[remoteAddr] = tc
	t.connsMu.Unlock()

	t.wg.Add(1)
	go t.handleConn(conn)
}
