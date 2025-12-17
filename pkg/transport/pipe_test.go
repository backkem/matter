package transport

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPipe_AutoProcess verifies that messages flow automatically by default.
func TestPipe_AutoProcess(t *testing.T) {
	f0, f1 := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	// Verify auto-process is enabled by default
	if !f0.Pipe().AutoProcess() {
		t.Fatal("AutoProcess should be true by default")
	}

	conn0, _ := f0.CreateUDPConn(5540)
	conn1, _ := f1.CreateUDPConn(5540)

	testData := []byte("auto-delivered message")
	done := make(chan error, 1)

	// Start reader
	go func() {
		buf := make([]byte, 100)
		n, _, err := conn1.ReadFrom(buf)
		if err != nil {
			done <- err
			return
		}
		if string(buf[:n]) != string(testData) {
			done <- &testError{msg: "data mismatch"}
			return
		}
		done <- nil
	}()

	// Give reader time to block
	time.Sleep(10 * time.Millisecond)

	// Write - no manual Process() needed!
	conn0.WriteTo(testData, f1.PeerAddr())

	// Wait for reader - message should be delivered automatically
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout - auto-process may not be working")
	}
}

// TestPipe_ManualProcess verifies that manual processing works when auto-process is disabled.
func TestPipe_ManualProcess(t *testing.T) {
	// Create with auto-process disabled
	f0, f1 := NewPipeFactoryPairWithConfig(PipeConfig{
		AutoProcess: false,
	})
	defer f0.Pipe().Close()

	// Verify auto-process is disabled
	if f0.Pipe().AutoProcess() {
		t.Fatal("AutoProcess should be false")
	}

	conn0, _ := f0.CreateUDPConn(5540)
	conn1, _ := f1.CreateUDPConn(5540)

	testData := []byte("manually-delivered message")
	done := make(chan error, 1)

	// Start reader
	go func() {
		buf := make([]byte, 100)
		n, _, err := conn1.ReadFrom(buf)
		if err != nil {
			done <- err
			return
		}
		if string(buf[:n]) != string(testData) {
			done <- &testError{msg: "data mismatch"}
			return
		}
		done <- nil
	}()

	// Give reader time to block
	time.Sleep(10 * time.Millisecond)

	// Write
	conn0.WriteTo(testData, f1.PeerAddr())

	// Message should NOT be delivered yet (no auto-process)
	select {
	case <-done:
		t.Fatal("message delivered without Process() - auto-process may be on")
	case <-time.After(50 * time.Millisecond):
		// Expected - message not yet delivered
	}

	// Now manually process
	f0.Pipe().Process()

	// Message should now be delivered
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout after Process()")
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string { return e.msg }

func TestPipe_BasicCommunication(t *testing.T) {
	f0, f1 := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	conn0, _ := f0.CreateUDPConn(5540)
	conn1, _ := f1.CreateUDPConn(5540)

	testData := []byte("hello from 0")
	done := make(chan error, 1)

	go func() {
		buf := make([]byte, 100)
		n, _, err := conn1.ReadFrom(buf)
		if err != nil {
			done <- err
			return
		}
		if string(buf[:n]) != string(testData) {
			done <- &testError{msg: "data mismatch"}
			return
		}
		done <- nil
	}()

	time.Sleep(10 * time.Millisecond)
	conn0.WriteTo(testData, f1.PeerAddr())

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for read")
	}
}

func TestPipe_Bidirectional(t *testing.T) {
	f0, f1 := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	conn0, _ := f0.CreateUDPConn(5540)
	conn1, _ := f1.CreateUDPConn(5540)

	done0 := make(chan string, 1)
	done1 := make(chan string, 1)

	// Start readers on both sides
	go func() {
		buf := make([]byte, 100)
		n, _, _ := conn0.ReadFrom(buf)
		done0 <- string(buf[:n])
	}()

	go func() {
		buf := make([]byte, 100)
		n, _, _ := conn1.ReadFrom(buf)
		done1 <- string(buf[:n])
	}()

	time.Sleep(10 * time.Millisecond)

	// Write in both directions
	conn0.WriteTo([]byte("from 0"), f1.PeerAddr())
	conn1.WriteTo([]byte("from 1"), f0.PeerAddr())

	// Check results
	select {
	case msg := <-done0:
		if msg != "from 1" {
			t.Errorf("conn0 got %q, want %q", msg, "from 1")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for conn0 read")
	}

	select {
	case msg := <-done1:
		if msg != "from 0" {
			t.Errorf("conn1 got %q, want %q", msg, "from 0")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for conn1 read")
	}
}

func TestPipePacketConn_Interface(t *testing.T) {
	f0, f1 := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	conn0, err := f0.CreateUDPConn(5540)
	if err != nil {
		t.Fatalf("CreateUDPConn: %v", err)
	}

	conn1, err := f1.CreateUDPConn(5540)
	if err != nil {
		t.Fatalf("CreateUDPConn: %v", err)
	}

	// Verify interface
	var _ net.PacketConn = conn0
	var _ net.PacketConn = conn1
}

func TestPipePacketConn_LocalAddr(t *testing.T) {
	f0, _ := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	conn, err := f0.CreateUDPConn(5540)
	if err != nil {
		t.Fatalf("CreateUDPConn: %v", err)
	}

	addr := conn.LocalAddr()
	if addr.Network() != "pipe" {
		t.Errorf("Network() = %q, want %q", addr.Network(), "pipe")
	}

	pipeAddr, ok := addr.(PipeAddr)
	if !ok {
		t.Fatalf("addr is not PipeAddr")
	}

	if pipeAddr.ID != 0 {
		t.Errorf("ID = %d, want 0", pipeAddr.ID)
	}
	if pipeAddr.Port != 5540 {
		t.Errorf("Port = %d, want 5540", pipeAddr.Port)
	}
}

func TestPipeFactory_ReusesConnection(t *testing.T) {
	f0, _ := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	conn1, _ := f0.CreateUDPConn(5540)
	conn2, _ := f0.CreateUDPConn(5540)

	if conn1 != conn2 {
		t.Error("CreateUDPConn should return the same connection on subsequent calls")
	}
}

func TestNetworkCondition_DropRate(t *testing.T) {
	f0, f1 := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	// Set 100% drop rate
	f0.SetCondition(NetworkCondition{
		DropRate: 1.0,
	})

	conn0, _ := f0.CreateUDPConn(5540)
	conn1, _ := f1.CreateUDPConn(5540)

	// Send a packet (should be dropped)
	testData := []byte("dropped packet")
	n, err := conn0.WriteTo(testData, f1.PeerAddr())
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(testData) {
		t.Errorf("WriteTo returned %d, want %d", n, len(testData))
	}

	// Try to read - should timeout since packet was dropped
	buf := make([]byte, 100)
	conn1.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, _, err = conn1.ReadFrom(buf)
	if err == nil {
		t.Error("expected timeout error due to dropped packet")
	}
}

func TestNetworkCondition_Delay(t *testing.T) {
	f0, f1 := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	delayDuration := 50 * time.Millisecond
	f0.SetCondition(NetworkCondition{
		DelayMin: delayDuration,
		DelayMax: delayDuration,
	})

	conn0, _ := f0.CreateUDPConn(5540)
	conn1, _ := f1.CreateUDPConn(5540)

	done := make(chan struct{})

	// Start reader
	go func() {
		buf := make([]byte, 100)
		conn1.ReadFrom(buf)
		close(done)
	}()

	time.Sleep(10 * time.Millisecond)

	// Measure time to send (delay happens in WriteTo)
	start := time.Now()
	conn0.WriteTo([]byte("delayed packet"), f1.PeerAddr())
	elapsed := time.Since(start)

	// Should have taken at least the delay duration
	if elapsed < delayDuration {
		t.Errorf("elapsed %v, want at least %v", elapsed, delayDuration)
	}

	select {
	case <-done:
		// Success
	case <-time.After(time.Second):
		t.Error("packet should arrive after delay")
	}
}

func TestPipeAddr_String(t *testing.T) {
	addr := PipeAddr{ID: 0, Port: 5540}
	if addr.String() != "pipe:0:5540" {
		t.Errorf("String() = %q, want %q", addr.String(), "pipe:0:5540")
	}
}

func TestPipeFactory_VerifyInterface(t *testing.T) {
	var _ Factory = (*PipeFactory)(nil)
}

func TestPipe_Tick(t *testing.T) {
	// Manual processing for deterministic test
	f0, f1 := NewPipeFactoryPairWithConfig(PipeConfig{
		AutoProcess: false,
	})
	defer f0.Pipe().Close()

	conn0, _ := f0.CreateUDPConn(5540)
	conn1, _ := f1.CreateUDPConn(5540)

	msg1 := make(chan string, 1)
	msg2 := make(chan string, 1)

	// Start first reader
	go func() {
		buf := make([]byte, 100)
		n, _, _ := conn1.ReadFrom(buf)
		msg1 <- string(buf[:n])
	}()

	time.Sleep(10 * time.Millisecond)

	// Queue first message
	conn0.WriteTo([]byte("msg1"), f1.PeerAddr())

	// Tick once to deliver first message
	if f0.Pipe().Tick() == 0 {
		t.Error("Tick should return > 0 when messages are pending")
	}

	select {
	case m := <-msg1:
		if m != "msg1" {
			t.Errorf("first message = %q, want %q", m, "msg1")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for first message")
	}

	// Start second reader
	go func() {
		buf := make([]byte, 100)
		n, _, _ := conn1.ReadFrom(buf)
		msg2 <- string(buf[:n])
	}()

	time.Sleep(10 * time.Millisecond)

	// Queue second message
	conn0.WriteTo([]byte("msg2"), f1.PeerAddr())

	// Tick again
	f0.Pipe().Tick()

	select {
	case m := <-msg2:
		if m != "msg2" {
			t.Errorf("second message = %q, want %q", m, "msg2")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for second message")
	}
}

func TestNetworkCondition_StatisticalDropRate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping statistical test in short mode")
	}

	f0, f1 := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	// Set 50% drop rate
	f0.SetCondition(NetworkCondition{
		DropRate: 0.5,
	})

	conn0, _ := f0.CreateUDPConn(5540)
	conn1, _ := f1.CreateUDPConn(5540)

	const numPackets = 100
	var received int32

	// Start receiver
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 100)
		for {
			conn1.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			_, _, err := conn1.ReadFrom(buf)
			if err != nil {
				return
			}
			atomic.AddInt32(&received, 1)
		}
	}()

	// Send packets
	for i := 0; i < numPackets; i++ {
		conn0.WriteTo([]byte("test"), f1.PeerAddr())
		time.Sleep(2 * time.Millisecond) // Give auto-process time
	}

	// Wait for receiver to timeout
	wg.Wait()

	// Should receive approximately 50% (allow 20-80% range for randomness)
	r := int(atomic.LoadInt32(&received))
	if r < 20 || r > 80 {
		t.Errorf("received %d/%d packets, expected ~50%% with 50%% drop rate", r, numPackets)
	}
}

func TestPipe_Close(t *testing.T) {
	pipe := NewPipe()

	// Close should succeed and stop auto-process
	err := pipe.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Second close should be no-op
	err = pipe.Close()
	if err != nil {
		t.Errorf("Second Close failed: %v", err)
	}
}

func TestPipeTCPListener_Basic(t *testing.T) {
	f0, f1 := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	// Create listener on f0
	listener, err := f0.CreateTCPListener(5540)
	if err != nil {
		t.Fatalf("CreateTCPListener: %v", err)
	}
	if listener == nil {
		t.Fatal("CreateTCPListener returned nil")
	}
	defer listener.Close()

	// Get client connection from f1
	clientConn := f1.GetTCPClientConn(5540)
	if clientConn == nil {
		t.Fatal("GetTCPClientConn returned nil")
	}

	// Accept should return immediately (pipe connection already exists)
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer serverConn.Close()

	// Verify addresses
	if serverConn.LocalAddr().String() != "pipe:0:5540" {
		t.Errorf("server LocalAddr = %q, want %q", serverConn.LocalAddr(), "pipe:0:5540")
	}
	if clientConn.LocalAddr().String() != "pipe:1:5540" {
		t.Errorf("client LocalAddr = %q, want %q", clientConn.LocalAddr(), "pipe:1:5540")
	}
}

func TestPipeTCPListener_DataTransfer(t *testing.T) {
	f0, f1 := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	listener, _ := f0.CreateTCPListener(5540)
	defer listener.Close()

	clientConn := f1.GetTCPClientConn(5540)
	serverConn, _ := listener.Accept()
	defer serverConn.Close()

	// Test client -> server
	testData := []byte("hello from client")
	done := make(chan error, 1)

	go func() {
		buf := make([]byte, 100)
		n, err := serverConn.Read(buf)
		if err != nil {
			done <- err
			return
		}
		if string(buf[:n]) != string(testData) {
			done <- &testError{msg: "data mismatch"}
			return
		}
		done <- nil
	}()

	time.Sleep(10 * time.Millisecond)
	_, err := clientConn.Write(testData)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server read error: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for server read")
	}
}

func TestPipeTCPListener_Bidirectional(t *testing.T) {
	f0, f1 := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	listener, _ := f0.CreateTCPListener(5540)
	defer listener.Close()

	clientConn := f1.GetTCPClientConn(5540)
	serverConn, _ := listener.Accept()
	defer serverConn.Close()

	serverMsg := make(chan string, 1)
	clientMsg := make(chan string, 1)

	// Server reads
	go func() {
		buf := make([]byte, 100)
		n, _ := serverConn.Read(buf)
		serverMsg <- string(buf[:n])
	}()

	// Client reads
	go func() {
		buf := make([]byte, 100)
		n, _ := clientConn.Read(buf)
		clientMsg <- string(buf[:n])
	}()

	time.Sleep(10 * time.Millisecond)

	// Write in both directions
	clientConn.Write([]byte("from client"))
	serverConn.Write([]byte("from server"))

	select {
	case msg := <-serverMsg:
		if msg != "from client" {
			t.Errorf("server got %q, want %q", msg, "from client")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for server message")
	}

	select {
	case msg := <-clientMsg:
		if msg != "from server" {
			t.Errorf("client got %q, want %q", msg, "from server")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for client message")
	}
}

func TestPipeTCPListener_AcceptOnce(t *testing.T) {
	f0, _ := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	listener, _ := f0.CreateTCPListener(5540)
	defer listener.Close()

	// First accept should succeed
	conn1, err := listener.Accept()
	if err != nil {
		t.Fatalf("first Accept: %v", err)
	}
	defer conn1.Close()

	// Second accept should block until close
	done := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		done <- err
	}()

	// Should not complete immediately
	select {
	case <-done:
		t.Fatal("second Accept should block")
	case <-time.After(50 * time.Millisecond):
		// Expected - still blocking
	}

	// Close listener to unblock
	listener.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Error("second Accept should return error after Close")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("second Accept should unblock after Close")
	}
}

func TestPipeTCPListener_AcceptAfterClose(t *testing.T) {
	f0, _ := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	listener, _ := f0.CreateTCPListener(5540)
	listener.Close()

	// Accept on closed listener should return error immediately
	_, err := listener.Accept()
	if err == nil {
		t.Error("Accept on closed listener should return error")
	}
}

func TestPipeTCPListener_Addr(t *testing.T) {
	f0, _ := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	listener, _ := f0.CreateTCPListener(5540)
	defer listener.Close()

	addr := listener.Addr()
	if addr.Network() != "pipe" {
		t.Errorf("Network() = %q, want %q", addr.Network(), "pipe")
	}
	if addr.String() != "pipe:0:5540" {
		t.Errorf("String() = %q, want %q", addr.String(), "pipe:0:5540")
	}
}

func TestPipeTCPConn_Interface(t *testing.T) {
	f0, f1 := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	listener, _ := f0.CreateTCPListener(5540)
	defer listener.Close()

	clientConn := f1.GetTCPClientConn(5540)
	serverConn, _ := listener.Accept()
	defer serverConn.Close()

	// Verify interfaces
	var _ net.Conn = clientConn
	var _ net.Conn = serverConn
}

func TestPipeTCPListener_ReusesListener(t *testing.T) {
	f0, _ := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	listener1, _ := f0.CreateTCPListener(5540)
	listener2, _ := f0.CreateTCPListener(5540)

	if listener1 != listener2 {
		t.Error("CreateTCPListener should return the same listener on subsequent calls")
	}
}

func TestPipe_SetAutoProcess(t *testing.T) {
	pipe := NewPipe()
	defer pipe.Close()

	// Default is auto-process enabled
	if !pipe.AutoProcess() {
		t.Error("AutoProcess should be true by default")
	}

	// Disable
	pipe.SetAutoProcess(false)
	if pipe.AutoProcess() {
		t.Error("AutoProcess should be false after disabling")
	}

	// Re-enable
	pipe.SetAutoProcess(true)
	if !pipe.AutoProcess() {
		t.Error("AutoProcess should be true after re-enabling")
	}
}

func TestPipeConfig_Defaults(t *testing.T) {
	config := DefaultPipeConfig()

	if !config.AutoProcess {
		t.Error("AutoProcess should be true by default")
	}
	if config.ProcessInterval != 1*time.Millisecond {
		t.Errorf("ProcessInterval = %v, want 1ms", config.ProcessInterval)
	}
}

// --- PipeManagerPair Tests ---

func TestPipeManagerPair_UDP(t *testing.T) {
	received := make(chan *ReceivedMessage, 2)
	handler := func(msg *ReceivedMessage) {
		received <- msg
	}

	pair, err := NewPipeManagerPair(PipeManagerConfig{
		UDP:      true,
		TCP:      false,
		Handlers: [2]MessageHandler{handler, handler},
	})
	if err != nil {
		t.Fatalf("NewPipeManagerPair: %v", err)
	}
	defer pair.Close()

	// Send from mgr0 to mgr1 via UDP
	testData := []byte("hello via UDP")
	peer1Addr := pair.PeerAddresses(1)

	if !peer1Addr.UDP.IsValid() {
		t.Fatal("UDP peer address should be valid")
	}
	if peer1Addr.TCP.IsValid() {
		t.Fatal("TCP peer address should NOT be valid when TCP is disabled")
	}

	err = pair.Manager(0).Send(testData, peer1Addr.UDP)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case msg := <-received:
		if string(msg.Data) != string(testData) {
			t.Errorf("received %q, want %q", msg.Data, testData)
		}
		if msg.PeerAddr.TransportType != TransportTypeUDP {
			t.Errorf("transport type = %v, want UDP", msg.PeerAddr.TransportType)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for message")
	}
}

func TestPipeManagerPair_TCP(t *testing.T) {
	received := make(chan *ReceivedMessage, 2)
	handler := func(msg *ReceivedMessage) {
		received <- msg
	}

	pair, err := NewPipeManagerPair(PipeManagerConfig{
		UDP:      false,
		TCP:      true,
		Handlers: [2]MessageHandler{handler, handler},
	})
	if err != nil {
		t.Fatalf("NewPipeManagerPair: %v", err)
	}
	defer pair.Close()

	// Send from mgr0 to mgr1 via TCP
	testData := []byte("hello via TCP")
	peer1Addr := pair.PeerAddresses(1)

	if peer1Addr.UDP.IsValid() {
		t.Fatal("UDP peer address should NOT be valid when UDP is disabled")
	}
	if !peer1Addr.TCP.IsValid() {
		t.Fatal("TCP peer address should be valid")
	}

	err = pair.Manager(0).Send(testData, peer1Addr.TCP)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case msg := <-received:
		if string(msg.Data) != string(testData) {
			t.Errorf("received %q, want %q", msg.Data, testData)
		}
		if msg.PeerAddr.TransportType != TransportTypeTCP {
			t.Errorf("transport type = %v, want TCP", msg.PeerAddr.TransportType)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for message")
	}
}

func TestPipeManagerPair_Bidirectional(t *testing.T) {
	received0 := make(chan *ReceivedMessage, 2)
	received1 := make(chan *ReceivedMessage, 2)

	pair, err := NewPipeManagerPair(PipeManagerConfig{
		UDP: true,
		TCP: true,
		Handlers: [2]MessageHandler{
			func(msg *ReceivedMessage) { received0 <- msg },
			func(msg *ReceivedMessage) { received1 <- msg },
		},
	})
	if err != nil {
		t.Fatalf("NewPipeManagerPair: %v", err)
	}
	defer pair.Close()

	// mgr0 -> mgr1 via UDP
	pair.Manager(0).Send([]byte("0->1 UDP"), pair.PeerAddresses(1).UDP)

	// mgr1 -> mgr0 via UDP
	pair.Manager(1).Send([]byte("1->0 UDP"), pair.PeerAddresses(0).UDP)

	// mgr0 -> mgr1 via TCP
	pair.Manager(0).Send([]byte("0->1 TCP"), pair.PeerAddresses(1).TCP)

	// mgr1 -> mgr0 via TCP
	pair.Manager(1).Send([]byte("1->0 TCP"), pair.PeerAddresses(0).TCP)

	// Collect messages
	var msgs0, msgs1 []*ReceivedMessage
	timeout := time.After(500 * time.Millisecond)

	for len(msgs0) < 2 || len(msgs1) < 2 {
		select {
		case msg := <-received0:
			msgs0 = append(msgs0, msg)
		case msg := <-received1:
			msgs1 = append(msgs1, msg)
		case <-timeout:
			t.Fatalf("timeout: got %d msgs at mgr0, %d at mgr1", len(msgs0), len(msgs1))
		}
	}

	// Verify mgr0 received messages from mgr1
	if len(msgs0) != 2 {
		t.Errorf("mgr0 received %d messages, want 2", len(msgs0))
	}

	// Verify mgr1 received messages from mgr0
	if len(msgs1) != 2 {
		t.Errorf("mgr1 received %d messages, want 2", len(msgs1))
	}
}

func TestPipeManagerPair_ProtocolIsolation(t *testing.T) {
	// Test that UDP-only pair cannot accidentally use TCP
	t.Run("UDP-only rejects TCP", func(t *testing.T) {
		pair, err := NewPipeManagerPair(PipeManagerConfig{
			UDP:      true,
			TCP:      false,
			Handlers: [2]MessageHandler{func(*ReceivedMessage) {}, func(*ReceivedMessage) {}},
		})
		if err != nil {
			t.Fatalf("NewPipeManagerPair: %v", err)
		}
		defer pair.Close()

		// PeerAddresses should return invalid TCP address
		peer1 := pair.PeerAddresses(1)
		if peer1.TCP.IsValid() {
			t.Error("TCP address should be invalid when TCP is disabled")
		}

		// Attempting to use a constructed TCP address should fail
		tcpAddr := NewTCPPeerAddress(PipeAddr{ID: 1, Port: 5540})
		err = pair.Manager(0).Send([]byte("test"), tcpAddr)
		if err == nil {
			t.Error("Send via TCP should fail when TCP is disabled")
		}
	})

	// Test that TCP-only pair cannot accidentally use UDP
	t.Run("TCP-only rejects UDP", func(t *testing.T) {
		pair, err := NewPipeManagerPair(PipeManagerConfig{
			UDP:      false,
			TCP:      true,
			Handlers: [2]MessageHandler{func(*ReceivedMessage) {}, func(*ReceivedMessage) {}},
		})
		if err != nil {
			t.Fatalf("NewPipeManagerPair: %v", err)
		}
		defer pair.Close()

		// PeerAddresses should return invalid UDP address
		peer1 := pair.PeerAddresses(1)
		if peer1.UDP.IsValid() {
			t.Error("UDP address should be invalid when UDP is disabled")
		}

		// Attempting to use a constructed UDP address should fail
		udpAddr := NewUDPPeerAddress(PipeAddr{ID: 1, Port: 5540})
		err = pair.Manager(0).Send([]byte("test"), udpAddr)
		if err == nil {
			t.Error("Send via UDP should fail when UDP is disabled")
		}
	})
}

func TestPipeManagerPair_Defaults(t *testing.T) {
	// When neither UDP nor TCP is specified, both should be enabled
	pair, err := NewPipeManagerPair(PipeManagerConfig{
		Handlers: [2]MessageHandler{func(*ReceivedMessage) {}, func(*ReceivedMessage) {}},
	})
	if err != nil {
		t.Fatalf("NewPipeManagerPair: %v", err)
	}
	defer pair.Close()

	peer1 := pair.PeerAddresses(1)
	if !peer1.UDP.IsValid() {
		t.Error("UDP should be enabled by default")
	}
	if !peer1.TCP.IsValid() {
		t.Error("TCP should be enabled by default")
	}
}

func TestPipeManagerPair_Close(t *testing.T) {
	pair, err := NewPipeManagerPair(PipeManagerConfig{
		UDP:      true,
		TCP:      true,
		Handlers: [2]MessageHandler{func(*ReceivedMessage) {}, func(*ReceivedMessage) {}},
	})
	if err != nil {
		t.Fatalf("NewPipeManagerPair: %v", err)
	}

	// Close should succeed (always returns nil, ignores already-closed errors)
	pair.Close()

	// Sending after close should fail
	err = pair.Manager(0).Send([]byte("test"), pair.PeerAddresses(1).UDP)
	if err == nil {
		t.Error("Send after Close should fail")
	}

	// Double close should be safe
	pair.Close()
}

func TestPipeManagerPair_PipeAccess(t *testing.T) {
	pair, err := NewPipeManagerPair(PipeManagerConfig{
		UDP:      true,
		TCP:      true,
		Handlers: [2]MessageHandler{func(*ReceivedMessage) {}, func(*ReceivedMessage) {}},
	})
	if err != nil {
		t.Fatalf("NewPipeManagerPair: %v", err)
	}
	defer pair.Close()

	// Should be able to access pipes for configuration
	if pair.Pipe() == nil {
		t.Error("Pipe() should not be nil when UDP is enabled")
	}
	if pair.TCPPipe() == nil {
		t.Error("TCPPipe() should not be nil when TCP is enabled")
	}

	// Can set network conditions
	pair.Pipe().SetCondition(NetworkCondition{
		DropRate: 0.5,
	})
	cond := pair.Pipe().Condition()
	if cond.DropRate != 0.5 {
		t.Errorf("DropRate = %v, want 0.5", cond.DropRate)
	}
}

func TestPipeManagerPair_ManagerAccess(t *testing.T) {
	pair, err := NewPipeManagerPair(PipeManagerConfig{
		Handlers: [2]MessageHandler{func(*ReceivedMessage) {}, func(*ReceivedMessage) {}},
	})
	if err != nil {
		t.Fatalf("NewPipeManagerPair: %v", err)
	}
	defer pair.Close()

	// Valid indices
	if pair.Manager(0) == nil {
		t.Error("Manager(0) should not be nil")
	}
	if pair.Manager(1) == nil {
		t.Error("Manager(1) should not be nil")
	}

	// Invalid indices
	if pair.Manager(-1) != nil {
		t.Error("Manager(-1) should be nil")
	}
	if pair.Manager(2) != nil {
		t.Error("Manager(2) should be nil")
	}
}
