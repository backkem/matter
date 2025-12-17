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

func TestPipeFactory_TCPNotSupported(t *testing.T) {
	f0, _ := NewPipeFactoryPair()
	defer f0.Pipe().Close()

	listener, err := f0.CreateTCPListener(5540)
	if err != nil {
		t.Errorf("CreateTCPListener should not error: %v", err)
	}
	if listener != nil {
		t.Error("CreateTCPListener should return nil (not supported)")
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
