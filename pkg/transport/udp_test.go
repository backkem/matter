package transport

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/backkem/matter/pkg/message"
)

func TestNewUDP(t *testing.T) {
	t.Run("with handler", func(t *testing.T) {
		handler := func(msg *ReceivedMessage) {}
		u, err := NewUDP(UDPConfig{
			ListenAddr:     "127.0.0.1:0",
			MessageHandler: handler,
		})
		if err != nil {
			t.Fatalf("NewUDP() error = %v", err)
		}
		defer u.Stop()

		if u.conn == nil {
			t.Error("NewUDP() conn is nil")
		}
	})

	t.Run("without handler", func(t *testing.T) {
		_, err := NewUDP(UDPConfig{
			ListenAddr: "127.0.0.1:0",
		})
		if err != ErrNoHandler {
			t.Errorf("NewUDP() error = %v, want %v", err, ErrNoHandler)
		}
	})

	t.Run("with injected conn", func(t *testing.T) {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("ListenPacket() error = %v", err)
		}

		handler := func(msg *ReceivedMessage) {}
		u, err := NewUDP(UDPConfig{
			Conn:           conn,
			MessageHandler: handler,
		})
		if err != nil {
			t.Fatalf("NewUDP() error = %v", err)
		}
		defer u.Stop()

		if u.conn != conn {
			t.Error("NewUDP() did not use injected conn")
		}
	})
}

func TestUDPStartStop(t *testing.T) {
	handler := func(msg *ReceivedMessage) {}
	u, err := NewUDP(UDPConfig{
		ListenAddr:     "127.0.0.1:0",
		MessageHandler: handler,
	})
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}

	// Start
	if err := u.Start(); err != nil {
		t.Errorf("Start() error = %v", err)
	}

	// Double start should fail
	if err := u.Start(); err != ErrAlreadyStarted {
		t.Errorf("Start() second call error = %v, want %v", err, ErrAlreadyStarted)
	}

	// Stop
	if err := u.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}

	// Double stop should fail
	if err := u.Stop(); err != ErrClosed {
		t.Errorf("Stop() second call error = %v, want %v", err, ErrClosed)
	}
}

func TestUDPSend(t *testing.T) {
	t.Run("normal send", func(t *testing.T) {
		received := make(chan *ReceivedMessage, 1)
		server, err := NewUDP(UDPConfig{
			ListenAddr:     "127.0.0.1:0",
			MessageHandler: func(msg *ReceivedMessage) { received <- msg },
		})
		if err != nil {
			t.Fatalf("NewUDP() error = %v", err)
		}
		if err := server.Start(); err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		defer server.Stop()

		client, err := NewUDP(UDPConfig{
			ListenAddr:     "127.0.0.1:0",
			MessageHandler: func(msg *ReceivedMessage) {},
		})
		if err != nil {
			t.Fatalf("NewUDP() error = %v", err)
		}
		if err := client.Start(); err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		defer client.Stop()

		testData := []byte{0x00, 0x01, 0x02, 0x03}
		if err := client.Send(testData, server.LocalAddr()); err != nil {
			t.Errorf("Send() error = %v", err)
		}

		select {
		case msg := <-received:
			if !bytes.Equal(msg.Data, testData) {
				t.Errorf("received data = %v, want %v", msg.Data, testData)
			}
			if msg.PeerAddr.TransportType != TransportTypeUDP {
				t.Errorf("TransportType = %v, want UDP", msg.PeerAddr.TransportType)
			}
		case <-time.After(time.Second):
			t.Error("timeout waiting for message")
		}
	})

	t.Run("nil address", func(t *testing.T) {
		u, err := NewUDP(UDPConfig{
			ListenAddr:     "127.0.0.1:0",
			MessageHandler: func(msg *ReceivedMessage) {},
		})
		if err != nil {
			t.Fatalf("NewUDP() error = %v", err)
		}
		defer u.Stop()

		if err := u.Send([]byte{0x01}, nil); err != ErrInvalidAddress {
			t.Errorf("Send() error = %v, want %v", err, ErrInvalidAddress)
		}
	})

	t.Run("message too large", func(t *testing.T) {
		u, err := NewUDP(UDPConfig{
			ListenAddr:     "127.0.0.1:0",
			MessageHandler: func(msg *ReceivedMessage) {},
		})
		if err != nil {
			t.Fatalf("NewUDP() error = %v", err)
		}
		defer u.Stop()

		addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:5540")
		largeData := make([]byte, message.MaxUDPMessageSize+1)
		if err := u.Send(largeData, addr); err != ErrMessageTooLarge {
			t.Errorf("Send() error = %v, want %v", err, ErrMessageTooLarge)
		}
	})

	t.Run("send after close", func(t *testing.T) {
		u, err := NewUDP(UDPConfig{
			ListenAddr:     "127.0.0.1:0",
			MessageHandler: func(msg *ReceivedMessage) {},
		})
		if err != nil {
			t.Fatalf("NewUDP() error = %v", err)
		}
		u.Stop()

		addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:5540")
		if err := u.Send([]byte{0x01}, addr); err != ErrClosed {
			t.Errorf("Send() error = %v, want %v", err, ErrClosed)
		}
	})
}

func TestUDPRoundtrip(t *testing.T) {
	received1 := make(chan *ReceivedMessage, 1)
	received2 := make(chan *ReceivedMessage, 1)

	// Create two UDP transports that can communicate
	udp1, err := NewUDP(UDPConfig{
		ListenAddr:     "127.0.0.1:0",
		MessageHandler: func(msg *ReceivedMessage) { received1 <- msg },
	})
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}
	if err := udp1.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer udp1.Stop()

	udp2, err := NewUDP(UDPConfig{
		ListenAddr:     "127.0.0.1:0",
		MessageHandler: func(msg *ReceivedMessage) { received2 <- msg },
	})
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}
	if err := udp2.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer udp2.Stop()

	// Send from udp1 to udp2
	msg1 := []byte("hello from udp1")
	if err := udp1.Send(msg1, udp2.LocalAddr()); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case msg := <-received2:
		if !bytes.Equal(msg.Data, msg1) {
			t.Errorf("received = %s, want %s", msg.Data, msg1)
		}
		// Reply back
		reply := []byte("hello back from udp2")
		if err := udp2.Send(reply, msg.PeerAddr.Addr); err != nil {
			t.Fatalf("Send() reply error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for message at udp2")
	}

	// Receive reply at udp1
	select {
	case msg := <-received1:
		expected := []byte("hello back from udp2")
		if !bytes.Equal(msg.Data, expected) {
			t.Errorf("reply = %s, want %s", msg.Data, expected)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for reply at udp1")
	}
}

func TestUDPLocalAddr(t *testing.T) {
	u, err := NewUDP(UDPConfig{
		ListenAddr:     "127.0.0.1:0",
		MessageHandler: func(msg *ReceivedMessage) {},
	})
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}
	defer u.Stop()

	addr := u.LocalAddr()
	if addr == nil {
		t.Error("LocalAddr() = nil")
	}

	// Verify it's a UDP address
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Errorf("LocalAddr() type = %T, want *net.UDPAddr", addr)
	}

	if udpAddr.Port == 0 {
		t.Error("LocalAddr() port = 0, want ephemeral port")
	}
}
