# transport

Package `transport` implements the network transport layer for Matter.

It abstracts the underlying network protocols (UDP, TCP) and provides a unified interface for sending and receiving Matter messages.

## Supported Transports

*   **UDP** (Default/Mandatory): Connectionless, used for discovery, group casting, and most operational messaging.
*   **TCP** (Optional): Connection-oriented, used for large data transfers (e.g., OTA).

## Architecture

The `Manager` owns the sockets and dispatches incoming messages to a registered handler.

```
      Application / Exchange Manager
                   ▲
                   │ OnMessageReceived ()
                   │
           ┌───────┴───────┐
           │    Manager    │
           └───────┬───────┘
                   │
       ┌───────────┴───────────┐
       ▼                       ▼
    ┌─────┐                 ┌─────┐
    │ UDP │                 │ TCP │
    └─────┘                 └─────┘
```

## Usage

### Initialize and Start

```go
import "github.com/backkem/matter/pkg/transport"

// Define the handler for incoming messages
handler := func(msg *transport.ReceivedMessage) {
    fmt.Printf("Received %d bytes from %s\n", len(msg.Data), msg.PeerAddr)
}

// Create manager (binds to port 5540 by default)
mgr, err := transport.NewManager(transport.ManagerConfig{
    MessageHandler: handler,
})

// Start listening
mgr.Start()
```

### Send a Message

The `Send` method automatically selects UDP or TCP based on the `PeerAddress`.

```go
// Send via UDP
addr := transport.NewUDPPeerAddress(remoteNetAddr)
err := mgr.Send(data, addr)
```

## Virtual Pipe for Testing

In-memory transport for deterministic, flaky-free tests without real network I/O.
Supports both UDP and TCP transports.

```
    Device                              Controller
    ──────                              ──────────
       │                                    │
       ▼                                    ▼
  PipeFactory ◄─────── Pipe ──────► PipeFactory
       │           (auto-process)           │
       ├───────────────────────────────────►├
       ▼                                    ▼
  PipePacketConn ◄── Queue 0→1 ──► PipePacketConn  (UDP)
                 ◄── Queue 1→0 ──►
       │                                    │
       ▼                                    ▼
  PipeTCPListener ◄── Stream ────► PipeTCPConn     (TCP)
```

### Basic Usage (UDP)

```go
// Create paired factories - messages flow automatically
deviceFactory, controllerFactory := transport.NewPipeFactoryPair()
defer deviceFactory.Pipe().Close()

// Use in NodeConfig
config := matter.NodeConfig{
    TransportFactory: deviceFactory,
}
```

### TCP Usage

```go
f0, f1 := transport.NewPipeFactoryPair()
defer f0.Pipe().Close()

// Server side: create listener
listener, _ := f0.CreateTCPListener(5540)
defer listener.Close()

// Client side: get connection
clientConn := f1.GetTCPClientConn(5540)

// Server accepts the connection
serverConn, _ := listener.Accept()
defer serverConn.Close()

// Now clientConn and serverConn are connected via the pipe
clientConn.Write([]byte("hello"))
buf := make([]byte, 100)
n, _ := serverConn.Read(buf)
// buf[:n] == "hello"
```

### Network Simulation

```go
deviceFactory.SetCondition(transport.NetworkCondition{
    DropRate:      0.1,                   // 10% packet loss
    DelayMin:      10 * time.Millisecond,
    DelayMax:      50 * time.Millisecond,
    DuplicateRate: 0.05,                  // 5% duplicates
})
```

### Manual Processing (Deterministic Tests)

```go
f0, f1 := transport.NewPipeFactoryPairWithConfig(transport.PipeConfig{
    AutoProcess: false,
})

conn0.WriteTo(data, addr)
f0.Pipe().Process() // manually deliver
```

## PipeManagerPair (Recommended for Testing)

For most testing scenarios, use `NewPipeManagerPair()` instead of manually wiring pipes.
It creates two fully connected Manager instances with minimal boilerplate.

```go
pair, _ := transport.NewPipeManagerPair(transport.PipeManagerConfig{
    UDP: true,
    TCP: true,
    Handlers: [2]transport.MessageHandler{handler0, handler1},
})
defer pair.Close()

// Send from manager 0 to manager 1
pair.Manager(0).Send(data, pair.PeerAddresses(1).UDP)

// Send from manager 1 to manager 0 over TCP
pair.Manager(1).Send(data, pair.PeerAddresses(0).TCP)
```

### Protocol Isolation

When testing specific protocols, disable the other to ensure test correctness:

```go
// UDP-only testing - TCP addresses will be invalid
pair, _ := transport.NewPipeManagerPair(transport.PipeManagerConfig{
    UDP:      true,
    TCP:      false,
    Handlers: [2]transport.MessageHandler{h0, h1},
})

peer := pair.PeerAddresses(1)
peer.UDP.IsValid() // true
peer.TCP.IsValid() // false - prevents accidental TCP usage
```

### Network Simulation with Manager Pairs

```go
pair, _ := transport.NewPipeManagerPair(transport.PipeManagerConfig{
    UDP:      true,
    Handlers: [2]transport.MessageHandler{h0, h1},
})

// Simulate 10% packet loss on UDP
pair.Pipe().SetCondition(transport.NetworkCondition{
    DropRate: 0.1,
})
```

## Factory Interface

```go
type Factory interface {
    CreateUDPConn(port int) (net.PacketConn, error)
    CreateTCPListener(port int) (net.Listener, error)
}
```

When `NodeConfig.TransportFactory` is nil, real OS sockets are used.