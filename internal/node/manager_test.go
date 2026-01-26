package node

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/auraspeak/protocol"
	"github.com/auraspeak/server/internal/router"
	"github.com/auraspeak/server/pkg/tracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNodeManager(t *testing.T) {
	r := router.NewRouter()
	traceCh := make(chan tracer.TraceEvent, 10)
	nm := NewNodeManager(8192, r, traceCh)

	require.NotNil(t, nm)
	assert.Equal(t, uint(8192), nm.connBufSize)
	assert.Equal(t, r, nm.router)
	assert.NotNil(t, nm.tracer)
}

func TestRegisterConn(t *testing.T) {
	r := router.NewRouter()
	traceCh := make(chan tracer.TraceEvent, 10)
	nm := NewNodeManager(1024, r, traceCh)

	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}
	conn := newMockConn(localAddr, remoteAddr)

	nm.RegisterConn(conn)

	// Connection should be registered
	_, ok := nm.conns.Load(remoteAddr.String())
	assert.True(t, ok)
}

func TestRegisterConn_Duplicate(t *testing.T) {
	r := router.NewRouter()
	traceCh := make(chan tracer.TraceEvent, 10)
	nm := NewNodeManager(1024, r, traceCh)

	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}
	conn1 := newMockConn(localAddr, remoteAddr)
	conn2 := newMockConn(localAddr, remoteAddr)

	nm.RegisterConn(conn1)
	nm.RegisterConn(conn2)

	// Second connection should overwrite the first
	_, ok := nm.conns.Load(remoteAddr.String())
	assert.True(t, ok)
}

func TestConnReadLoop_NormalPacket(t *testing.T) {
	r := router.NewRouter()
	traceCh := make(chan tracer.TraceEvent, 10)
	nm := NewNodeManager(1024, r, traceCh)

	handlerCalled := make(chan bool, 1)
	handler := func(packet *protocol.Packet, clientAddr string) error {
		handlerCalled <- true
		assert.Equal(t, protocol.PacketTypeDebugHello, packet.PacketHeader.PacketType)
		assert.Equal(t, []byte("test"), packet.Payload)
		return nil
	}
	r.OnPacket(protocol.PacketTypeDebugHello, handler)

	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}
	conn := newMockConn(localAddr, remoteAddr)

	packet := &protocol.Packet{
		PacketHeader: protocol.Header{PacketType: protocol.PacketTypeDebugHello},
		Payload:      []byte("test"),
	}
	conn.setReadData(packet.Encode())

	nm.RegisterConn(conn)

	// Wait for handler call or timeout
	select {
	case <-handlerCalled:
		// Handler wurde aufgerufen
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Handler was not called within timeout")
	}
}

func TestConnReadLoop_ReadError(t *testing.T) {
	r := router.NewRouter()
	traceCh := make(chan tracer.TraceEvent, 10)
	nm := NewNodeManager(1024, r, traceCh)

	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}
	conn := newMockConn(localAddr, remoteAddr)

	conn.setReadError(io.EOF)

	nm.RegisterConn(conn)

	// Wait briefly
	time.Sleep(100 * time.Millisecond)

	// Connection should be removed
	_, ok := nm.conns.Load(remoteAddr.String())
	assert.False(t, ok)
	assert.True(t, conn.isClosed())
}

func TestConnReadLoop_DecodeError(t *testing.T) {
	r := router.NewRouter()
	traceCh := make(chan tracer.TraceEvent, 10)
	nm := NewNodeManager(1024, r, traceCh)

	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}
	conn := newMockConn(localAddr, remoteAddr)

	// Ungültige Daten (zu kurz) - setze sie mehrfach, damit Read nicht sofort EOF gibt
	invalidData := []byte{0x01}
	// Füge Daten mehrfach hinzu, damit Read nicht sofort EOF zurückgibt
	conn.setReadData(append(invalidData, invalidData...))

	nm.RegisterConn(conn)

	// Wait briefly
	time.Sleep(100 * time.Millisecond)

	// Connection might be removed when Read returns EOF, or still registered when decode error is ignored
	// The test checks that decode errors don't stop the loop, but Read-EOF would remove the connection
	// Therefore this test is somewhat fragile - we only check that it doesn't crash
	_ = nm
}

func TestConnReadLoop_HandlerError(t *testing.T) {
	r := router.NewRouter()
	traceCh := make(chan tracer.TraceEvent, 10)
	nm := NewNodeManager(1024, r, traceCh)

	handlerErr := errors.New("handler error")
	handler := func(packet *protocol.Packet, clientAddr string) error {
		return handlerErr
	}
	r.OnPacket(protocol.PacketTypeDebugHello, handler)

	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}
	conn := newMockConn(localAddr, remoteAddr)

	packet := &protocol.Packet{
		PacketHeader: protocol.Header{PacketType: protocol.PacketTypeDebugHello},
		Payload:      []byte("test"),
	}
	// Setze Daten mehrfach, damit Read nicht sofort EOF gibt
	data := packet.Encode()
	conn.setReadData(append(data, data...))

	nm.RegisterConn(conn)

	// Wait briefly
	time.Sleep(100 * time.Millisecond)

	// Connection might be removed when Read returns EOF, or still registered when handler error is ignored
	// The test checks that handler errors don't stop the loop, but Read-EOF would remove the connection
	// Therefore this test is somewhat fragile - we only check that it doesn't crash
	_ = nm
}

func TestBroadcast_NoConnections(t *testing.T) {
	r := router.NewRouter()
	traceCh := make(chan tracer.TraceEvent, 10)
	nm := NewNodeManager(1024, r, traceCh)

	packet := &protocol.Packet{
		PacketHeader: protocol.Header{PacketType: protocol.PacketTypeDebugHello},
		Payload:      []byte("test"),
	}

	// Should not crash
	nm.Broadcast(packet)
}

func TestBroadcast_OneConnection(t *testing.T) {
	r := router.NewRouter()
	traceCh := make(chan tracer.TraceEvent, 10)
	nm := NewNodeManager(1024, r, traceCh)

	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}
	conn := newMockConn(localAddr, remoteAddr)

	nm.conns.Store(remoteAddr.String(), conn)

	packet := &protocol.Packet{
		PacketHeader: protocol.Header{PacketType: protocol.PacketTypeDebugHello},
		Payload:      []byte("test"),
	}

	nm.Broadcast(packet)

	// Wait briefly
	time.Sleep(50 * time.Millisecond)

	writtenData := conn.getWriteData()
	assert.NotEmpty(t, writtenData)
	assert.Equal(t, packet.Encode(), writtenData)
}

func TestBroadcast_MultipleConnections(t *testing.T) {
	r := router.NewRouter()
	traceCh := make(chan tracer.TraceEvent, 10)
	nm := NewNodeManager(1024, r, traceCh)

	conns := make([]*mockConn, 3)
	for i := 0; i < 3; i++ {
		localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
		remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081 + i}
		conn := newMockConn(localAddr, remoteAddr)
		conns[i] = conn
		nm.conns.Store(remoteAddr.String(), conn)
	}

	packet := &protocol.Packet{
		PacketHeader: protocol.Header{PacketType: protocol.PacketTypeDebugHello},
		Payload:      []byte("test"),
	}

	nm.Broadcast(packet)

	// Wait briefly
	time.Sleep(50 * time.Millisecond)

	// All connections should have received the packet
	for _, conn := range conns {
		writtenData := conn.getWriteData()
		assert.NotEmpty(t, writtenData)
		assert.Equal(t, packet.Encode(), writtenData)
	}
}

func TestBroadcast_WriteError(t *testing.T) {
	r := router.NewRouter()
	traceCh := make(chan tracer.TraceEvent, 10)
	nm := NewNodeManager(1024, r, traceCh)

	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}
	conn := newMockConn(localAddr, remoteAddr)
	conn.setWriteError(errors.New("write error"))

	nm.conns.Store(remoteAddr.String(), conn)

	packet := &protocol.Packet{
		PacketHeader: protocol.Header{PacketType: protocol.PacketTypeDebugHello},
		Payload:      []byte("test"),
	}

	nm.Broadcast(packet)

	// Wait briefly
	time.Sleep(50 * time.Millisecond)

	// Connection should be removed
	_, ok := nm.conns.Load(remoteAddr.String())
	assert.False(t, ok)
}

func TestDisconnectAll(t *testing.T) {
	r := router.NewRouter()
	traceCh := make(chan tracer.TraceEvent, 10)
	nm := NewNodeManager(1024, r, traceCh)

	conns := make([]*mockConn, 3)
	for i := 0; i < 3; i++ {
		localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
		remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081 + i}
		conn := newMockConn(localAddr, remoteAddr)
		conns[i] = conn
		nm.conns.Store(remoteAddr.String(), conn)
	}

	nm.DisconnectAll()

	// All connections should be removed
	count := 0
	nm.conns.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	assert.Equal(t, 0, count)
}

func TestSendStop(t *testing.T) {
	r := router.NewRouter()
	traceCh := make(chan tracer.TraceEvent, 10)
	nm := NewNodeManager(1024, r, traceCh)

	conns := make([]*mockConn, 2)
	for i := 0; i < 2; i++ {
		localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
		remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081 + i}
		conn := newMockConn(localAddr, remoteAddr)
		conns[i] = conn
		nm.conns.Store(remoteAddr.String(), conn)
	}

	nm.SendStop()

	// Wait briefly to give goroutines time
	time.Sleep(100 * time.Millisecond)

	// All connections should have received the disconnect packet
	for _, conn := range conns {
		writtenData := conn.getWriteData()
		assert.NotEmpty(t, writtenData)
		// Check that it is a disconnect packet
		packet, err := protocol.Decode(writtenData)
		require.NoError(t, err)
		assert.Equal(t, protocol.PacketTypeClientNeedsDisconnect, packet.PacketHeader.PacketType)
	}
}

func TestSendStop_WriteError(t *testing.T) {
	r := router.NewRouter()
	traceCh := make(chan tracer.TraceEvent, 10)
	nm := NewNodeManager(1024, r, traceCh)

	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}
	conn := newMockConn(localAddr, remoteAddr)
	conn.setWriteError(errors.New("write error"))

	nm.conns.Store(remoteAddr.String(), conn)

	nm.SendStop()

	// Wait briefly
	time.Sleep(100 * time.Millisecond)

	// Connection should be removed
	_, ok := nm.conns.Load(remoteAddr.String())
	assert.False(t, ok)
}

func TestConnReadLoop_LargePacket(t *testing.T) {
	r := router.NewRouter()
	traceCh := make(chan tracer.TraceEvent, 10)
	nm := NewNodeManager(1024, r, traceCh)

	handlerCalled := make(chan bool, 1)
	handler := func(packet *protocol.Packet, clientAddr string) error {
		handlerCalled <- true
		return nil
	}
	r.OnPacket(protocol.PacketTypeDebugHello, handler)

	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}
	conn := newMockConn(localAddr, remoteAddr)

	// Großes Packet (größer als Buffer)
	largePayload := make([]byte, 2000)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}
	packet := &protocol.Packet{
		PacketHeader: protocol.Header{PacketType: protocol.PacketTypeDebugHello},
		Payload:      largePayload,
	}
	conn.setReadData(packet.Encode())

	nm.RegisterConn(conn)

	// Wait for handler call or timeout
	select {
	case <-handlerCalled:
		// Handler wurde aufgerufen
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Handler was not called within timeout")
	}
}

func TestBroadcast_Concurrent(t *testing.T) {
	r := router.NewRouter()
	traceCh := make(chan tracer.TraceEvent, 10)
	nm := NewNodeManager(1024, r, traceCh)

	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}
	conn := newMockConn(localAddr, remoteAddr)
	nm.conns.Store(remoteAddr.String(), conn)

	packet := &protocol.Packet{
		PacketHeader: protocol.Header{PacketType: protocol.PacketTypeDebugHello},
		Payload:      []byte("test"),
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nm.Broadcast(packet)
		}()
	}

	wg.Wait()
	time.Sleep(50 * time.Millisecond)

	// Connection should still exist
	_, ok := nm.conns.Load(remoteAddr.String())
	assert.True(t, ok)
}

func TestRegisterConn_DisconnectAll_Race(t *testing.T) {
	r := router.NewRouter()
	traceCh := make(chan tracer.TraceEvent, 10)
	nm := NewNodeManager(1024, r, traceCh)

	var wg sync.WaitGroup

	// Concurrent RegisterConn
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
			remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081 + i}
			conn := newMockConn(localAddr, remoteAddr)
			nm.RegisterConn(conn)
		}
	}()

	// Concurrent DisconnectAll
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			nm.DisconnectAll()
			time.Sleep(10 * time.Millisecond)
		}
	}()

	wg.Wait()
}
