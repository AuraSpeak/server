package router

import (
	"errors"
	"testing"

	"github.com/auraspeak/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRouter(t *testing.T) {
	r := NewRouter()
	require.NotNil(t, r)
	// Test that handlers map works by storing and loading a value
	r.handlers.Store(protocol.PacketTypeDebugHello, func(*protocol.Packet, string) error { return nil })
	_, ok := r.handlers.Load(protocol.PacketTypeDebugHello)
	assert.True(t, ok)
}

func TestOnPacket(t *testing.T) {
	r := NewRouter()
	handler := func(packet *protocol.Packet, clientAddr string) error {
		return nil
	}

	r.OnPacket(protocol.PacketTypeDebugHello, handler)
	handlerFromMap, ok := r.handlers.Load(protocol.PacketTypeDebugHello)
	require.True(t, ok)
	assert.NotNil(t, handlerFromMap)

	// Test Handler-Überschreibung
	handler2 := func(packet *protocol.Packet, clientAddr string) error {
		return nil
	}
	r.OnPacket(protocol.PacketTypeDebugHello, handler2)
	handlerFromMap2, ok2 := r.handlers.Load(protocol.PacketTypeDebugHello)
	require.True(t, ok2)
	assert.NotNil(t, handlerFromMap2)
}

func TestHandlePacket_Success(t *testing.T) {
	r := NewRouter()
	called := false
	clientAddr := "127.0.0.1:8080"
	handler := func(packet *protocol.Packet, clientAddr string) error {
		called = true
		assert.Equal(t, "127.0.0.1:8080", clientAddr)
		return nil
	}

	r.OnPacket(protocol.PacketTypeDebugHello, handler)

	packet := &protocol.Packet{
		PacketHeader: protocol.Header{PacketType: protocol.PacketTypeDebugHello},
		Payload:      []byte("test"),
	}

	err := r.HandlePacket(packet, clientAddr)
	assert.NoError(t, err)
	assert.True(t, called)
}

func TestHandlePacket_HandlerError(t *testing.T) {
	r := NewRouter()
	expectedErr := errors.New("handler error")
	handler := func(packet *protocol.Packet, clientAddr string) error {
		return expectedErr
	}

	r.OnPacket(protocol.PacketTypeDebugHello, handler)

	packet := &protocol.Packet{
		PacketHeader: protocol.Header{PacketType: protocol.PacketTypeDebugHello},
		Payload:      []byte("test"),
	}

	err := r.HandlePacket(packet, "127.0.0.1:8080")
	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
}

func TestHandlePacket_InvalidPacketType(t *testing.T) {
	r := NewRouter()
	packet := &protocol.Packet{
		PacketHeader: protocol.Header{PacketType: protocol.PacketTypeNone},
		Payload:      []byte("test"),
	}

	err := r.HandlePacket(packet, "127.0.0.1:8080")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid packet type")
}

func TestHandlePacket_NoHandler(t *testing.T) {
	r := NewRouter()
	packet := &protocol.Packet{
		PacketHeader: protocol.Header{PacketType: protocol.PacketTypeDebugAny},
		Payload:      []byte("test"),
	}

	err := r.HandlePacket(packet, "127.0.0.1:8080")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no handler found")
}

func TestHandlePacket_NilPacket(t *testing.T) {
	r := NewRouter()
	handler := func(packet *protocol.Packet, clientAddr string) error {
		return nil
	}
	r.OnPacket(protocol.PacketTypeDebugHello, handler)

	// nil packet should lead to a panic, since protocol.IsValidPacketType accesses nil
	// But we test it anyway
	assert.Panics(t, func() {
		_ = r.HandlePacket(nil, "127.0.0.1:8080")
	})
}

func TestListRoutes_Empty(t *testing.T) {
	r := NewRouter()
	// ListRoutes only outputs, should not crash
	r.ListRoutes()
}

func TestListRoutes_Multiple(t *testing.T) {
	r := NewRouter()
	handler := func(packet *protocol.Packet, clientAddr string) error {
		return nil
	}

	r.OnPacket(protocol.PacketTypeDebugHello, handler)
	r.OnPacket(protocol.PacketTypeDebugAny, handler)

	// ListRoutes only outputs, should not crash
	r.ListRoutes()
}

func TestHandlePacket_ConcurrentRegistration(t *testing.T) {
	r := NewRouter()
	done := make(chan bool, 2)

	// Concurrent Handler-Registrierung
	go func() {
		handler := func(packet *protocol.Packet, clientAddr string) error {
			return nil
		}
		r.OnPacket(protocol.PacketTypeDebugHello, handler)
		done <- true
	}()

	go func() {
		handler := func(packet *protocol.Packet, clientAddr string) error {
			return nil
		}
		r.OnPacket(protocol.PacketTypeDebugAny, handler)
		done <- true
	}()

	<-done
	<-done

	// Both handlers should be registered
	_, ok1 := r.handlers.Load(protocol.PacketTypeDebugHello)
	_, ok2 := r.handlers.Load(protocol.PacketTypeDebugAny)
	assert.True(t, ok1)
	assert.True(t, ok2)
}

func TestHandlePacket_HandlerPanic(t *testing.T) {
	r := NewRouter()
	handler := func(packet *protocol.Packet, clientAddr string) error {
		panic("handler panic")
	}

	r.OnPacket(protocol.PacketTypeDebugHello, handler)

	packet := &protocol.Packet{
		PacketHeader: protocol.Header{PacketType: protocol.PacketTypeDebugHello},
		Payload:      []byte("test"),
	}

	assert.Panics(t, func() {
		_ = r.HandlePacket(packet, "127.0.0.1:8080")
	})
}
