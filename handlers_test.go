package server

import (
	"strconv"
	"testing"

	"github.com/auraspeak/protocol"
	"github.com/stretchr/testify/assert"
)

func TestHandleDebugHelloRelease(t *testing.T) {
	// In release builds handleDebugHelloRelease should always return nil
	packet := &protocol.Packet{
		PacketHeader: protocol.Header{PacketType: protocol.PacketTypeDebugHello},
		Payload:      []byte("123"),
	}

	err := handleDebugHelloRelease(packet, "127.0.0.1:8080")
	assert.NoError(t, err)
}

func TestHandleDebugHelloDebug_ValidPayload(t *testing.T) {
	// These tests only work in debug builds
	// For release builds they are skipped
	if !debug {
		t.Skip("Skipping debug handler tests in release build")
	}

	tests := []struct {
		name    string
		payload string
		wantID  int
	}{
		{"simple number", "123", 123},
		{"zero", "0", 0},
		{"large number", "999999", 999999},
		{"single digit", "5", 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := &protocol.Packet{
				PacketHeader: protocol.Header{PacketType: protocol.PacketTypeDebugHello},
				Payload:      []byte(tt.payload),
			}

			err := handleDebugHelloDebug(packet, "127.0.0.1:8080")
			assert.NoError(t, err)
		})
	}
}

func TestHandleDebugHelloDebug_InvalidPayload(t *testing.T) {
	if !debug {
		t.Skip("Skipping debug handler tests in release build")
	}

	tests := []struct {
		name    string
		payload string
	}{
		{"non-numeric", "abc"},
		{"empty", ""},
		{"mixed", "123abc"},
		{"whitespace", " 123 "},
		{"negative", "-123"},
		{"float", "123.45"},
		{"leading zeros", "00123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := &protocol.Packet{
				PacketHeader: protocol.Header{PacketType: protocol.PacketTypeDebugHello},
				Payload:      []byte(tt.payload),
			}

			// handleDebugHelloDebug should log the error, but return nil
			err := handleDebugHelloDebug(packet, "127.0.0.1:8080")
			assert.NoError(t, err) // Handler always returns nil, even on errors
		})
	}
}

func TestHandleDebugHelloDebug_NilPacket(t *testing.T) {
	if !debug {
		t.Skip("Skipping debug handler tests in release build")
	}

	// nil packet should lead to a panic at strconv.Atoi
	assert.Panics(t, func() {
		_ = handleDebugHelloDebug(nil, "127.0.0.1:8080")
	})
}

func TestHandleDebugHelloDebug_VeryLargeNumber(t *testing.T) {
	if !debug {
		t.Skip("Skipping debug handler tests in release build")
	}

	// Very large number (should still work if it fits in int)
	largeNum := strconv.Itoa(int(^uint(0) >> 1)) // Max int
	packet := &protocol.Packet{
		PacketHeader: protocol.Header{PacketType: protocol.PacketTypeDebugHello},
		Payload:      []byte(largeNum),
	}

	err := handleDebugHelloDebug(packet, "127.0.0.1:8080")
	assert.NoError(t, err)
}

func TestHandleDebugHello(t *testing.T) {
	packet := &protocol.Packet{
		PacketHeader: protocol.Header{PacketType: protocol.PacketTypeDebugHello},
		Payload:      []byte("123"),
	}

	// handleDebugHello delegates to handleDebugHelloDebug or handleDebugHelloRelease
	err := handleDebugHello(packet, "127.0.0.1:8080")
	assert.NoError(t, err)
}
