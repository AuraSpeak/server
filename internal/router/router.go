// Package router provides packet routing functionality for the server.
package router

import (
	"errors"
	"fmt"
	"sync"

	"github.com/auraspeak/protocol"
)

// PacketHandler is a function type that handles incoming packets from clients.
type PacketHandler func(packet *protocol.Packet, clientAddr string) error

// Router routes incoming packets to their registered handlers based on packet type.
type Router struct {
	handlers sync.Map // packetType -> PacketHandler
}

// NewRouter creates a new Router.
func NewRouter() *Router {
	return &Router{
		handlers: sync.Map{},
	}
}

// OnPacket registers a new PacketHandler for a specific packet type
// Example:
//
//	router.OnPacket(protocol.PacketTypeDebugHello, func(packet *protocol.Packet, clientAddr string) error {
//		fmt.Println("Received debug hello packet from client:", clientAddr)
//		return nil
//	})
func (r *Router) OnPacket(packetType protocol.PacketType, handler PacketHandler) {
	r.handlers.Store(packetType, handler)
}

// HandlePacket handles a packet from a client
// Example:
//
//	router.HandlePacket(packet, clientAddr)
//	if err != nil {
//		fmt.Println("Error handling packet:", err)
//	}
func (r *Router) HandlePacket(packet *protocol.Packet, clientAddr string) error {
	if !protocol.IsValidPacketType(packet.PacketHeader.PacketType) {
		return errors.New("invalid packet type")
	}
	handler, ok := r.handlers.Load(packet.PacketHeader.PacketType)
	if !ok {
		strPacketType, exists := protocol.PacketTypeMapType[packet.PacketHeader.PacketType]
		if !exists {
			strPacketType = fmt.Sprintf("Unknown(0x%02X)", packet.PacketHeader.PacketType)
		}
		return fmt.Errorf("no handler found for packet type: %s", strPacketType)
	}
	handlerFunc := handler.(PacketHandler)
	return handlerFunc(packet, clientAddr)
}

// ListRoutes prints all registered packet type routes to stdout.
func (r *Router) ListRoutes() {
	r.handlers.Range(func(key, value interface{}) bool {
		strPacketType, exists := protocol.PacketTypeMapType[key.(protocol.PacketType)]
		if !exists {
			strPacketType = fmt.Sprintf("Unknown(0x%02X)", key.(protocol.PacketType))
		}
		fmt.Printf("Packet type: %s\n", strPacketType)
		return true
	})
}
