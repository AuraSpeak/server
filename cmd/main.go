package main

import (
	"context"
	"log"

	"github.com/auraspeak/protocol"
	"github.com/auraspeak/server"
	"github.com/auraspeak/server/internal/config"
)

func main() {
	ctx := context.Background()
	cfg := config.Load()
	srv := server.NewServer(8080, ctx, cfg)
	if srv == nil {
		log.Fatal("Failed to create server: DTLS config error")
	}
	srv.OnPacket(protocol.PacketTypeDebugAny, func(packet *protocol.Packet, clientAddr string) error {
		srv.Broadcast(packet)
		return nil
	})
	srv.Run()
}
