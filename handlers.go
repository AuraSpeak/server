// Package server provides packet handlers for the server.
package server

import (
	"strconv"

	"github.com/auraspeak/protocol"
	"github.com/auraspeak/server/pkg/client"
	log "github.com/sirupsen/logrus"
)

func handleDebugHello(packet *protocol.Packet, clientAddr string) error {
	if debug {
		return handleDebugHelloDebug(packet, clientAddr)
	}
	return handleDebugHelloRelease(packet, clientAddr)
}

func handleDebugHelloRelease(packet *protocol.Packet, clientAddr string) error {
	log.Warn("Debug Hello not implemented in release build")
	return nil
}

func handleDebugHelloDebug(packet *protocol.Packet, clientAddr string) error {
	id, err := strconv.Atoi(string(packet.Payload))
	if err != nil {
		log.WithField("caller", "server").WithError(err).Error("Error converting payload to integer")
		return nil
	}
	client.TryRegisterClient(clientAddr, id)
	return nil
}
