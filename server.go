// Package server provides a DTLS-based UDP server that delegates networking to github.com/auraspeak/network/server.
package server

import (
	"context"
	"errors"
	"sync/atomic"

	netserver "github.com/auraspeak/network/server"
	"github.com/auraspeak/protocol"
	"github.com/auraspeak/server/internal/config"
	mdtls "github.com/auraspeak/server/internal/dtls"
	"github.com/auraspeak/server/pkg/command"
	"github.com/auraspeak/server/pkg/tracer"
	log "github.com/sirupsen/logrus"
)

// Server is the application-layer server: it wraps the network server and adds state and commands.
type Server struct {
	ns *netserver.Server

	Port int
	ctx  context.Context

	ServerState

	IsAlive    int32
	shouldStop int32

	OutCommandCh chan command.InternalCommand
	TraceCh      chan tracer.TraceEvent

	srvConfig *config.Config
}

// ServerState holds the current state of the server.
type ServerState struct {
	updated    bool `json:"-"`
	ShouldStop bool `json:"shouldStop"`
	IsAlive    bool `json:"isAlive"`
}

// NewServer creates a new Server. cfg may be nil; then a minimal dev/self_signed config is used.
// Returns nil if DTLS config cannot be built.
func NewServer(port int, ctx context.Context, cfg *config.Config) *Server {
	dcfg := cfg
	if dcfg == nil {
		dcfg = &config.Config{}
		dcfg.Server.Env = "dev"
		dcfg.Server.DTLS.Certs.Mode = "self_signed"
	}

	mode := dcfg.Server.DTLS.Certs.Mode
	if mode == "" {
		if dcfg.Server.Env == "dev" {
			mode = "self_signed"
		} else {
			mode = "files"
		}
	}
	if mode == "files" && dcfg.Server.Env == "dev" {
		if err := config.GenerateCertificates(dcfg); err != nil {
			log.WithField("caller", "server").WithError(err).Error("Failed to generate DTLS certificates")
			return nil
		}
	}

	dtlsConfig, err := mdtls.NewDTLSConfig(dcfg)
	if err != nil {
		log.WithField("caller", "server").WithError(err).Error("Failed to create DTLS config")
		return nil
	}

	traceCh := make(chan tracer.TraceEvent, 2000)
	traceFunc := func(local, remote, dir string, payload []byte) {
		var d tracer.TraceDirection
		if dir == "in" {
			d = tracer.TraceIn
		} else {
			d = tracer.TraceOut
		}
		ev := tracer.NewTraceEvent(d, local, remote, len(payload), payload, 0)
		select {
		case traceCh <- ev:
		default:
		}
	}

	cfgNet := netserver.ServerConfig{
		Port:        port,
		DTLSConfig:  dtlsConfig,
		ConnBufSize: 8192,
		TraceFunc:   traceFunc,
	}
	ns := netserver.NewServer(cfgNet)

	srv := &Server{
		ns:           ns,
		Port:         port,
		ctx:          ctx,
		OutCommandCh: make(chan command.InternalCommand, 10),
		TraceCh:      traceCh,
		srvConfig:    dcfg,
	}
	ns.OnPacket(protocol.PacketTypeDebugHello, func(packet *protocol.Packet, peer string) error {
		return handleDebugHello(packet, peer)
	})
	return srv
}

// PacketHandler is the application-layer handler type (peer is client address).
type PacketHandler func(packet *protocol.Packet, clientAddr string) error

// OnPacket registers a handler for a packet type.
func (s *Server) OnPacket(packetType protocol.PacketType, handler PacketHandler) {
	log.WithField("caller", "server").Debugf("Registering packet handler for packet type: %s", protocol.PacketTypeMapType[packetType])
	s.ns.OnPacket(packetType, func(packet *protocol.Packet, peer string) error {
		return handler(packet, peer)
	})
}

// Run starts the server and listens for incoming DTLS connections.
func (s *Server) Run() error {
	if atomic.LoadInt32(&s.IsAlive) == 1 {
		return errors.New("server is already running")
	}
	s.setIsAlive(true)
	defer s.setIsAlive(false)
	return s.ns.Run(s.ctx)
}

// Stop stops the server and closes all connections.
func (s *Server) Stop() {
	s.setShouldStop()
	s.ns.Stop()
}

// Broadcast sends a packet to all connected clients.
func (s *Server) Broadcast(packet *protocol.Packet) {
	s.ns.Broadcast(packet)
}

func (s *Server) setShouldStop() {
	atomic.StoreInt32(&s.shouldStop, 1)
	s.updated = true
	s.ShouldStop = true
	select {
	case <-s.ctx.Done():
		return
	case s.OutCommandCh <- command.CmdUpdateServerState:
	default:
	}
}

func (s *Server) setIsAlive(val bool) {
	var v int32
	if val {
		v = 1
	}
	atomic.StoreInt32(&s.IsAlive, v)
	s.updated = true
	s.ServerState.IsAlive = val
	select {
	case <-s.ctx.Done():
		return
	case s.OutCommandCh <- command.CmdUpdateServerState:
	default:
	}
}
