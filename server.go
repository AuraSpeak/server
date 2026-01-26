// Package server provides a DTLS-based UDP server for handling incoming connections and packets.
package server

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/auraspeak/protocol"
	"github.com/auraspeak/server/internal/config"
	mdtls "github.com/auraspeak/server/internal/dtls"
	"github.com/auraspeak/server/internal/node"
	"github.com/auraspeak/server/internal/router"
	"github.com/auraspeak/server/pkg/command"
	"github.com/auraspeak/server/pkg/tracer"
	"github.com/pion/dtls/v3"
	log "github.com/sirupsen/logrus"
)

// Server represents a DTLS-based UDP server that handles incoming connections and routes packets.
type Server struct {
	Port int
	ln   net.Listener

	ctx context.Context

	ServerState

	IsAlive    int32
	shouldStop int32

	nm *node.NodeManager

	OutCommandCh chan command.InternalCommand

	packetRouter *router.Router
	TraceCh      chan tracer.TraceEvent

	dtlsConfig *dtls.Config

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
	srv := &Server{
		Port:         port,
		OutCommandCh: make(chan command.InternalCommand, 10),
		ctx:          ctx,
		packetRouter: router.NewRouter(),
	}

	dcfg := cfg
	if dcfg == nil {
		dcfg = &config.Config{}
		dcfg.Server.Env = "dev"
		dcfg.Server.DTLS.Certs.Mode = "self_signed"
	}

	// For mode=files: generate Cert/Key/CA if needed (GenerateCertificates is a no-op if all exist).
	mode := dcfg.Server.DTLS.Certs.Mode
	if mode == "" {
		if dcfg.Server.Env == "dev" {
			mode = "self_signed"
		} else {
			mode = "files"
		}
	}
	// If mode is file and env is dev, generate certificates
	if mode == "files" && dcfg.Server.Env == "dev" {
		if err := config.GenerateCertificates(dcfg); err != nil {
			log.WithField("caller", "server").WithError(err).Error("Failed to generate DTLS certificates")
			return nil
		}
	}

	var err error
	srv.dtlsConfig, err = mdtls.NewDTLSConfig(dcfg)
	if err != nil {
		log.WithField("caller", "server").WithError(err).Error("Failed to create DTLS config")
		return nil
	}
	srv.srvConfig = dcfg

	srv.OnPacket(protocol.PacketTypeDebugHello, handleDebugHello)
	srv.TraceCh = make(chan tracer.TraceEvent, 2000)
	srv.nm = node.NewNodeManager(8192, srv.packetRouter, srv.TraceCh)
	return srv
}

// OnPacket registers a new PacketHandler for a specific packet type
//
// Example:
//
//	server.OnPacket(protocol.PacketTypeDebugHello, func(packet *protocol.Packet, clientAddr string) error {
//		fmt.Println("Received text packet:", string(packet))
//		return nil
//	})
func (s *Server) OnPacket(packetType protocol.PacketType, handler router.PacketHandler) {
	log.WithField("caller", "server").Debugf("Registering packet handler for packet type: %s", protocol.PacketTypeMapType[packetType])
	s.packetRouter.OnPacket(packetType, handler)
}

// Run starts the Server and listens for incoming DTLS connections
func (s *Server) Run() error {
	s.packetRouter.ListRoutes()
	if atomic.LoadInt32(&s.IsAlive) == 1 {
		return errors.New("server is already running")
	}
	addr := &net.UDPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: s.Port,
	}
	var err error
	s.ln, err = dtls.Listen("udp", addr, s.dtlsConfig)
	if err != nil {
		return err
	}
	defer s.ln.Close()
	s.setIsAlive(true)
	log.WithField("caller", "server").Infof("Server started on port %d", s.Port)

	for {
		select {
		case <-s.ctx.Done():
			return nil
		case <-s.OutCommandCh:
		default:
		}
		shouldStop := atomic.LoadInt32(&s.shouldStop) == 1
		if shouldStop {
			break
		}
		conn, err := s.ln.Accept()
		if err != nil {
			log.WithField("caller", "server").WithError(err).Error("Accept Error")
			conn.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		dtlsConn, ok := conn.(*dtls.Conn)
		if ok {
			err = dtlsConn.HandshakeContext(ctx)
		}
		if !ok {
			log.WithField("caller", "server").Error("Accept Error: Connection is not a DTLS connection")
			conn.Close()
		}
		cancel()
		if err == nil {
			s.nm.RegisterConn(conn)
		}
	}
	s.setIsAlive(false)
	return nil
}

// Stop stops the Server and closes all connections
func (s *Server) Stop() {
	s.setShouldStop()

	if s.ln != nil {
		_ = s.ln.Close()
		s.ln = nil
	}
	s.nm.SendStop()
	s.nm.DisconnectAll()
}

// Broadcast sends a packet to all connected clients.
func (s *Server) Broadcast(packet *protocol.Packet) {
	s.nm.Broadcast(packet)
}

// setShouldStop marks the server for shutdown and notifies the state update channel.
func (s *Server) setShouldStop() {
	atomic.StoreInt32(&s.shouldStop, 1)
	select {
	case <-s.ctx.Done():
		return
	case s.OutCommandCh <- command.CmdUpdateServerState:
	default:
	}
	s.updated = true
	s.ShouldStop = true
}

// setIsAlive updates the server's alive status and notifies the state update channel.
func (s *Server) setIsAlive(val bool) {
	var v int32
	if val {
		v = 1
	}
	atomic.StoreInt32(&s.IsAlive, v)
	select {
	case <-s.ctx.Done():
		return
	case s.OutCommandCh <- command.CmdUpdateServerState:
	default:
	}
	s.updated = true
	s.ServerState.IsAlive = val
}
