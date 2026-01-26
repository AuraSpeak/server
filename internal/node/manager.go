package node

import (
	"net"
	"sync"

	"github.com/auraspeak/protocol"
	"github.com/auraspeak/server/internal/router"
	"github.com/auraspeak/server/pkg/tracer"
	log "github.com/sirupsen/logrus"
)

// NodeManager manages network connections and routes incoming packets.
type NodeManager struct {
	connBufSize uint
	conns       sync.Map // string -> net.Conn

	router *router.Router

	tracer *tracer.Tracer
}

// NewNodeManager creates a new NodeManager with the specified connection buffer size, router, and trace channel.
func NewNodeManager(
	connBufSize uint,
	router *router.Router,
	traceCh chan tracer.TraceEvent,
) *NodeManager {
	return &NodeManager{
		connBufSize: connBufSize,
		router:      router,
		tracer:      tracer.NewTracerWithChannel(traceCh),
	}
}

// RegisterConn registers a new connection and starts reading packets from it.
func (nm *NodeManager) RegisterConn(conn net.Conn) {
	nm.conns.Store(conn.RemoteAddr().String(), conn)

	go nm.connReadLoop(conn)
}

func (nm *NodeManager) connReadLoop(conn net.Conn) {
	buf := make([]byte, nm.connBufSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.WithError(err).WithField("caller", "node manager").Error("Client Read")
			nm.connUnregister(conn)
			return
		}
		b := make([]byte, n)
		copy(b, buf[:n])
		packet, err := protocol.Decode(b)
		if err != nil {
			log.WithField("caller", "node manager").WithError(err).Error("Error Decoding Packet")
			continue
		}
		nm.tracer.Trace(tracer.TraceIn, conn.LocalAddr(), conn.RemoteAddr(), packet.Payload)
		if err := nm.router.HandlePacket(packet, conn.RemoteAddr().String()); err != nil {
			log.WithField("caller", "node manager").WithError(err).Error("Handling Packet")
		}
	}
}

func (nm *NodeManager) connUnregister(conn net.Conn) {
	nm.conns.Delete(conn.RemoteAddr().String())
	if err := conn.Close(); err != nil {
		log.WithField("caller", "node manager").WithError(err).Errorf("Failed to disconnect %v", conn.RemoteAddr())
	}
}

// Broadcast sends a packet to all registered connections.
func (nm *NodeManager) Broadcast(packet *protocol.Packet) {
	nm.conns.Range(func(key, mapConn any) bool {
		conn, ok := mapConn.(net.Conn)
		if !ok {
			return true
		}
		if _, err := conn.Write(packet.Encode()); err != nil {
			nm.conns.Delete(key)
			return true
		}
		nm.tracer.Trace(tracer.TraceOut, conn.LocalAddr(), conn.RemoteAddr(), packet.Payload)
		return true
	})
}

// DisconnectAll disconnects all registered connections.
func (nm *NodeManager) DisconnectAll() {
	nm.conns.Range(func(key, value any) bool { nm.conns.Delete(key); return true })
}

// SendStop sends a disconnect packet to all registered connections and closes them.
func (nm *NodeManager) SendStop() {
	hdr := protocol.Header{PacketType: protocol.PacketTypeClientNeedsDisconnect}
	pkg := protocol.Packet{PacketHeader: hdr, Payload: []byte("Server Stops")}
	nm.conns.Range(func(key, value any) bool {
		go func() {
			conn, ok := value.(net.Conn)
			if !ok {
				return
			}
			if _, err := conn.Write(pkg.Encode()); err != nil {
				nm.conns.Delete(key)
				return
			}
			nm.tracer.Trace(tracer.TraceOut, conn.LocalAddr(), conn.RemoteAddr(), pkg.Payload)
		}()
		return true
	})
}
