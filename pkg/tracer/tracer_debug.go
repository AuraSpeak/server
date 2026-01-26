//go:build debug
// +build debug

package tracer

import (
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// TraceDirection indicates the direction of a trace event.
type TraceDirection string

const (
	// TraceIn indicates an incoming packet.
	TraceIn TraceDirection = "in"
	// TraceOut indicates an outgoing packet.
	TraceOut TraceDirection = "out"
)

// TraceEvent represents a trace event with timing and payload information.
type TraceEvent struct {
	TS       time.Time      `json:"ts"`
	Dir      TraceDirection `json:"dir"`
	Local    string         `json:"local"`
	Remote   string         `json:"remote"`
	Len      int            `json:"len"`
	Payload  []byte         `json:"payload"`
	ClientID int            `json:"client_id"`
}

// Tracer traces network events and sends them to a channel.
type Tracer struct {
	ch chan TraceEvent // if nil, emitTrace is a no-op
}

// NewTracer creates a new Tracer with its own event channel.
func NewTracer() *Tracer {
	return &Tracer{
		ch: make(chan TraceEvent, 2000),
	}
}

// NewTracerWithChannel creates a tracer that sends events to the given channel.
// Used to wire the nodeManager's tracer to the Server's TraceCh.
func NewTracerWithChannel(ch chan TraceEvent) *Tracer {
	return &Tracer{ch: ch}
}

// NewTraceEvent creates a new trace event with the given parameters.
func NewTraceEvent(dir TraceDirection, local string, remote string, payloadLen int, payload []byte, clientID int) TraceEvent {
	return TraceEvent{
		TS:       time.Now(),
		Dir:      dir,
		Local:    local,
		Remote:   remote,
		Len:      payloadLen,
		Payload:  payload,
		ClientID: clientID,
	}
}

func (t *Tracer) emitTrace(dir TraceDirection, local, remote string, payload []byte, clientID int) {
	if t.ch == nil {
		return
	}

	if len(payload) > 1024 {
		payload = payload[:1024]
	}

	select {
	case t.ch <- NewTraceEvent(dir, local, remote, len(payload), payload, clientID):
	default:
	}
}

// Trace records a trace event for the given direction, addresses, and payload.
func (t *Tracer) Trace(dir TraceDirection, local net.Addr, remote net.Addr, payload []byte) {
	ls := ""
	remoteAddr := ""
	if local != nil {
		ls = local.String()
	}
	if remote != nil {
		remoteAddr = remote.String()
	}
	if ls == "" {
		ls = "unknown"
	}
	if remoteAddr == "" {
		remoteAddr = "unknown"
	}
	clientID, ok := lookupClientID(remoteAddr)
	if !ok {
		clientID = 0
	}
	log.WithField("caller", "server").Debugf("Trace registerd for userid: %d", clientID)
	t.emitTrace(dir, ls, remoteAddr, payload, clientID)
}
