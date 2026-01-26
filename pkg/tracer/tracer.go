//go:build !debug
// +build !debug

// Package tracer provides tracing functionality (release build, no-op).
package tracer

import (
	"net"
	"time"
)

// TraceDirection indicates the direction of a trace event.
type TraceDirection string

const (
	// TraceIn indicates an incoming packet.
	TraceIn TraceDirection = "in"
	// TraceOut indicates an outgoing packet.
	TraceOut TraceDirection = "out"
)

// TraceEvent represents a trace event. In release builds it has the same shape as in debug
type TraceEvent struct {
	TS       time.Time
	Dir      TraceDirection
	Local    string
	Remote   string
	Len      int
	Payload  []byte
	ClientID int
}

// Tracer is a no-op tracer in release builds.
type Tracer struct{}

// NewTracer creates a new no-op tracer.
func NewTracer() *Tracer { return &Tracer{} }

// NewTracerWithChannel returns a no-op tracer in release builds.
func NewTracerWithChannel(ch chan TraceEvent) *Tracer { return &Tracer{} }

// Trace is a no-op in release builds.
func (t *Tracer) Trace(dir TraceDirection, local net.Addr, remote net.Addr, payload []byte) {}

// NewTraceEvent creates a new trace event. In release builds, returns an empty event.
func NewTraceEvent(dir TraceDirection, local string, remote string, payloadLen int, payload []byte, clientID int) TraceEvent {
	return TraceEvent{}
}
