package server

import (
	"strconv"
	"testing"

	"github.com/auraspeak/protocol"
	log "github.com/sirupsen/logrus"
)

func init() {
	// Reduce log output during fuzzing so the fuzzer is not slowed and logs are not flooded.
	log.SetLevel(log.PanicLevel)
}

// FuzzHandleDebugHello fuzzes handleDebugHello with arbitrary raw bytes.
// Data is decoded via protocol.Decode; on success handleDebugHello is called.
// Invalid inputs must not panic; both release and debug handler paths must be stable.
func FuzzHandleDebugHello(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xFF})
	f.Add([]byte{0x90})
	f.Add([]byte{0x90, 0x00})
	f.Add([]byte{0x90, '1', '2', '3'})
	f.Add([]byte{0x01})
	f.Add(append([]byte{0x90}, make([]byte, 100)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		packet, err := protocol.Decode(data)
		if err != nil {
			return
		}
		_ = handleDebugHello(packet, "127.0.0.1:0")
	})
}

// FuzzParseDebugHelloPayload fuzzes the same parsing logic as handleDebugHelloDebug: strconv.Atoi(string(payload)).
// Ensures robustness for invalid characters, very long strings, empty slices, etc.
func FuzzParseDebugHelloPayload(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("123"))
	f.Add([]byte("0"))
	f.Add([]byte("999999"))
	f.Add([]byte("not a number"))
	f.Add([]byte{0xFF, 0xFE})
	f.Add(make([]byte, 1000))
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = strconv.Atoi(string(payload))
	})
}
