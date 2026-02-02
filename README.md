# Server

The Server package provides the application-layer DTLS-UDP server for the AuraSpeak Project. It delegates networking to `github.com/auraspeak/network/server` and adds config (YAML), DTLS certs, packet handlers, broadcast, trace events and state/commands. It utilizes the [AuraSpeak Protocol](https://github.com/AuraSpeak/protocol).

---

## Requirements

GO Version: 1.25.1

Go dependencies:
- `github.com/auraspeak/network` for local development replaced: `replace github.com/auraspeak/network => ../network`
- `github.com/auraspeak/protocol` for local development replaced: `replace github.com/auraspeak/protocol => ../protocol`

Indirect:
- `pion/dtls`
- `logrus`
- `gopkg.in/yaml.v2`

---

## Structure

### Server

Application-layer server that wraps the network server. Holds `ServerState` (ShouldStop, IsAlive), `OutCommandCh` and `TraceCh`. `NewServer(port, ctx, cfg)` creates a server; if `cfg` is nil a minimal dev/self_signed config is used.

### handlers

Packet handlers, e.g. `DebugHello` (release: no-op; debug: client registration).

### internal/config

YAML config: server.port, host, env; server.dtls.certs.mode (`self_signed` | `files`); security, tuning.

### internal/dtls

Builds DTLS config from config.

### pkg/client

Client map (debug build: TryRegisterClient, LookupClientID; release: no-op).

### pkg/command

Defines `InternalCommand`, e.g. `CmdUpdateServerState`.

### pkg/debugui

Config for the debug-ui.

### pkg/tracer

TraceEvent (direction, payload); written to TraceCh.

---

## Quick start

`Server`
- Port
- Context
- Config (optional; nil → dev/self_signed). Use `config.Load()` to load YAML. Env: `dev` or `prod`. Certs: `self_signed` or `files` (Cert, Key, CA).

`Functions` / `Methods`
- `NewServer(port, ctx, cfg)` creates a new server (returns nil if DTLS config fails)
- `OnPacket(packetType, handler)` registers a handler; `PacketHandler` is `func(packet *protocol.Packet, clientAddr string) error`
- `Run()` listens and blocks
- `Stop()` closes the listener and all clients
- `Broadcast(packet)` sends a packet to all connected clients

---

## Testing

Run `go test ./...` to test.

---

## License

[License](./LICENSE)
