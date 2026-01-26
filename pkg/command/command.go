// Package command defines internal server commands.
package command

// InternalCommand represents a command type for internal server operations.
type InternalCommand int

// Internal commands for server operations.
const (
	// CmdUpdateServerState signals that the server state should be updated.
	CmdUpdateServerState InternalCommand = iota
)
