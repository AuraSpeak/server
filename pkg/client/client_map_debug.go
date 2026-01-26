//go:build debug
// +build debug

package client

import (
	"sync"
)

var dbgAddrToClientMap = sync.Map{}

// TryRegisterClient registers a client with the given remote address and ID.
func TryRegisterClient(remote string, id int) (registered bool) {
	dbgAddrToClientMap.Store(remote, id)
	return true
}

// LookupClientID looks up the client ID for the given remote address.
func LookupClientID(remote string) (int, bool) {
	v, ok := dbgAddrToClientMap.Load(remote)
	if !ok {
		return 0, false
	}
	id, ok := v.(int)
	return id, ok
}
