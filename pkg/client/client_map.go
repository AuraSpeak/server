//go:build !debug
// +build !debug

// Package client provides client mapping functionality (release build, no-op).
package client

// TryRegisterClient is a no-op in release builds and always returns false.
func TryRegisterClient(remote string, id int) (registered bool) { return false }

// LookupClientID is a no-op in release builds and always returns 0, false.
func LookupClientID(remote string) (int, bool) { return 0, false }
