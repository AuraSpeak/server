//go:build !debug
// +build !debug

package server

var debug = false

// debug is used as a global variable to check if the server is running in debug mode.
// This approach allows stripping special debug handlers in server handlers that are not allowed in release builds.
// These are only small changes that don't require big changes in the codebase.
