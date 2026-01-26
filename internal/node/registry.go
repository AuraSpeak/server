package node

import "sync"

// NodeID is a unique identifier for a node.
type NodeID uint

// NodeRegistry maintains a registry of nodes by their IDs.
type NodeRegistry struct {
	mu    sync.RWMutex
	nodes map[NodeID]*Node
}

// NewNodeRegistry creates a new NodeRegistry.
func NewNodeRegistry() *NodeRegistry {
	return &NodeRegistry{nodes: make(map[NodeID]*Node)}
}
