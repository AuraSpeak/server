// Package node provides node management functionality.
package node

import "github.com/auraspeak/server/internal/router"

// Node represents a single node on the AuraSpeak instance.
type Node struct {
	ID NodeID
	nm *NodeManager
}

// NewNode creates a new Node with the specified connection buffer size and router.
func NewNode(
	connBufSize uint,
	router *router.Router,
) *Node {
	return &Node{
		nm: NewNodeManager(connBufSize, router, nil),
	}
}

// Stop stops the node and disconnects all connections.
func (n *Node) Stop() {
	n.nm.SendStop()
	n.nm.DisconnectAll()
}
