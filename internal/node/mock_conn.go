package node

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// mockConn is a mock implementation of net.Conn for testing
type mockConn struct {
	readData    []byte
	readErr     error
	writeData   []byte
	writeErr    error
	closeErr    error
	localAddr   net.Addr
	remoteAddr  net.Addr
	closed      bool
	mu          sync.RWMutex
	readCalled  bool
	writeCalled bool
	closeCalled bool
}

// NewMockConn creates a new mock connection (exported for tests)
func NewMockConn(localAddr, remoteAddr net.Addr) *mockConn {
	return &mockConn{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

// newMockConn creates a new mock connection (internal alias)
func newMockConn(localAddr, remoteAddr net.Addr) *mockConn {
	return NewMockConn(localAddr, remoteAddr)
}

// Read implements net.Conn
func (m *mockConn) Read(b []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readCalled = true

	if m.closed {
		return 0, io.EOF
	}

	if m.readErr != nil {
		return 0, m.readErr
	}

	if len(m.readData) == 0 {
		// Block instead of EOF, so connReadLoop continues
		// In real tests one should use setReadData
		return 0, io.EOF
	}

	n = copy(b, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

// SetReadDataLoop sets data that will be returned repeatedly
func (m *mockConn) SetReadDataLoop(data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// For loop tests: store data that is returned repeatedly
	m.readData = data
}

// Write implements net.Conn
func (m *mockConn) Write(b []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeCalled = true

	if m.closed {
		return 0, errors.New("connection closed")
	}

	if m.writeErr != nil {
		return 0, m.writeErr
	}

	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

// Close implements net.Conn
func (m *mockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalled = true
	m.closed = true
	return m.closeErr
}

// LocalAddr implements net.Conn
func (m *mockConn) LocalAddr() net.Addr {
	return m.localAddr
}

// RemoteAddr implements net.Conn
func (m *mockConn) RemoteAddr() net.Addr {
	return m.remoteAddr
}

// SetDeadline implements net.Conn
func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline implements net.Conn
func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline implements net.Conn
func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// SetReadData sets the data to be returned by Read
func (m *mockConn) SetReadData(data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readData = data
}

// SetReadError sets the error to be returned by Read
func (m *mockConn) SetReadError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readErr = err
}

// SetWriteError sets the error to be returned by Write
func (m *mockConn) SetWriteError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeErr = err
}

// GetWriteData returns the data written to the connection
func (m *mockConn) GetWriteData() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]byte, len(m.writeData))
	copy(result, m.writeData)
	return result
}

// IsClosed returns whether the connection is closed
func (m *mockConn) IsClosed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closed
}

// setReadData sets the data to be returned by Read (internal alias)
func (m *mockConn) setReadData(data []byte) {
	m.SetReadData(data)
}

// setReadError sets the error to be returned by Read (internal alias)
func (m *mockConn) setReadError(err error) {
	m.SetReadError(err)
}

// setWriteError sets the error to be returned by Write (internal alias)
func (m *mockConn) setWriteError(err error) {
	m.SetWriteError(err)
}

// getWriteData returns the data written to the connection (internal alias)
func (m *mockConn) getWriteData() []byte {
	return m.GetWriteData()
}

// isClosed returns whether the connection is closed (internal alias)
func (m *mockConn) isClosed() bool {
	return m.IsClosed()
}
