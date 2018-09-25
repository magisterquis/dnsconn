// dnsconnserver is the server side of dnsconn.
package dnsconnserver

/*
 * server.go
 * Server side of dnsconnserver
 * By J. Stuart McMurray
 * Created 20180923
 * Last Modified 20180923
 */

import (
	"errors"
	"net"
	"sync"
)

// ErrListenerClosed is returned from Accept and AcceptServerConn when
// they have been called on a listener closed with Close after there
// are no more new queued connections.
var ErrListenerClosed = errors.New("listener closed")

// Config is used to configure a new Server.
type Config struct {
	// Domains holds the initial set of domains to serve.  Domains may be
	// added or removed with Server's AddDomain and RemoveDomain methods.
	Domains []string

	// Backlog sets how many unaccepted connections are held before new
	// connections are refused.  A backlog of 0 will cause processing to
	// stop if connections are pending.
	Backlog uint

	// Parse specifies the parsing function to use.  Please see the
	// documentation for Parser and DefaultParser for more details and an
	// example
	Parse Parser
}

// DefaultConfig holds sensible defaults for Config.
var DefaultConfig = Config{
	Domains: []string{"dnsconn.test"},
	Backlog: 10,
	Parse:   DefaultParser,
}

// Server represents the server side of dnsconn.  It's responsible for reading
// DNS queries and sending replies via its underlying transport.  Server
// implements net.Listener.
type Server struct {
	packetConn net.PacketConn /* Underlying transport */
	closed     bool           /* If Close() was called */
	lock       *sync.Mutex
	parse      Parser /* Question parsing function */

	domains  map[string]struct{} /* Served domains */
	domainsL *sync.Mutex

	newConns chan *Conn     /* Accept backlog */
	conns    map[uint]*Conn /* Open connections */
	connsL   *sync.Mutex

	err error /* First error encountered */
	wg  *sync.WaitGroup
}

// New initializes a new Server using pc as its underlying transport.
func New(pc net.PacketConn, conf Config) *Server {
	/* Server to return */
	s := Server{
		packetConn: pc,
		lock:       new(sync.Mutex),
		parse:      conf.Parse,
		domains:    make(map[string]struct{}),
		domainsL:   new(sync.Mutex),
		newConns:   make(chan *Conn, int(conf.Backlog)),
		conns:      make(map[uint]*Conn),
		connsL:     new(sync.Mutex),
		wg:         new(sync.WaitGroup),
	}

	/* Add served domains */
	for _, d := range conf.Domains {
		s.domains[d] = struct{}{}
	}

	s.wg.Add(1) /* For the listener */
	return &s
}

// AddDomain causes s to answer queries for subdomains of d.
func (s *Server) AddDomain(d string) {
	s.domainsL.Lock()
	defer s.domainsL.Unlock()
	s.domains[d] = struct{}{}
}

// RemoveDomain causes s to not answer queries for d.
func (s *Server) RemoveDomain(d string) {
	s.domainsL.Lock()
	defer s.domainsL.Unlock()
	delete(s.domains, d)
}

// Wait waits for all of the Conns returned by s to end as well as s.Close()
// to be called.
func (s *Server) Wait() { s.wg.Wait() }

// Address returns the address of s's underlying transport.  It implements the
// Address method of the net.Listener interface.
func (s *Server) Address() net.Addr { return s.packetConn.LocalAddr() }

// Close prevents new connections from being accepted, but does not close the
// underlying transport.  Close must be called before Wait will return.
func (s *Server) Close() error {
	s.lock.Lock()
	defer s.lock.Unlock()
	/* Don't double-close */
	if true == s.closed {
		return nil
	}

	s.wg.Done()
	s.closed = true
	return nil
}

// AcceptConn waits for and returns the next new connection.
func (s *Server) AcceptConn() (*Conn, error) {
	c, ok := <-s.newConns
	if !ok {
		return nil, ErrListenerClosed
	}
	return c, nil
}

// Accept wraps s.AcceptConn to satisfy the net.Listener interface.
func (s *Server) Accept() (net.Conn, error) {
	return s.AcceptConn()
}

/* send sends b to a */
func (s *Server) send(a net.Addr, b []byte) {
	_, err := s.packetConn.WriteTo(b, a)
	if nil != err {
		/* TODO: Set error state in s */
	}
}

/* newConn handles the SYN and SYNACK equivalents of the handshake, and sets
q's answer to the new Conn ID. */
func (s *Server) NewConn(q *query) {
	/* TODO: Finish this */
}
