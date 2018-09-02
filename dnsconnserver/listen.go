// Package dnsconnserver is the server side of dnsconn.
//
// TODO: Actual documentation
//  With an example or two, of course
package dnsconnserver

/*
 * listen.go
 * Listen/Accept side of dnscon
 * By J. Stuart McMurray
 * Created 20180822
 * Last Modified 20180901
 */

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	// ErrListenerClosed is returned from Accept and AcceptServerConn when
	// they have been called on a listener closed with Close after there
	// are no more new queued connections.
	ErrListenerClosed = errors.New("listener closed")

	// ErrIncorrectDomain indicates that a query was received for a domain
	// not served by the Listener.
	ErrIncorrectDomain = errors.New("domain not served")

	// ErrNXConnFin indicates a FIN message was received for a nonexistent
	// Conn ID.
	ErrNXConnFin = errors.New("fin message for nonexistent conn ID")
)

// ResponseError is returned in a QueryHandleError's Err field when an error
// occurrs responding to a query.
type ResponseError struct {
	Payload []byte   /* Raw payload */
	Addr    net.Addr /* Client's address */
	Err     error    /* Underlying error */
}

// Error satisfies the error interface.  It is a wrapper for r.Err.Error().
func (r ResponseError) Error() string { return r.Err.Error() }

// Config is used configure a listener.
type Config struct {
	// Domains is the initial set of domains to serve.  The set may be
	// modified later with Listener's AddDomain and RemoveDomain methods.
	Domains []string

	// Parser is used to parse incoming DNS queries.  DefaultParser will
	// be used if Parser is nil.  Please see the the documentation for
	// Parser for more details.
	Parser MessageParser

	// AcceptBacklog controls how many pending new connections are kept
	// available before further new connections are rejected.
	AcceptBacklog uint

	// ReceiveBufferSize set the initial size of the receive buffer, which
	// should be large enough to hold an entire DNS packet, as returned
	// from the Listener's underlying net.PacketConn.}
	ReceiveBufferSize uint

	// QueryHandleErrors, if not nil, will receive errors of type
	// ParseError.  If QueryHandleErrors is non-nil, it must be serviced
	// or the listener and all clients will hang.
	QueryHandleErrors chan<- QueryHandleError

	// TTL is the Time-To-Live value, in seconds, sent in DNS replies
	// for new Conns as well as for DNS queries used by Conns returned
	// from Accept or AcceptConn.  If 0, or if a nil *Config is passed to
	// NewListener, the value from DefaultConfig will be used.
	TTL uint32

	/* TODO: Work out when to close QueryHandleErrors */
}

// DefaultConfig is the Config used when nil is passed as the
// config to Listen.
var DefaultConfig = Config{
	Domains:           []string{},
	Parser:            DefaultParser,
	AcceptBacklog:     16,
	ReceiveBufferSize: 2048,
	TTL:               7200,
}

// Listener listens for new DNS stream connections.  It implements
// net.Listener.
type Listener struct {
	pc    net.PacketConn /* Underlying PacketConn */
	parse MessageParser  /* Custom unmarshal function */

	ds map[string]struct{} /* Domains to serve */
	dl *sync.Mutex

	accept bool             /* True to accept new conns */
	ncs    chan *Conn       /* Connections ready to be accepted */
	conns  map[string]*Conn /* Conns returned by Accept */
	cl     *sync.Mutex      /* Conn lock */

	ttl uint32 /* Reply TTL */

	err error
	wg  *sync.WaitGroup /* Wait for the underlying connection to be done */
}

// Listen listens for new connection requests on pc.  It is configured by
// passing in a Config, or nil to use DefaultConfig.  New connections (as
// returned from Accept or AcceptServerConn) will use pc as their underlying
///net.PacketConn.
func Listen(pc net.PacketConn, config *Config) (*Listener, error) {
	/* Work out the config to use */
	if nil == config {
		config = &DefaultConfig
	}

	/* Listener to return */
	l := &Listener{
		pc:     pc,
		parse:  config.Parser,
		ds:     make(map[string]struct{}),
		dl:     new(sync.Mutex),
		accept: true,
		ncs:    make(chan *Conn, config.AcceptBacklog),
		conns:  make(map[string]*Conn),
		ttl:    config.TTL,
		cl:     new(sync.Mutex),
		wg:     new(sync.WaitGroup),
	}
	if nil == l.parse {
		l.parse = DefaultConfig.Parser
	}
	if 0 == l.ttl {
		l.ttl = DefaultConfig.TTL
	}

	/* Add the served domains */
	for _, d := range config.Domains {
		l.AddDomain(d)
	}

	/* Start processing received packets and outgoing messages */
	if 0 == config.ReceiveBufferSize {
		config.ReceiveBufferSize = DefaultConfig.ReceiveBufferSize
	}
	go l.process(
		make([]byte, config.ReceiveBufferSize),
		config.QueryHandleErrors,
	)

	/* Note that we're listening */
	l.wg.Add(1)

	return l, nil
}

// Accept implements the Accept method in the net.Listener interface.  Returned
// connections will be of type ServerConn.
func (l *Listener) Accept() (net.Conn, error) {
	return l.AcceptConn()
}

// AcceptConn returns the next new connection.
func (l *Listener) AcceptConn() (*Conn, error) {
	/* If we've already got an error, return that */
	l.cl.Lock()
	if nil != l.err {
		l.cl.Unlock()
		return nil, l.err
	}
	l.cl.Unlock()

	/* Return the next connection */
	c, ok := <-l.ncs
	if !ok {
		/* If we've no connection, return either the error set or just
		that the listener's closed */
		l.cl.Lock()
		defer l.cl.Unlock()
		err := l.err
		if nil == err {
			err = ErrListenerClosed
		}
		return nil, ErrListenerClosed
	}
	return c, nil
}

// Close prevents the listener from accepting new connections.  Any blocked
// Accept or AccceptServerConn calls will return ErrListenerClosed.  It is safe
// to call Close more than once or from more than one goroutine.
func (l *Listener) Close() error {
	l.cl.Lock()
	defer l.cl.Unlock()
	/* Don't double-close */
	if false == l.accept {
		return nil
	}
	/* Note that we're no longer listening */
	l.wg.Done()
	if nil != l.err {
		l.err = ErrListenerClosed
	}
	l.accept = false
	close(l.ncs)

	return nil
}

// Addr returns l's underlying net.PacketConn's address.
func (l *Listener) Addr() net.Addr {
	return l.pc.LocalAddr()
}

// AddDomain adds a domain to l's set of domains to serve.  It is safe to add
// a domain more than once.
func (l *Listener) AddDomain(d string) {
	l.dl.Lock()
	defer l.dl.Unlock()

	/* Get rid of extra dots */
	d = strings.Trim(d, ".")

	/* If we're left with the root, add that */
	if "" == d {
		d = "."
	}

	l.ds[d] = struct{}{}
}

// RemoveDomain removes a domain from l's set of domains to serve.  It returns
// true if d was actually in the set.  Calling RemoveDomain with a domain not
// in the set is not an error.  RemoveDomain will simply return false.
func (l *Listener) RemoveDomain(d string) bool {
	l.dl.Lock()
	defer l.dl.Unlock()

	/* Check if the domain's actually there */
	_, ok := l.ds[d]
	if !ok {
		return false
	}

	delete(l.ds, d)
	return true
}

// Domains returns a copy of the set of domains served by l.  It is safe to
// modify the returned slice.
func (l *Listener) Domains() []string {
	l.dl.Lock()
	defer l.dl.Unlock()
	ds := make([]string, 0, len(l.ds))
	for d := range l.ds {
		ds = append(ds, d)
	}
	return ds
}

// ServesDomain returns true if l serves the domain d.
func (l *Listener) ServesDomain(d string) bool {
	l.dl.Lock()
	defer l.dl.Unlock()
	_, ok := l.ds[d]
	return ok
}

// ServedName first checks whether d is served by l, and if it is, the longest
// matching domain served by l is returned as parent, as well as the rest of
// the domain as child.  If d is not served, ok will be false.
func (l *Listener) ServedName(d string) (child, parent string, ok bool) {
	l.dl.Lock()
	defer l.dl.Unlock()

	/* Split domain into parts */
	d = strings.Trim(d, ".")
	parts := strings.Split(d, ".")

	/* Find the longest match */
	for i := 0; i < len(parts); i++ {
		s := strings.Join(parts[i:], ".")
		if _, ok := l.ds[s]; ok {
			return strings.Join(parts[:i], "."), s, ok
		}
	}

	/* Maybe it serves the root? */
	if _, ok := l.ds["."]; ok {
		return d, ".", true
	}

	return "", "", false
}

/* process pops packets from l.pc and handles them.  If it's for a new
connection, it'll wrap it in a Conn, otherwise, it'll send it to the
appropriate conn. If the exact request has been seen, the previously-returned
answer will be sent back. */
func (l *Listener) process(buf []byte, ech chan<- QueryHandleError) {
	var (
		n    int
		addr net.Addr
		err  error
		p    dnsmessage.Parser
	)
	for {
		/* Pop a packet */
		n, addr, err = l.pc.ReadFrom(buf)

		/* Process the data we have */
		if 0 < n { /* TODO: Put all of this in a function */
			/* Parse the query */
			q, err := l.parseQuery(&p, buf[:n], addr)
			if nil != err {
				handleQHE(ech, buf[:n], addr, err)
				/* TODO: Have something return if the packet was too short so we can double the buffer for next time. */
				/* TODO: Figure out how to tell if packet's too short */
				/* Send an error back if we have a channel */
			} else {
				/* Got a good query, take action */
				err := l.handleQuery(buf[:n], q, addr, ech)
				handleQHE(ech, buf[:n], addr, err)
			}
		}

		/* Retry after a temporary error */
		if e, ok := err.(*net.OpError); ok &&
			nil != e &&
			e.Temporary() {
			continue
		}

		/* If we have an error, tell all the Conns */
		if nil != err {
			l.cl.Lock()
			defer l.cl.Unlock()
			l.err = err
			/* Close the listener in a goroutine, so we don't have
			to worry about a double-lock of l.cl */
			go l.Close()
			/* TODO: Propagate error to children */
			return
		}
	}
}

// Wait returns after l has been closed and all of the clients returned by
// Accept or AcceptServerConn have been closed.
func (l *Listener) Wait() {
	l.wg.Wait()
}

/* processQuery extracts the QName from the packet in buf */
func (l *Listener) parseQuery(p *dnsmessage.Parser, buf []byte, a net.Addr) (*query, error) {
	var (
		q   query
		err error
	)

	/* Start parsing, get the header */
	q.hdr, err = p.Start(buf)
	if nil != err {
		return nil, err
	}

	/* Extract the questions */
	qns, err := p.AllQuestions()
	if nil != err {
		return nil, err
	}

	/* Parse each question, save */
	for _, qn := range qns {
		/* See if wq care about the qname */
		c, _, ok := l.ServedName(qn.Name.String())
		/* If we don't, add it as a "don't care" */
		if !ok {
			q.qs = append(q.qs, &question{q: qn, unserved: true})
			continue
		}
		/* Parse the payload bit of the query */
		msg, err := l.parse(c)
		if nil != err {
			return nil, MessageParseError{c, err}
		}
		if messageTypeNames[MTUnknown] == msg.Type.String() {
			return nil, MessageParseError{c, ErrUnknownMessageType}
		}
		q.qs = append(q.qs, &question{
			msg:      msg,
			q:        qn,
			unserved: !handledType(qn.Type),
		})
	}

	/* Add the return address */
	q.a = a

	/* Sort the questions */
	q.SortQuestions()

	return &q, nil
}

// Err returns the first error encountered by l.
func (l *Listener) Err() error {
	l.cl.Lock()
	defer l.cl.Unlock()
	return l.err
}

/* handleQuery takes a query and takes action based on all of the questions.
The answer will be sent back to addr. */
func (l *Listener) handleQuery(
	raw []byte,
	q *query,
	addr net.Addr,
	ech chan<- QueryHandleError,
) error {

	/* Get answers for each question */
	for _, qn := range q.qs {
		/* Ignore unserved questions */
		if qn.unserved {
			continue
		}

		/* Set some fields in the answer */
		qn.ans.Header.Name = qn.q.Name
		qn.ans.Header.Class = qn.q.Class
		qn.ans.Header.TTL = l.ttl
		/* qn.ans.Body will be set below */

		/* MTNew (make a new Conn) doesn't require an existing conn */
		if MTNew == qn.msg.Type {
			handleQHE(ech, raw, addr, l.newConn(qn))
			continue
		}

		/* Get the conn for this ID */
		c, ok := l.getConn(qn.msg.ID)
		if !ok { /* Unknown client */
			/* Tell someone we've an unknown client */
			handleQHE(
				ech,
				raw,
				addr,
				fmt.Errorf(
					"unknown connection: %v",
					qn.msg.ID,
				),
			)
			/* Send a FIN back if we haven't a client */
			handleQHE(ech, raw, addr, qn.Fin())
			continue
		}

		/* Let the relevant conn handle the message */
		var err error
		switch qn.msg.Type {
		case MTData:
			err = c.psh(qn)
		case MTDReq:
			err = c.req(qn)
		case MTRIndex:
			c.rindex(qn)
		case MTEnd:
			if !l.deleteConn(qn.msg.ID) {
				/* Conn doesn't exist */
				err = ErrNXConnFin
				break
			}
			err = c.fin(qn)
		default:
			/* This should have been caught already */
			log.Panic("unknown message type", qn.msg.Type)
		}
		handleQHE(ech, raw, addr, err)
	}

	/* Make sure all of the answers have Bodies */
	for _, qn := range q.qs {
		if nil == qn.ans.Body {
			log.Panic("Unfilled body in ", qn.ans)
		}
	}

	/* Change header to be a response */
	q.hdr.Response = true
	q.hdr.Authoritative = true
	q.hdr.RCode = dnsmessage.RCodeSuccess

	/* Make a response */
	var res dnsmessage.Message
	res.Header = q.hdr
	/* Add the original questions */
	for _, qn := range q.qs {
		res.Questions = append(res.Questions, qn.q)
	}
	/* Add the answers which actually have answers.  They all should. */
	for _, qn := range q.qs {
		res.Answers = append(res.Answers, qn.ans)
	}
	buf, err := res.Pack()
	if nil != err {
		return err
	}

	/* Send it back */
	if _, err := l.pc.WriteTo(buf, addr); nil != err {
		return ResponseError{
			Payload: buf,
			Addr:    addr,
			Err:     err,
		}
	}

	return nil
}

/* TODO: Warn that the conns must be closed or there'll be data leakage */

/* getConn gets the conn with ID id.  It also returns whether the conn was
known. */
func (l *Listener) getConn(id string) (*Conn, bool) {
	l.cl.Lock()
	defer l.cl.Unlock()

	c, ok := l.conns[id]
	return c, ok
}

/* putConn adds the conn to l.conns.  It returns true if the conn was added
successfully and false if a conn with that ID already exists. */
func (l *Listener) putConn(id string, c *Conn) bool {
	l.cl.Lock()
	defer l.cl.Unlock()

	_, ok := l.conns[id]
	if ok {
		return false
	}
	l.conns[id] = c
	return true
}

/* deleteConn removes the conn with the given ID from l.conns.  It returns
true if the conn was in l.conns. */
func (l *Listener) deleteConn(id string) bool {
	l.cl.Lock()
	defer l.cl.Unlock()

	_, ok := l.conns[id]
	if !ok {
		return false
	}
	delete(l.conns, id)
	return true
}

/* newConn makes a new conn available to AcceptConn, and updates the answer
with the Conn's ID, the length of which will be determined by the type of the
query. */
func (l *Listener) newConn(qn *question) (err error) {
	/* TODO: Finish this */
	return nil
}

/* handleQHE sends a QueryHandleError to ech if ech and err are not nil.  The
Raw field of the QueryHandleError will be a copy of raw. */
func handleQHE(
	ech chan<- QueryHandleError,
	raw []byte,
	addr net.Addr,
	err error,
) {
	if nil == ech || nil == err {
		return
	}
	e := make([]byte, len(raw))
	copy(e, raw)
	ech <- QueryHandleError{e, addr, err}
}

/* TODO: make a cache for replies */
