// Package resolver implements a lightweight DNS resolver
//
// It'd be really cool if this all worked.  It's a work in progress.
package resolver

/*
 * resolver.go
 * Lightweight DNS resolver
 * By J. Stuart McMurray
 * Created 20180925
 * Last Modified 20181011
 */

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

// QueryMethod is used to configure which server(s) are queried by resolver
// returned by NewResolver.
type QueryMethod int

const (
	// RoundRobin causes a different server to be used for every query.
	RoundRobin QueryMethod = iota

	// NextOnFail causes the servers to be tried in order until one
	// returns an answer or the list of servers is exhausted.
	NextOnFail

	// QueryAll causes all servers to be tried for every query.
	QueryAll
)

// QUERYTIMEOUT is the default query timeout
const QUERYTIMEOUT = 10 * time.Second

// StdlibResolver is a Resolver which wraps the net.Lookup* functions.  The
// Resolver's LookupAC and LookupAAAAC methods will always return errors and
// its LookupA and LookupAAAA methods will both make queries for both A and
// AAAA records.  StblibResolver.QueryTimeout is a no-op.  The default
// net.Lookup* timeouts are used instead.
var StdlibResolver Resolver = stdlibResolver()

// ErrTooManyQueries is returned when there are too many outstanding queries.
// Approximate 65k queries can be in flight at once.
var ErrTooManyQueries = errors.New("too many outstanding queries")

// MX represents an MX record.
type MX struct {
	Preference uint16
	Name       string
}

// SRV represents a SRV record.
type SRV struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

// Resolver implements a lightweight DNS resolver.
type Resolver interface {
	// LookupA returns the A records (IPv4 addresses) for the given name.
	LookupA(name string) ([][4]byte, error)

	//// LookupAC performs a query for A records for the given name, but
	//// expects and returns only CNAME records sent in the reply.
	//LookupAC(name string) ([]string, error)

	//// LookupNS returns the NS records for the given name.
	//LookupNS(name string) ([]string, error)

	//// LookupCNAME returns the CNAME records for the given name.
	//LookupCNAME(name string) ([]string, error)

	//// LookupPTR looks up the PTR records for the given IP address.
	//LookupPTR(addr net.IP) ([]string, error)

	//// LookupMX looks up the MX records for the given name.
	//LookupMX(name string) ([]MX, error)

	//// LookupTXT looks up the TXT records for the given name.
	//LookupTXT(name string) ([]string, error)

	//// LookupAAAA looks up the AAAA records (IPv6 addresses) for the given
	//// name.
	//LookupAAAA(name string) ([][16]byte, error)

	//// LookupAAAAC performs a query for AAAA records for the given name,
	//// but expects and returns only CNAME records sent in the reply.
	//LookupAAAAC(name string) ([]string, error)

	//// LookupSRV looks up the SRV records for the given name.
	//LookupSRV(name string) ([]SRV, error)

	// QueryTimeout sets the timeout for receiving responses to queries.
	QueryTimeout(to time.Duration)
}

/* buflen is the size of the buffers kept in the resolver's pool */
const buflen = 65536

/* resolver is the built-in implementation of Resolver */
type resolver struct {
	/* Connections to use */
	servers []net.Addr
	conns   []conn
	connsN  int
	connsL  *sync.Mutex

	/* Used if we have multiple servers to query */
	nextServer  int
	queryMethod QueryMethod

	/* Buffer pools */
	bufpool *sync.Pool
	upool   *sync.Pool

	/* Query timeout */
	qto  time.Duration
	qtoL sync.RWMutex
}

// NewResolver returns a resolver which makes queries to the given servers.
// How the servers are queried is determined by method.
func NewResolver(servers []net.Addr, method QueryMethod) (Resolver, error) {
	/* Make sure we actually have servers */
	if 0 == len(servers) {
		return nil, errors.New("no servers specified")
	}

	/* Make sure the method is ok */
	if method != RoundRobin && method != NextOnFail && method != QueryAll {
		return nil, errors.New("unknown query method")
	}

	/* Return an initialized resolver */
	res := newResolver()
	res.servers = servers
	res.queryMethod = method
	return res, nil
}

// NewResolverFromConn returns a Resolver which sends its queries on the
// provided net.Conn.  If the net.Conn implements the net.PacketConn interface,
// it will be treated as a UDPish connection (though it need not be), otherwise
// it will be treated as TCPish.  Errors encountered during reading and parsing
// responses will be sent to the returned channel which will be closed when
// no more responses are able to be read (usually due to c being closed).  The
// channel must be serviced or resolution will hang.
func NewResolverFromConn(c net.Conn) Resolver {
	res := newResolver()
	res.conns = append(res.conns, res.newConn(c))
	res.queryMethod = RoundRobin

	return res
}

/* newResolver makes and initializes as much of a resolver as can be
initialized without a conn or query method */
func newResolver() *resolver {
	return &resolver{
		connsL:  new(sync.Mutex),
		bufpool: newBufPool(buflen),
		upool:   newBufPool(2),
		qto:     QUERYTIMEOUT,
	}
}

/* newConn makes a new conn for the resolver */
func (r *resolver) newConn(c net.Conn) conn {
	ret := conn{
		r:      r,
		c:      c,
		txL:    new(sync.Mutex),
		ansCh:  make(map[uint16]chan<- ansOrErr),
		ansChL: new(sync.Mutex),
		errL:   new(sync.Mutex),
	}
	_, ok := c.(net.PacketConn)
	ret.isPC = ok
	go ret.listenForAnswers()
	return ret
}

// QueryTimeout sets the timeout for responses to queries.
func (r *resolver) QueryTimeout(to time.Duration) {
	r.qtoL.Lock()
	defer r.qtoL.Unlock()
	r.qto = to
}

/* newBufPool returns a new sync.Pool which holds buffers of the given size. */
func newBufPool(size uint) *sync.Pool {
	return &sync.Pool{New: func() interface{} {
		return make([]byte, int(size))
	}}
}

/* randUint16 returns a random uint16 */
func (r *resolver) randUint16() (uint16, error) {
	b := r.upool.Get().([]byte)
	defer r.upool.Put(b)
	if _, err := rand.Read(b); nil != err {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}
