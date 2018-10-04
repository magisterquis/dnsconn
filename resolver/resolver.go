// Package resolver implements a lightweight DNS resolver
//
// It'd be really cool if this all worked.  It's a work in progress.
package resolver

/*
 * resolver.go
 * Lightweight DNS resolver
 * By J. Stuart McMurray
 * Created 20180925
 * Last Modified 20181003
 */

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
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
	// CNAME records, if returned, will be resolved into A records.
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
	//// name.  CNAME records, if returned, will be resolved into AAAA
	//// records.
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
	conn        net.Conn
	isPC        bool /* Is conn a net.PacketConn? */
	cech        chan error
	connL       sync.Mutex
	servers     []net.IP
	queryMethod QueryMethod
	bufpool     *sync.Pool
	upool       *sync.Pool

	/* Answers to queries are sent here */
	ansCh  map[uint16]chan<- *dnsmessage.Message
	ansChL sync.Mutex

	qto  time.Duration /* Query timeout */
	qtoL sync.RWMutex
}

// NewResolver returns a resolver which makes queries to the given servers.
// How the servers are queried is determined by method.
func NewResolver(servers []net.IP, method QueryMethod) (Resolver, error) {
	/* Make sure we actually have servers */
	if 0 == len(servers) {
		return nil, errors.New("no servers specified")
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
func NewResolverFromConn(c net.Conn) (Resolver, <-chan error) {
	res := newResolver()
	res.conn = c
	res.ech = make(chan error)
	if _, ok := c.(net.PacketConn); ok {
		res.isPC = true
	}

	/* Listen on Conn for answers */
	go res.listenforanswers()

	return res, res.ech

	/* TODO: Listen on conn for answers.  If an answer comes back for a DNS
	ID in ansCh, send it back and close the channel. */
}

/* newResolver makes and initializes as much of a resolver as can be
initialized without a conn or query method */
func newResolver() *resolver {
	return &resolver{
		bufpool: newBufPool(buflen),
		upool:   newBufPool(2),
		ansCh:   make(map[uint16]chan<- *dnsmessage.Message),
		qto:     QUERYTIMEOUT,
	}
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

/* listenForAnswers listens on r.conn for DNS answers and sends them to the
appropriate channel in r.ansCh. */
func (r *resolver) listenForAnswers() {
	var (
		/* Read buffers */
		sbuf = r.upool.Get().([]byte)
		pbuf = r.bufpool.Get().([]byte)
		n    int
		size uint16
		err  error
	)

	for {
		/* Reset the size */
		size = uint16(len(pbuf))

		/* Grab a query */
		if !r.isPC {
			/* Grab the size */
			_, err = io.ReadFull(r.conn, sbuf)
			if nil != err {
				go r.sendErr(err, true)
				return
			}
			size = binary.Uint16(sbuf)
			/* Grab the query */
			_, err = io.ReadFull(r.conn, pbuf[:size])
			if nil != err {
				go r.sendErr(err, true)
				return
			}
		} else {
			n, err = r.conn.Read(pbuf)
			if nil != err {
				go r.sendErr(err, true)
				return
			}
			size = uint16(n)
		}

		/* Unmarshal it */
		msg := new(dnsmessage.Message)
		if err := msg.Unpack(pbuf[:size]); nil != err {
			go r.sendErr(err, false)
			continue
		}

		/* Work out where to send it */
		ch, ok := msg.Header.ID
	}
}

/* sendErr sends an error to r.cech if it is not already closed.  If close is
true, the channel will be closed.  sendErr should probably always be called
in a goroutine. */
func (r *resolver) sendErr(err error, close bool) {
	r.connL.Lock()
	defer r.connL.Unlock()
	/* If the channel has been closed, don't bother */
	if nil == r.cech {
		return
	}
	/* Send the error on the channel */
	r.cech <- err
	/* Close the channel if we're meant to */
	close(r.cech)
	r.cech = nil
}

/* newAnsChannel registers a channel in r on which will be sent a reply to a
query with the returned ID.  The channel will be closed after the timeout. */
func (r *resolver) newAnsChannel() (
	id uint16,
	ch <-chan *dnsmessage.Message,
	err error,
) {
	r.ansChL.Lock()
	r.ansChL.Unlock()

	/* If there's already uint16Max outstanding queries, give up */
	if 0xFFFF <= len(r.ansCh) {
		return ErrTooManyQueries
	}

	/* Find a unique ID */
	id, err = r.randUint16()
	if nil != err {
		return 0, nil, err
	}
	for {
		if _, inUse := r.ansCh[id]; !inUse {
			break
		}
		id++
	}

	/* Register the channel */
	ch = make(chan *dnsmessage.Message)
	r.ansCh[id] = ch

	/* Close the channel if the message takes too long to come back */
	go func() {
		/* Work out how long to sleep before killing the channel */
		r.qtoL.RLock()
		to := r.qto
		r.qtoL.RUnlock()
		/* Wait until the timeout */
		time.Sleep(to)
		/* Grab hold of the channel if we have one */
		r.ansChL.Lock()
		defer r.ansChL.Unlock()
		ach, ok := r.ansCh[id]
		/* If we don't actually have a channel or if this isn't the
		right channel for this ID (because of ID reuse), we're done */
		if !ok || ach != ch {
			return
		}
		/* Close the channel and remove it from the map */
		delete(r.ansCh, id)
		close(ch)
		/* Drain the channel after we closed it to avoid
		channel leakage.  There's a small race here where the answer
		could come in right before the close and the drain loop gets it
		before the real reader which is more or less equivalent to the
		answer coming past the timeout. */
		for _ = range ach {
			/* Drain */
		}
	}()
}

/* sendAnsChannel sends a to the appropriate answer channel (if it exists),
closes it and removes the channel from r. */
func (r *resolver) sendAnsChannel(a *dnsmessage.Message) {
	/* TODO: Finish this */
}
