package dnsconnserver

/*
 * handle_query.go
 * Handle received queries
 * By J. Stuart McMurray
 * Created 20181202
 * Last Modified 20181208
 */

import (
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// TTL is the TTL to send on responses.
	TTL = 1800 /* TODO: un-hardcode */

	// FIRSTABYTE is the first byte of returned A records
	FIRSTABYTE = 17
)

/* cachedAnswer is used to hold a cached answer.  It allows for multiple
goroutines to wait for an answer for the same query. */
type cachedAnswer struct {
	answer [4]byte
	valid  bool /* True when the answer is valid */
	cond   *sync.Cond
}

/* newCachedAnswer returns an initialized cachedAnswer. */
func newCachedAnswer() *cachedAnswer {
	return &cachedAnswer{cond: sync.NewCond(new(sync.Mutex))}
}

/* handle pops queries off the wire and processes them */
func (l *Listener) handle() {
	var (
		n   int
		err error
	)
	for {
		/* Packet buffer */
		buf := l.pool.Get().([]byte)

		/* Pop a packet */
		var addr net.Addr
		n, addr, err = l.pc.ReadFrom(buf)
		if nil != err {
			l.CloseWithError(err)
			return
		}

		/* Handle it */
		go func() {
			l.handlePacket(addr, buf[:n])
			l.pool.Put(buf)
		}()
	}
}

/* handlePacket unmarshals and handles individual DNS packets.  Addr is used to
send back the response. */
func (l *Listener) handlePacket(addr net.Addr, buf []byte) {
	/* Try to unroll packet */
	var m dnsmessage.Message
	if err := m.Unpack(buf); nil != err {
		l.debug("Unable to unpack %02x: %v", buf, err)
		return
	}

	/* Make sure an answer is sent back */
	var res *dnsmessage.Resource
	defer func() {
		/* Append the answer */
		if nil != res {
			m.Answers = append(m.Answers, *res)
		}
		/* Set the response bit */
		m.Header.Response = true
		/* Roll it into a packet */
		buf := l.pool.Get().([]byte)
		defer l.pool.Put(buf)
		mb, err := m.AppendPack(buf[:0])
		if nil != err {
			l.debug("Unable to pack message %v: %v", m, err)
			return
		}
		/* Send it off */
		if _, err := l.pc.WriteTo(mb, addr); nil != err {
			l.debug("Unable to send response to %v: %v", addr, err)
			return
		}
	}()

	/* Make sure packet is a single A request */
	/* TODO: Handle non-A */
	if 1 != len(m.Questions) {
		l.debug("Too many questions (%v) in %v", len(m.Questions), m)
		return
	}
	q := m.Questions[0]
	if dnsmessage.TypeA != q.Type {
		l.debug("Non-A %v request for %v", q.Type, q.Name)
		return
	}

	/* Parse query and get an answer */
	ans, err := l.handleQuery(q.Name.String())
	if nil != err {
		l.debug("Error processing %v: %v", q.Name, err)
	}

	/* Roll resource to send back */
	res = &dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  q.Name,
			Type:  q.Type,
			Class: q.Class,
			TTL:   TTL, /* TODO: Something better */
		},
		Body: &dnsmessage.AResource{A: ans},
	}
}

/* handleQuery is where the magic starts.  The query is interpreted as either
a handshake, a payload, or a teardown and used to create, update, or destroy
a client.  An A record in the form of four bytes is returned. */
func (l *Listener) handleQuery(q string) ([4]byte, error) {
	var ok bool /* Do we serve this domain? */

	/* Only deal in Upper-case queries, to help with b32ing. */
	q = strings.ToUpper(q)

	/* Strip off the domain */
	q, ok = l.removeDomain(q)
	if !ok {
		return randARec(), fmt.Errorf("unserved domain")
	}

	/* Dots and hyphens are arbitrarily placed */
	q = removeDotsAndHyphens(q)

	/* Handle caching */
	nca := newCachedAnswer()
	ca := l.cache.GetOrPut(q, nca).(*cachedAnswer)

	/* If we're not responsible for working this one out, wait for an
	answer and send it back */
	if ca != nca {
		ca.cond.L.Lock()
		defer ca.cond.L.Unlock()
		for !ca.valid {
			ca.cond.Wait()
		}
		return ca.answer, nil
	}

	/* Get the answer, and make sure any goroutine waiting on it will be
	woken up. */
	ca.cond.L.Lock()
	defer ca.cond.Broadcast()
	defer ca.cond.L.Unlock()

	/* Get the answer for the question */
	var err error
	ca.answer, err = l.handleQuestion(q)
	ca.valid = true

	return ca.answer, err
}

/* removeDomain returns q with the domain removed, if the domain is a suffix of
q.  If not, the returned bool is false. */
func (l *Listener) removeDomain(q string) (string, bool) {
	/* TODO: Adapt for DGA */
	return strings.TrimSuffix(q, l.domain), strings.HasSuffix(q, l.domain)
}

/* dhremover removes dots andhyphens */
var dhremover = strings.NewReplacer(".", "", "-", "")

/* removeDotsAndHyphens returns s with all of the dots and hyphens removed */
func removeDotsAndHyphens(s string) string { return dhremover.Replace(s) }

/* randARec returns a random a record starting with FIRSTABYTE */
func randARec() [4]byte {
	var b [4]byte
	b[0] = FIRSTABYTE
	rand.Read(b[1:]) /* Best effort */
	return b
}
