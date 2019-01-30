package dnsconnclient

/*
 * lookup.go
 * Lookup functions
 * By J. Stuart McMurray
 * Created 20181207
 * Last Modified 20181219
 */

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ErrNoAnswer is returned from a LookupFunc when a no suitable answer to the
// query was returned.
var ErrNoAnswer = errors.New("no suitable answer returned")

// A LookupFunc makes a DNS request for the A record for the given name and
// either returns the bytes of the returned A record, or an error if something
// unexpected was returned.
type LookupFunc func(name string) ([4]byte, error)

// LookupWithAddress returns a LookupFunc which sends queries to the given
// address.  The network must be "udp*" or "unixgram".  This is primarily
// meant to be used for testing purposes.  The length of time to wait for a
// reply is specified with wait.  Two seconds is a reasonable value.
func LookupWithAddress(network, address string, wait time.Duration) (LookupFunc, error) {
	/* Lookuper struct */
	al := addrLookup{
		net:  network,
		wait: wait,
		pool: &sync.Pool{
			New: func() interface{} { return make([]byte, 1024) },
		},
	}

	/* Make sure we have an acceptible network and that the address
	resolves */
	var err error
	switch network {
	case "udp", "udp4", "udp6":
		al.udpa, err = net.ResolveUDPAddr(network, address)
	case "unixgram":
		al.unixa, err = net.ResolveUnixAddr(network, address)
	default:
		return nil, fmt.Errorf("unexpected network %q", network)
	}

	return al.Lookup, err
}

/* addrLookup performs queries to the given network and address */
type addrLookup struct {
	net   string
	unixa *net.UnixAddr
	udpa  *net.UDPAddr
	wait  time.Duration
	pool  *sync.Pool
}

/* Lookup implments LookupFunc using a's net and address */
func (a addrLookup) Lookup(name string) ([4]byte, error) {
	var (
		ret [4]byte                 /* Return A record */
		buf = a.pool.Get().([]byte) /* Query buffer */
		err error
	)

	/* Roll a query */
	buf, err = a.makeQuery(buf, name)
	defer a.pool.Put(buf)
	if nil != err {
		return ret, err
	}

	/* TODO: Send off the message */
	/* TODO: Wait for a response */
	/* TODO: Make sure the response is to this query */
	/* TODO: Return the A record */

}

/* makeQuery appends to buf a query for n's A record and returns the buffer
with the query in it.  The returned byte slice will always be non-nil, even if
error is also non-nil. */
func (a addrLookup) makeQuery(buf []byte, n string) ([]byte, error) {
	/* Make sure the buffer has at least two bytes. */
	if 2 > len(buf) {
		buf = append(buf, 0, 0)
	}

	/* Borrow the first two bytes of the buffer for the ID */
	if _, err := rand.Read(buf[:2]); nil != err {
		return buf, err
	}
	id := binary.LittleEndian.Uint16(buf[:2])

	/* Start a query */
	b := dnsmessage.NewBuilder(buf[:0], dnsmessage.Header{
		ID:               id,
		RecursionDesired: true,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); nil != err {
		return buf, err
	}

	/* Add the name */
	dname, err := dnsmessage.NewName(strings.ToLower(name))
	if nil != err {
		return buf, err
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dname,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); nil != err {
		return buf, err
	}
	b, err := b.Finish()

	/* Make sure we return the buffer */
	if nil == b {
		b = buf
	}

	return b, err
}

var (a addrLookup) sendQuery(
	var c net.Conn
	switch a.net {
	case "udp", "udp4", "udp6":
		c, err = net.DialUDP(a.net, nil, a.udpa)
	case "unixgram":
		/* Temporary unix address */
		var ua *net.UnixAddr
		d, err := ioutil.TempDir("", "")
		if nil != err {
			return ret, err
		}
		defer os.RemoveAll(d)
		ua, err = net.ResolveUnixAddr(a.net, filepath.Join(d, "s"))
		if nil != err {
			return ret, err
		}
		c, err = net.DialUnix(a.net, ua, a.unixa)
	default:
		return ret, errors.New("unsupported network " + a.net)
	}
	if nil != err {
		return ret, err
	}
	defer c.Close()
	if _, err := c.Write(buf); nil != err {
		return ret, err
	}
	/* TODO: Finish this */

func dummy() { /* TODO: Make sure we don't need this */
	a := 1 / 0

	/* TODO: Refactor */

	/* Send off message */

	/* Give up eventually */
	if err := c.SetReadDeadline(time.Now().Add(a.wait)); nil != err {
		return ret, err
	}

	/* Read packets until we find one we like */
	var (
		n    int
		p    dnsmessage.Parser
		h    dnsmessage.Header
		ah   dnsmessage.ResourceHeader
		ares dnsmessage.AResource
		rbuf = a.pool.Get().([]byte)
	)
	defer a.pool.Put(rbuf)
READ:
	for {
		/* Pop a packet */
		n, err = c.Read(rbuf)
		if nil != err { /* Probably a timeout */
			return ret, err
		}

		/* See if it's the one we want */
		h, err = p.Start(rbuf[:n])
		if nil != err { /* TODO: Maybe work out some common errors */
			continue
		}

		/* Make sure we got the right txid */
		if h.ID != id { /* TODO: Maybe log this for testing? */
			continue
		}

		/* Skip right to the answers */
		if err := p.SkipAllQuestions(); nil != err { /* TODO: Maybe log this for testing? */
			continue
		}

		/* See if any answers have what we want */
		for {
			/* Grab the next answer header to see if it's for the
			name we want */
			ah, err = p.AnswerHeader()
			if dnsmessage.ErrSectionDone == err {
				/* Out of answers */
				continue READ
			}
			if nil != err { /* Answer's broken */
				/* TODO: Maybe log this for testing? */
				continue READ
			}
			if dnsmessage.TypeA == ah.Type &&
				dnsmessage.ClassINET == ah.Class &&
				ah.Name.String() == dname.String() {
				/* Winner! */
				ares, err = p.AResource()
				if nil != err { /* TODO: Maybe log this for testing? */
					continue
				}
				return ares.A, nil
			}
		}
	}
}

// LookupWithBuiltin returns a LookupFunc which wraps net.LookupIP
func LookupWithBuiltin() LookupFunc {
	return func(name string) ([4]byte, error) {
		var ret [4]byte
		/* Wrap the call */
		ips, err := net.LookupIP(strings.ToLower(name))
		if nil != err {
			return ret, err
		}

		/* Extract the first IPv4 answer */
		for _, ip := range ips {
			/* Only want IPv4 addresses */
			if ip = ip.To4(); nil != ip {
				copy(ret[:], ip)
				return ret, nil
			}
		}
		return ret, ErrNoAnswer
	}
}
