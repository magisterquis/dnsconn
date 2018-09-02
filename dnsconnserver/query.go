package dnsconnserver

/*
 * query.go
 * Represents a received query
 * By J. Stuart McMurray
 * Created 20180826
 * Last Modified 20180830
 */

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// AOk is the first byte of a normal A record.  It corresponds to
	// Apple Inc.'s IPv4 range.
	AOk = 17
	// ABad is the first byte of an A record indicating something's wrong.
	// It corresponds to HP's range.
	ABad = 16
	// AUintMax is the maximum uint value which can be stored in an A
	// record
	AUintMax = 0xFFFFFF

	// AAAAOk is the first 8 bytes of a normal AAAA record in big-endian
	// byte order.  It corresponds to Google's IPv6 ranges.
	AAAAOk = "2607:f8b0:4004:0800"
	// AAAABad is the first 8 bytes of an AAAA record indicating
	// something's wrong.  It corresponds to AT&T's range.
	AAAABad = "2001:1890:1c00:3113"
	// AAAAUintMax is the maximum uint value which can be stored in an AAAA
	// record.
	AAAAUintMax = 0xFFFFFFFFFFFFFFFF
)

/* Constants for SOA records.  These are RIPE-recommended values */
const (
	soaRefresh = 86400
	soaRetry   = 7200
	soaExpire  = 3600000
	soaMinTTL  = 172800
)

/* AAAA ok/bad flags, in slices */
var (
	aaaabadbuf = makeAAAA(AAAABad)
	aaaaokbuf  = makeAAAA(AAAAOk)
)

// QueryHandleError contains information about a received DNS query which was
// unable to be parsed or handled correctly.
type QueryHandleError struct {
	Raw  []byte   /* Raw query which caused the error */
	Addr net.Addr /* Source address of the query */
	Err  error    /* Underlying error */
}

// Error satisfies the error interface.  It is a wrapper for q.Err.Error().
func (q QueryHandleError) Error() string {
	return q.Err.Error()
}

// Question represents a decoded question */
type question struct {
	msg Message             /* Decoded client message */
	q   dnsmessage.Question /* Question from DNS query */
	ans dnsmessage.Resource /* Answer */

	/* unserved lets us know to ignore this Question because it's not for
	a domain we serve for comms. */
	unserved bool
}

// PutUint sets the answer to q to n.  If n is larger than the maximum value
// able to be sent by the type requested by q, the answer will be set to the
// maximum settable value.  ok controls whether the first byte is set to the
// appropriate OK value (e.g. AOK) or the
func (q *question) PutUint(n uint, ok bool) {
	/* The value to use for the OK flag, if we need a byte */
	var okv byte
	if ok {
		okv = AOk
	} else {
		okv = ABad
	}

	/* These don't take a domain name as the answer */
	switch q.q.Type {
	case dnsmessage.TypeA:
		/* Cap index if it's too big */
		if AUintMax < n {
			n = AUintMax
		}
		var ans [4]byte
		/* Put the answer in */
		binary.BigEndian.PutUint32(ans[:], uint32(n))
		/* First byte is status */
		ans[0] = okv
		q.ans.Body = &dnsmessage.AResource{A: ans}
		return
	case dnsmessage.TypeAAAA:
		/* Cap index if it's too big */
		if AAAAUintMax < n {
			n = AAAAUintMax
		}
		var ans [16]byte
		/* Put the answer in */
		binary.BigEndian.PutUint64(ans[8:], uint64(n))
		/* First half is status */
		if ok {
			copy(ans[:], aaaaokbuf)
		} else {
			copy(ans[:], aaaabadbuf)
		}
		q.ans.Body = &dnsmessage.AAAAResource{AAAA: ans}
		return
	case dnsmessage.TypeTXT:
		q.ans.Body = &dnsmessage.TXTResource{TXT: []string{
			fmt.Sprintf("%02x=%02x", okv, n),
		}}
		return
	}

	/* Name to put in replies */
	name, err := dnsmessage.NewName(fmt.Sprintf("%v.%02x.com", okv, n))
	if nil != err {
		panic(err)
	}
	/* TODO: Document formats for each record type */

	/* The following take a domain name as the answer */
	switch q.q.Type {
	case dnsmessage.TypeNS:
		q.ans.Body = &dnsmessage.NSResource{NS: name}
	case dnsmessage.TypeCNAME:
		q.ans.Body = &dnsmessage.CNAMEResource{CNAME: name}
	case dnsmessage.TypeSOA:
		q.ans.Body = &dnsmessage.SOAResource{
			NS:      name,
			MBox:    name,
			Serial:  uint32(n),
			Refresh: soaRefresh,
			Retry:   soaRetry,
			Expire:  soaExpire,
			MinTTL:  soaMinTTL,
		}
	case dnsmessage.TypePTR:
		q.ans.Body = &dnsmessage.PTRResource{PTR: name}
	case dnsmessage.TypeMX:
		q.ans.Body = &dnsmessage.MXResource{
			Pref: randUint16(),
			MX:   name,
		}
	case dnsmessage.TypeSRV:
		q.ans.Body = &dnsmessage.SRVResource{
			Priority: randUint16(),
			Weight:   randUint16(),
			Port:     randUint16(),
			Target:   name,
		}
	default:
		panic("unknown record type " + q.q.Type.String())
	}
}

// NewID sets the answer to indicate the ID the client is to use in response
// to a new connection.  The number of significant bits (starting at the right)
// in the id is given in n.
func (q *question) NewID(n uint, id string) error {
	/* TODO: Finish this */
	return nil
}

// DataLen returns the number of bytes of data which can fit in the question's
// response.
func (q *question) DataLen() uint {
	switch q.q.Type {
	case dnsmessage.TypeA: /* 4-byte IP address */
		return 3
	case /* Domain name */
		dnsmessage.TypeNS,
		dnsmessage.TypeCNAME,
		dnsmessage.TypeSOA,
		dnsmessage.TypePTR,
		dnsmessage.TypeMX,
		dnsmessage.TypeTXT,
		dnsmessage.TypeSRV:
		/* TODO: Work out if we can actually stick in more */
		/* TODO: Some of these require encoding */
		return 254
	case dnsmessage.TypeAAAA: /* 16-byte IP address */
		return 15
	default:
		/* We should be ignoring anything else */
		panic("unknown type " + q.q.Type.String())
	}
}

// Push sets the answer to send data back to the client.  This is used as
// the answer for a MTDReq query.  Index is the index of the highest-indexed
// byte in buf.
func (q *question) Push(buf []byte, index uint) error {
	/* TODO: Finish this */
	return nil
}

/* Fin sets the answer to indicate the stream is finished. */
func (q *question) Fin() error {
	/* TODO: Finish this */
	return nil
}

/* TODO: Have a way to acknowledge reset of index */

// Query represents a query received off the wire
type query struct {
	a   net.Addr          /* Return address */
	hdr dnsmessage.Header /* Query header */
	qs  []*question       /* Decoded questions */
}

// Reply returns a reply for q ready to be sent on the wire.
func (q query) Reply() ([]byte, error) { return nil, nil }

// SortQuestions sorts the questions (really, the ClientMessages) in q first by
// ID and then by Index.  The idea here is to prevent a situation in which
// multiple qnames come in one query, we get a later message first, and have to
// ask for a resend of an earlier message is actually there.
func (q *query) SortQuestions() {
	/* Don't bother if we've not enough to sort */
	if 2 > len(q.qs) {
		return
	}

	/* Sort first by ID and then by Index */
	sort.Slice(q.qs, func(i, j int) bool {
		/* Ignored questions go last */
		if q.qs[i].unserved {
			return false
		}

		/* Sort first by ID */
		if q.qs[i].msg.ID < q.qs[j].msg.ID {
			return true
		}

		/* Then by Index */
		if q.qs[i].msg.Index < q.qs[j].msg.Index {
			return true
		}
		return false
	})
}

/* handledType returns true if the type is handled by this library */
func handledType(t dnsmessage.Type) bool {
	switch t {
	case
		dnsmessage.TypeA,
		dnsmessage.TypeNS,
		dnsmessage.TypeCNAME,
		dnsmessage.TypeSOA,
		dnsmessage.TypePTR,
		dnsmessage.TypeMX,
		dnsmessage.TypeTXT,
		dnsmessage.TypeAAAA,
		dnsmessage.TypeSRV:
		return true
	default:
		return false
	}
}

/*
switch q.q.Type {
case
	dnsmessage.TypeA,
	dnsmessage.TypeNS,
	dnsmessage.TypeCNAME,
	dnsmessage.TypeSOA,
	dnsmessage.TypePTR,
	dnsmessage.TypeMX,
	dnsmessage.TypeTXT,
	dnsmessage.TypeAAAA,
	dnsmessage.TypeSRV:
default:
	panic("unknown type " + q.q.Type.String())
}
*/

/* makeAAAA turns a, which should be half of an IPv6 address, into a []byte.
it panics on error. */
func makeAAAA(a string) []byte {
	i := net.ParseIP(a + "::").To16()
	if 16 != len(i) {
		panic("incorrect slice length for " + a)
	}
	r := make([]byte, 8)
	copy(r, i)
	return r
}

/* TODO: Work out how to detect and handle the case where inbound IPs get discarded. */

/* randUint16 returns a random uint16. */
func randUint16() uint16 {
	b := make([]byte, 2)
	if _, err := io.ReadFull(rand.Reader, b); nil != err {
		panic(err)
	}
	return binary.BigEndian.Uint16(b)
}
