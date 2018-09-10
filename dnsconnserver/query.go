package dnsconnserver

/*
 * query.go
 * Represents a received query
 * By J. Stuart McMurray
 * Created 20180826
 * Last Modified 20180909
 */

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
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

/* AAAA ok/bad flags, in slices */
var (
	aaaabadbuf = makeAAAA(AAAABad)
	aaaaokbuf  = makeAAAA(AAAAOk)
)

/* Constants for SOA records.  These are RIPE-recommended values */
const (
	soaRefresh = 86400
	soaRetry   = 7200
	soaExpire  = 3600000
	soaMinTTL  = 172800
)

const (
	// TLD is the TLD to use for DNS names used for returning data.
	TLD = "com"
	// RNAME is the administrator email used in SOA records
	RNAME = "hostmaster.example.com"
)

/* rname is RNAME, able to be stuck into a SOA RR */
var rname = dnsmessage.MustNewName(RNAME)

/* b32 is a base32 encoder using Hex Encoding and no padding */
var b32 = base32.HexEncoding.WithPadding(base32.NoPadding)

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
// appropriate Ok value (e.g. AOk) or the appropriate not ok value (e.g. ABad).
func (q *question) PutUint(n uint, ok bool) {
	/* Work out how many bytes we can put in */
	m := q.DataLen()

	/* Make sure n isn't too big */
	if (1<<(m*8))-1 < n {
		n = (1 << (m * 8)) - 1
	}

	/* Stick n in a buffer */
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(n))

	/* Put the relevant bytes in q */
	start := 0
	if len(buf) > int(m) {
		start = len(buf) - int(m)
	}
	for ; 0 == buf[start]; start++ {
	}
	q.PutBytes(buf[start:len(buf)], ok)
}

// PutBytes sets the answer to q to b.  If b has more data than can fit into
// the answer to q, PutBytes panics.  ok controls the start of the message
// (e.g. AOk vs ABad).  If b holds more data than the response to q can handle,
// b panics.
func (q *question) PutBytes(b []byte, ok bool) {
	/* Make sure we don't have too much data */
	if uint(len(b)) > q.DataLen() {
		panic("too many bytes to put")
	}

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
		var ans dnsmessage.AResource
		/* First byte is the ok value */
		ans.A[0] = okv
		/* Last three bytes are the payload */
		copy(ans.A[4-len(b):], b)
		q.ans.Body = &ans
		return
	case dnsmessage.TypeAAAA:
		var ans dnsmessage.AAAAResource
		/* First half is status */
		if ok {
			copy(ans.AAAA[:], aaaaokbuf)
		} else {
			copy(ans.AAAA[:], aaaabadbuf)
		}
		/* Second half is the payload */
		copy(ans.AAAA[16-len(b):], b)
		q.ans.Body = &ans
		return
	case dnsmessage.TypeTXT:
		q.ans.Body = &dnsmessage.TXTResource{TXT: []string{
			fmt.Sprintf(
				"%02x=%s",
				okv,
				base64.RawStdEncoding.EncodeToString(b),
			),
		}}
		return
	}

	/* Base32'd input bytes */
	s := []byte(b32.EncodeToString(b))

	/* Buffer into which to stick name.  It's the length of the base32 data
	plus enoug space for the TLD, the OK value, and dots. */
	o := make([]byte, 0, (len(s)/63)+4+len(TLD))
	o = append(o, []byte(fmt.Sprintf("%v.", okv))...)

	/* Add the buffer as labels. */
	var end int
	for start := 0; start < len(s); start += 63 {
		/* DNS labels are at most 63 characters. */
		end = start + 63
		if len(s) < end {
			end = len(s)
		}
		/* Add label bit and dot. */
		o = append(o, s[start:end]...)
		o = append(o, '.')
	}

	/* Add final TLD. */
	o = append(o, []byte(TLD)...)

	/* Turn into a DNS name */
	name := dnsmessage.MustNewName(string(o))
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
			MBox:    rname,
			Serial:  uint32(randUint16()),
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

// DataLen returns the number of bytes of data which can fit in the question's
// response.
func (q *question) DataLen() uint {
	switch q.q.Type {
	case dnsmessage.TypeA: /* 4-byte IP address, 1 byte ok flag */
		return 3
	case dnsmessage.TypeAAAA: /* 16-byte IP address, 8 byte ok flag */
		return 8
	case dnsmessage.TypeTXT: /* 3 bytes key/delimeter, 189 base64 chars */
		return 189
	case /* Domain name */
		dnsmessage.TypeNS,
		dnsmessage.TypeCNAME,
		dnsmessage.TypeSOA,
		dnsmessage.TypePTR,
		dnsmessage.TypeMX,
		dnsmessage.TypeSRV:
		return 152
	default:
		/* We should be ignoring anything else */
		panic("unknown type " + q.q.Type.String())
	}
}

/* Fin sets the answer to indicate the stream is finished. */
func (q *question) Fin() error {
	/* TODO: Finish this */
	return nil
}

/* TODO: Have a way to acknowledge reset of index */
/* TODO: A way to query the index, to see if a reset is ok or if more
data needs to be transferred. */

// Query represents a query received off the wire
type query struct {
	a   net.Addr          /* Return address */
	hdr dnsmessage.Header /* Query header */
	qs  []*question       /* Decoded questions */
}

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
