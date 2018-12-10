/* TODO: Documentation */
package dnsconnclient

/*
 * client.go
 * Client side of dnsconn
 * By J. Stuart McMurray
 * Created 20181204
 * Last Modified 20181209
 */

import (
	"errors"
	"log"
	"strings"
	"sync"
	"unicode"

	"github.com/magisterquis/dnsconn/keys"
	"golang.org/x/crypto/nacl/box"
)

// Config is used to configure a Client.
type Config struct {
	// Lookup specifies a lookup function to use.  By default the internal
	// resolver will be used.
	Lookup LookupFunc

	// MaxPayloadLen is the maximum length of the base32 data which will
	// be prepended to the domain.  Setting this to >63 will cause the
	// data to be split into multiple labels.  The default length is quite
	// conservative; most applications should set this much higher.  The
	// practical upper limit on the payload length is 253 less space for
	// the domain.

	// MaxPayloadLen is the maximum number of bytes which will be encoded
	// and sent to the server.  The encoded length will be longer than the
	// payload length; how much so depends on the EncodingFunc.
	MaxPayloadLen uint

	// EncodingFunc is used to encode up to MaxPayloadLen bytes into a
	// string suitable for use as a DNS query.  See the documentation for
	// EncodingFunc for more details.
	Encoder EncodingFunc

	/* TODO: Write Base32Encode */
	/* TODO: Make EncodingFunc type, document what's expected of the
	function and that the cid might be multiple bytes, but no more than NN
	bytes. */
}

/* defaultConfig is the defaults to use for Dial if config is nil. */
var defaultConfig = &Config{
	Lookup:        LookupWithBuiltin(),
	MaxPayloadLen: 12,
	Encoder:       Base32Encode,
}

// Client represents a dnsconn Client.  It satisfies net.Conn. */
type Client struct {
	domain    string
	lookup    LookupFunc
	cid       []byte       /* Connection ID as a uvarint */
	qmax      uint         /* Maximum query size, not including the domain */
	pubkey    *[32]byte    /* Our pubkey keys */
	sharedkey *[32]byte    /* Pre-computed key with the server */
	encode    EncodingFunc /* Encoding function */
}

/* TODO: Implement net.Conn methods on Client */

const (
	/* Buffer length */
	buflen = 1024
	/* Maximum number of bytes we'll stick in a question */
	maxdomainlen = 253
)

var (
	/* pool holds the buffer pool for the package */
	pool = sync.Pool{New: func() interface{} {
		return make([]byte, buflen)
	}}
)

// Dial makes a connection to the dnsconnserver via DNS queries to the given
// domain.  If the config is nil, sensible defaults will be used.  The server's
// public key is given with svrkey.
func Dial(domain string, svrkey *[32]byte, config *Config) (*Client, error) {
	/* Sensible Defaults */
	if nil == config {
		config = defaultConfig
	}

	/* Make sure the domain ends in a dot */
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	/* Have to have server's key */
	if nil == svrkey {
		return nil, errors.New("server's public key required")
	}

	/* Client to return */
	c := &Client{
		domain: domain,
		lookup: config.Lookup,
		cid:    []byte{0x00}, /* 0 as a uvarint */
		qmax:   config.MaxPayloadLen,
		encode: config.Encoder,
	}

	/* Make sure we have a lookup function */
	if nil == c.lookup {
		c.lookup = LookupWithBuiltin()
	}

	/* Work out how many bytes we can have in our queries */
	if 0 == c.qmax {
		c.qmax = defaultConfig.MaxPayloadLen
	}

	/* Make sure we have an encoder */
	if nil == c.encode {
		c.encode = defaultConfig.Encoder
	}

	/* Set up keys */
	var (
		sk  [32]byte
		kr  *[32]byte
		err error
	)
	c.pubkey, kr, err = keys.GenerateKeypair()
	log.Printf("Client pubkey: %02x", c.pubkey) /* DEBUG */
	if nil != err {
		return nil, err
	}
	box.Precompute(&sk, svrkey, kr)
	c.sharedkey = &sk

	/* Handshake */
	if err := c.handshake(); nil != err {
		return nil, err
	}

	/* TODO: Finish this */
	/* TODO: Handle defaults */

	return c, nil
}

// sendPayload sends a message with the given payload and returns the returned
// A record.
/* TODO: Write test for this */
func (c *Client) sendPayload(payload []byte) ([4]byte, error) {
	var ret [4]byte

	/* Roll the payload into something sendable on the wire */
	mbuf := pool.Get().([]byte)
	defer pool.Put(mbuf)
	n, err := c.marshalPayload(mbuf, payload)
	if nil != err {
		return ret, err
	}

	/* Perform the lookup */
	return c.lookup(string(mbuf[:n]))
}

/* marshalPayload rolls a payload sufficient for passing to lookup.  The
marshalled payload is placed in out and the length of the marshalled payload
is returned. */
func (c *Client) marshalPayload(out []byte, payload []byte) (int, error) {
	/* Message (plaintext) buffer */
	mbuf := pool.Get().([]byte)
	defer pool.Put(mbuf)

	/* Put the message bits into one place */
	mbuf = mbuf[:0]
	mbuf = append(mbuf, c.cid...)
	mbuf = append(mbuf, payload...)

	/* Encode the message */
	ebuf := pool.Get().([]byte)
	defer pool.Put(ebuf)
	n := c.encode(ebuf, mbuf)
	ebuf = ebuf[:n]

	/* Add in the domain */
	ebuf = append(ebuf, '.')
	ebuf = append(ebuf, []byte(c.domain)...)

	/* Lowercase it so as to not be suspicious */
	var l rune
	for i, v := range ebuf {
		l = unicode.ToLower(rune(v))
		if 0xFF >= l {
			ebuf[i] = byte(l)
		}
	}

	/* Copy to the output buffer */
	if len(out) < len(ebuf) {
		return 0, errors.New("insufficient output buffer space")
	}
	copy(out, ebuf)

	return len(ebuf), nil
}
