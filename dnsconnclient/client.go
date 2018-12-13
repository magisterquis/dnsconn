/* TODO: Documentation */
package dnsconnclient

/*
 * client.go
 * Client side of dnsconn
 * By J. Stuart McMurray
 * Created 20181204
 * Last Modified 20181212
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

	// PayloadLen is the number of bytes which will be encoded and sent to
	// the server in each DNS message.  The first 1-4 bytes of the payload
	// will be the same for each request and the remaining bytes will be
	// fairly high-entropy.
	//
	// MaxPayloadLen should be large enough to prevent identical requests
	// in a short span of time to avoid caching issues.  A conservative
	// default of 10 will be used if MaxPayloadLen is 0.  Applications
	// requiring higher throughput should use a much higher number.
	// Applications where very few (e.g. <100) simultaneous connections to
	// the server are expected can probably set this as low as 4.
	MaxPayloadLen uint

	// EncodingFunc is used to encode up to MaxPayloadLen bytes into a
	// string suitable for use as a DNS query.  See the documentation for
	// EncodingFunc for more details.
	Encoder EncodingFunc
}

/* defaultConfig is the defaults to use for Dial if config is nil. */
var defaultConfig = &Config{
	Lookup:        LookupWithBuiltin(),
	MaxPayloadLen: 10,
	Encoder:       Base32Encode,
}

// Client represents a dnsconn Client.  It satisfies net.Conn. */
type Client struct {
	pubkey    *[32]byte /* Our pubkey keys */
	sharedkey *[32]byte /* Pre-computed key with the server */

	encode EncodingFunc /* Encoding function */
	lookup LookupFunc   /* DNS query-maker */

	domain []byte /* Domain surrounded by dots */
	pbuf   []byte /* Buffer for the sid and payload */
	pbufL  *sync.Mutex
	pind   int    /* Payload start index in pbuf */
	plen   int    /* Payload length in pbuf */
	ebuf   []byte /* Encoded payload buffer */
}

/* TODO: Implement net.Conn methods on Client */

const (
	/* Buffer length */
	buflen = 1024
)

// Dial makes a connection to the dnsconnserver via DNS queries to the given
// domain.  If the config is nil, sensible defaults will be used.  The server's
// public key is given with svrkey.
func Dial(domain string, svrkey *[32]byte, config *Config) (*Client, error) {
	var c Client

	/* Initialize client */
	if err := c.init(domain, svrkey, config); nil != err {
		return nil, err
	}

	/* Handshake */
	if err := c.handshake(); nil != err {
		return nil, err
	}

	/* TODO: Start network service */

	/* TODO: Finish this */
	return &c, nil
}

/* init initializes c such that it is ready to start a handshake */
func (c *Client) init(domain string, svrkey *[32]byte, config *Config) error {
	/* Need a domain */
	if "" == domain {
		return errors.New("cannot use empty domain")
	}

	/* Sensible Defaults */
	if nil == config {
		config = defaultConfig
	}

	/* Have to have server's key */
	if nil == svrkey {
		return errors.New("server's public key required")
	}

	/* Make sure we have a paylod length */
	mpl := config.MaxPayloadLen
	if 0 == mpl {
		mpl = defaultConfig.MaxPayloadLen
	}
	if 1 == mpl {
		return errors.New("maximum payload length must be at least 2")
	}

	/* Set fields in client */
	c.lookup = config.Lookup
	c.encode = config.Encoder
	c.domain = []byte(
		"." + strings.ToLower(strings.Trim(domain, ".")) + ".",
	)
	c.pbuf = make([]byte, mpl)
	c.ebuf = make([]byte, buflen)
	c.pind = 1
	c.plen = int(mpl) - 1
	c.pbufL = new(sync.Mutex)

	/* Make sure we have functions */
	if nil == c.lookup {
		c.lookup = LookupWithBuiltin()
	}
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
	if nil != err {
		return err
	}
	log.Printf("Client pubkey: %02x", c.pubkey) /* DEBUG */
	box.Precompute(&sk, svrkey, kr)
	c.sharedkey = &sk

	return nil
}

/* sendPayload sends p in a single query and returns the A record returned by
the server.  If p is too big to fit into c's internal buffer, sendPayload
panics.  Only one query will be in-flight at any given time. */
func (c *Client) sendPayload(p []byte) ([4]byte, error) {
	c.pbufL.Lock()
	defer c.pbufL.Unlock()

	/* Roll the payload into something sendable on the wire */
	n, err := c.marshalPayload(p)
	if errPayloadTooBig == err {
		log.Panicf("oversized payload (%v > %v)", len(p), c.plen)
	}

	/* Perform the lookup */
	return c.lookup(string(c.ebuf[:n]))
}

/* errPayloadTooBig is returned by marshalPayload when the payload is bigger
than c.pbuf allows */
var errPayloadTooBig = errors.New("payload too big")

/* marshalPayload puts an encoded form of a possibly-padded p into c.ebuf along
with the domain and returns the length of the data in c.ebuf such that
string(c.ebuf[:n]) (where n is the returned int) is a DNS name ready to send
to the server.  It returns an error if len(p) > c.plen. */
func (c *Client) marshalPayload(p []byte) (int, error) {
	/* Panic if we have too much payload */
	if len(p) > c.plen {
		return 0, errPayloadTooBig
	}

	/* Get the encodable bit encoded */
	copy(c.pbuf[c.pind:], p)

	/* Zero out the unused bytes */
	for i := c.pind + len(p); i < len(c.pbuf); i++ {
		c.pbuf[i] = 0
	}

	/* Encode and make sure the result doesn't end in a dot. */
	n := c.encode(c.ebuf, c.pbuf)
	if '.' == c.ebuf[n-1] {
		n--
	}

	/* Lowercase it so as to not be suspicious */
	var l rune
	for i, v := range c.ebuf[:n] {
		l = unicode.ToLower(rune(v))
		if 0xFF >= l {
			c.ebuf[i] = byte(l)
		}
	}

	/* Add in the domain */
	copy(c.ebuf[n:], c.domain)

	return n + len(c.domain), nil
}
