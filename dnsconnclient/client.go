/* TODO: Documentation */
package dnsconnclient

/*
 * client.go
 * Client side of dnsconn
 * By J. Stuart McMurray
 * Created 20181204
 * Last Modified 20181219
 */

import (
	"errors"
	"log"
	"strings"
	"unicode"

	"github.com/magisterquis/dnsconn/keys"
	"golang.org/x/crypto/nacl/box"
)

// Config is used to configure a Client.
type Config struct {
	// Lookup specifies a lookup function to use.  By default the internal
	// resolver will be used.
	Lookup LookupFunc

	// PayloadLen is the number of payload bytes which will be passed to
	// the EncodingFunc.
	/* TODO: Something about too big and too small */
	// PayloadLen should be large enough to prevent identical requests
	// in a short span of time to avoid caching issues.  A conservative
	// default of 10 will be used if PayloadLen is 0.  Applications
	// requiring higher throughput should use a much higher number.
	// Applications where very few (e.g. <100) simultaneous connections to
	// the server are expected can probably set this as low as 4.
	PayloadLen uint

	// EncodingFunc is used to encode up to PayloadLen bytes into a
	// string suitable for use as a DNS query.  See the documentation for
	// EncodingFunc for more details.
	Encoder EncodingFunc
}

/* defaultConfig is the defaults to use for Dial if config is nil. */
var defaultConfig = &Config{
	Lookup:     LookupWithBuiltin(),
	PayloadLen: 10,
	Encoder:    Base32Encode,
}

// Client represents a dnsconn Client.  It satisfies net.Conn. */
type Client struct {
	pubkey    *[32]byte /* Our pubkey keys */
	sharedkey *[32]byte /* Pre-computed key with the server */

	encode EncodingFunc /* Encoding function */
	lookup LookupFunc   /* DNS query-maker */

	domain []byte  /* Domain surrounded by dots */
	txBuf  *msgBuf /* Buffer for sending data */
	rxBuf  *msgBuf /* Buffer for requests for data */
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
	mpl := config.PayloadLen
	if 0 == mpl {
		mpl = defaultConfig.PayloadLen
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
	c.txBuf = newMsgBuf(1, mpl)
	c.rxBuf = newMsgBuf(1, mpl)

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

/* sendMessage sends a message to the server */
func (c *Client) sendCTS(p []byte) error {
	/* TODO: Finish this */
	return nil
}

/* poll polls the server for new data */
func (c *Client) poll() {
	/* TODO: Finish this */
}

/* sendPayload sends p using b in a single query and returns the A record
returned by the server.  If p is too big to fit into b's internal buffer,
sendPayload panics. */
func (c *Client) sendPayload(m *msgBuf, p []byte) ([4]byte, error) {
	m.Lock()
	defer m.Unlock()

	/* Roll the payload into something sendable on the wire */
	n, err := c.marshalPayload(m, p)
	if errPayloadTooBig == err {
		/* Should never happen */
		panic(err)
	}
	if nil != err {
		return [4]byte{}, err
	}

	/* Perform the lookup */
	return c.lookup(string(m.ebuf[:n]))
}

/* errPayloadTooBig is returned by marshalPayload when the payload is bigger
than maxPayloadLen allows */
var errPayloadTooBig = errors.New("payload too big")

/* marshalPayload puts an encoded form of a possibly-padded p into m.ebuf along
with the domain and returns the length of the data in m.ebuf such that
string(c.ebuf[:n]) (where n is the returned int) is a DNS name ready to send
to the server.  It returns an error if len(p) > m.plen.  marshalPayload's
caller is responsible for locking m. */
func (c *Client) marshalPayload(m *msgBuf, p []byte) (int, error) {
	/* Panic if we have too much payload */
	if len(p) > m.PLen() {
		/* Should never happen */
		return 0, errPayloadTooBig
	}

	/* Get the encodable bit encoded */
	copy(m.pbuf[m.pind:], p)

	/* Zero out the unused bytes */
	for i := m.pind + len(p); i < len(m.pbuf); i++ {
		m.pbuf[i] = 0
	}

	/* Encode and make sure the result doesn't end in a dot. */
	n := c.encode(m.ebuf, m.pbuf)
	if '.' == m.ebuf[n-1] {
		n--
	}

	/* Lowercase it so as to not be suspicious */
	var l rune
	for i, v := range m.ebuf[:n] {
		l = unicode.ToLower(rune(v))
		if 0xFF >= l {
			m.ebuf[i] = byte(l)
		}
	}

	/* Add in the domain */
	copy(m.ebuf[n:], c.domain)

	return n + len(c.domain), nil
}
