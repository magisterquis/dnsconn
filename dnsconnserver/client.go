package dnsconnserver

/*
 * client.go
 * dnsconnserver client
 * By J. Stuart McMurray
 * Created 20181203
 * Last Modified 20181203
 */

import (
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// Client represents a connected dnsconnclient.  It satisfies net.Conn.
type Client struct {
	pubkey    *[32]byte
	pklen     byte /* Length of pubkey we have */
	sharedkey *[32]byte
	cid       uint32
	l         *sync.Mutex
	listener  *Listener
}

/* handleQuery handles a query sent by a client via the network and returns
an A record.  If rx is true, p is assumed to contain received payload data.
During handshaking, rx is ignored. */
func (c *Client) handlePayload(rx bool, p []byte) ([4]byte, error) {
	c.l.Lock()
	defer c.l.Unlock()

	/* If we've not yet got the whole key, add to it */
	if nil == c.sharedkey {
		return c.handleKeyChunk(p)
	}

	/* TODO: Finish this */
	return randARec(), errors.New("TODO: Finish this")
}

/* handleKeyChunk adds the p to the current public key and returns the length
of the key after p is added.  If p contains more bytes than are needed, only
the needed bytes will be added. */
func (c *Client) handleKeyChunk(p []byte) ([4]byte, error) {

	/* Work out how many bytes we still need */
	end := len(c.pubkey) - int(c.pklen)
	if 0 > end {
		/* Should be unpossible */
		return randARec(), errors.New("pubkey overflow")
	}
	if 0 == end {
		/* We have all the pubkey we need and shouldn't get any more */
		return randARec(), errors.New("unneeded pubkey chunk")
	}
	if len(p) < end {
		end = len(p)
	}

	/* Add this chunk */
	c.pklen += byte(copy(c.pubkey[c.pklen:], p[:end]))

	/* If we've got the whole thing, compute the shared key */
	if len(c.pubkey) == int(c.pklen) {
		var sk [32]byte
		box.Precompute(&sk, c.pubkey, c.listener.privkey)
		c.sharedkey = &sk
		c.listener.debug("[%v] Kex complete", c.cid)
	}
	return [4]byte{
		FIRSTABYTE,
		byte(c.pklen),
		byte(c.pklen),
		byte(c.pklen),
	}, nil
}

func (c *Client) Read([]byte) (int, error)           { return 0, nil }
func (c *Client) Write([]byte) (int, error)          { return 0, nil }
func (c *Client) Close() error                       { return nil }
func (c *Client) LocalAddr() net.Addr                { return nil }
func (c *Client) RemoteAddr() net.Addr               { return nil }
func (c *Client) SetDeadline(t time.Time) error      { return nil }
func (c *Client) SetReadDeadline(t time.Time) error  { return nil }
func (c *Client) SetWriteDeadline(t time.Time) error { return nil }
