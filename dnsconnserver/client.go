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
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// Client represents a connected dnsconnclient.  It satisfies net.Conn.
type Client struct {
	pubkey    *[32]byte
	pklen     uint /* Length of pubkey we have */
	sharedkey *[32]byte
	cid       uint32
	l         *sync.Mutex
	listener  *Listener
}

/* handleQuery handles a query sent by a client via the network and returns
an A record. */
func (c *Client) handlePayload(p []byte) ([4]byte, error) {
	c.l.Lock()
	defer c.l.Unlock()
	/* If we've not yet got the whole key, add to it */
	if nil == c.sharedkey {
		c.pklen += uint(copy((*c.pubkey)[c.pklen:], p))
		if len(c.pubkey) < int(c.pklen) {
			/* Unpossible */
			panic("client pubkey overflow")
		}
		/* If we've got the whole thing, ask for more */
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

	log.Printf("[s%v] Payload: %02x", c.cid, p) /* DEBUG */

	/* TODO: Finish this */
	return randARec(), errors.New("TODO: Finish this")
}

func (c *Client) Read([]byte) (int, error)           { return 0, nil }
func (c *Client) Write([]byte) (int, error)          { return 0, nil }
func (c *Client) Close() error                       { return nil }
func (c *Client) LocalAddr() net.Addr                { return nil }
func (c *Client) RemoteAddr() net.Addr               { return nil }
func (c *Client) SetDeadline(t time.Time) error      { return nil }
func (c *Client) SetReadDeadline(t time.Time) error  { return nil }
func (c *Client) SetWriteDeadline(t time.Time) error { return nil }
