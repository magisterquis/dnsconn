package dnsconnclient

/*
 * handshake.go
 * Initial handshake with server
 * By J. Stuart McMurray
 * Created 20181208
 * Last Modified 20181208
 */

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/magisterquis/dnsconn/keys"
)

/* handsake performs the initial handshake with the server */
func (c *Client) handshake() error {
	/* Send our pubkey to the server */
	if err := c.sendPubkey(); nil != err {
		return err
	}

	/* TODO: Work out initial values for expected replies to gets and
	puts */

	/* TODO: Make sure encrypted comms work right */

	return nil
}

/* sendPubey sends our pubkey to the server */
func (c *Client) sendPubkey() error {
	var nsent byte /* Number of key bytes sent */

	/* Send the key */
	for start := 0; start < len(*c.pubkey); start += int(c.plen) {
		/* Work out end index */
		end := start + int(c.plen)
		if end > len(*c.pubkey) {
			end = len(*c.pubkey)
		}

		/* Record the number of bytes sent */
		nsent += byte(end - start)

		/* Send the query */
		a, err := c.sendPayload((*c.pubkey)[start:end])
		if nil != err {
			return err
		}

		/* If we got 0's back, bummer */
		if 0 == a[1] && 0 == a[2] && 0 == a[3] {
			return errors.New("server error")
		}

		log.Printf("[c0x%02x] Sent %02x got %v", c.pbuf[:c.pind], (*c.pubkey)[start:end], a) /* DEBUG */

		/* If this is the first query, we'll have a cid in the reply */
		if 0 == start {
			c.setCID(a)
			continue
		}

		/* The server should respond with the number of key bytes it
		has. */
		if a[1] != nsent || a[2] != nsent || a[3] != nsent {
			return fmt.Errorf("server returned incorrect reply")
		}
	}

	log.Printf("[c0x%02x] Shared key: %v", c.pbuf[:c.pind], keys.Encode(c.sharedkey)) /* DEBUG */
	return nil
}

/* setCID sets a new cid */
func (c *Client) setCID(a [4]byte) {
	/* The returned cid is a good old-fashioned int, uvarinted */
	cbuf := make([]byte, 11) /* This will hold a uvarint upto UINT64_MAX */
	a[0] = 0
	n := binary.PutUvarint(cbuf, uint64(binary.BigEndian.Uint32(a[:])))

	/* Update c */
	copy(c.pbuf, cbuf[:n])
	c.pind = n
	c.plen = len(c.pbuf) - n
}
