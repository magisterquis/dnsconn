package dnsconnclient

/*
 * handshake.go
 * Initial handshake with server
 * By J. Stuart McMurray
 * Created 20181208
 * Last Modified 20181219
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
	for start := 0; start < len(*c.pubkey); start = int(nsent) {
		/* Work out end index */
		end := start + int(c.txBuf.PLen())
		if end > len(*c.pubkey) {
			end = len(*c.pubkey)
		}

		/* Record the number of bytes sent */
		nsent += byte(end - start)

		/* Send the query */
		a, err := c.sendPayload(c.txBuf, (*c.pubkey)[start:end])
		if nil != err {
			return err
		}

		/* If we got 0's back, bummer */
		if 0 == a[1] && 0 == a[2] && 0 == a[3] {
			return errors.New("server error")
		}

		log.Printf("[c] Sent %02x got %v", (*c.pubkey)[start:end], a) /* DEBUG */

		/* If this is the first query, we'll have a cid in the reply */
		if 0 == start {
			if err := c.setCIDs(a); nil != err {
				return err
			}
			continue
		}

		/* The server should respond with the number of key bytes it
		has. */
		if a[1] != nsent || a[2] != nsent || a[3] != nsent {
			return fmt.Errorf("server returned incorrect reply")
		}
	}

	log.Printf("[c] Shared key: %v", keys.Encode(c.sharedkey)) /* DEBUG */
	return nil
}

/* setCID sets a new cids in the message buffers. */
func (c *Client) setCIDs(a [4]byte) error {
	/* The cid we got is a good old-fashioned uvarint */
	a[0] = 0
	cid := binary.BigEndian.Uint32(a[:])
	/* TODO: Maybe put cid in c for users? */

	/* For the tx side, we use the cid followed by a 0 */
	cid <<= 1
	if err := c.txBuf.setCID(cid); nil != err {
		return err
	}

	/* For the rx side, we use the cid followed by a 1 */
	cid++
	if err := c.rxBuf.setCID(cid); nil != err {
		return err
	}

	return nil
}
