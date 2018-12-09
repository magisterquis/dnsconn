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
	var nsent byte /* Number of key bytes sent */

	/* TODO: Put in kex function */
	/* Send the key */
	for start := 0; start < len(*c.pubkey); start += int(c.qmax) {
		/* Work out end index */
		end := start + int(c.qmax)
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

		/* TODO: Check A */
		log.Printf("[c0x%02x] Sent %02x got %v", c.cid, (*c.pubkey)[start:end], a) /* DEBUG */

		/* If this is the first iteration, we'll get a cid which may
		be bigger than our current, one-byte cid. */
		if 0 == start {
			/* The returned cid is a good old-fashioned int */
			cbuf := pool.Get().([]byte)
			defer pool.Put(cbuf)
			a[0] = 0
			n := binary.PutUvarint(
				cbuf,
				uint64(binary.BigEndian.Uint32(a[:])),
			)

			/* Set the new cid */
			osl := len(c.cid)
			c.cid = cbuf[:n]

			/* Adjust how many bytes we can send now */
			c.qmax += uint(osl)
			if uint(n) >= c.qmax {
				return errors.New(
					"maximum payload size too small",
				)
			}
			c.qmax -= uint(n)

			continue
		}

		/* The server should respond with the number of bytes sent */
		if a[1] != nsent || a[2] != nsent || a[3] != nsent {
			return fmt.Errorf("server returned incorrect reply")
		}
	}

	log.Printf("[c0x%02x] Shared key: %v", c.cid, keys.Encode(c.sharedkey)) /* DEBUG */

	/* TODO: Make sure encrypted comms work right */

	return nil
}
