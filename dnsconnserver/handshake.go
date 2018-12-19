package dnsconnserver

/*
 * handshake.go
 * Handle handshaking clients
 * By J. Stuart McMurray
 * Created 20181208
 * Last Modified 20181208
 */

import (
	"encoding/binary"
	"errors"
	"log"
	"sync"
	"time"
)

/* TODO: Somewhere document that a x.0.0.0 on a handshake is a fail */

/* handshakeTimeout is how long a client has to finish handshaking */
const handshakeTimeout = 2 * time.Minute

/* newConn makes a new pending conn starting the key with keychunk */
func (l *Listener) newConn(keychunk []byte) ([4]byte, error) {

	/* Make sure we're accepting clients */
	l.newClientsL.Lock()
	if l.noMoreClients {
		l.newClientsL.Unlock()
		return errARec, errors.New(
			"handshake while not accepting clients",
		)
	}
	l.newClientsL.Unlock()

	/* Get a CID for the connection */
	cid, ok := l.getCID()
	if !ok {
		return errARec, errors.New("out of CIDs")
	}

	/* Roll a new client */
	c := &Client{
		cid:      cid,
		pubkey:   &[32]byte{},
		l:        new(sync.Mutex),
		listener: l,
	}
	if _, err := c.handlePayload(false, keychunk); nil != err {
		return errARec, err
	}
	l.debug("[%v] Initial message", cid)

	/* Stick it in the listener and start a timer to make sure the
	handshake finishes fast enough */
	l.clientsL.Lock()
	defer l.clientsL.Unlock()
	if _, ok := l.clients[cid]; ok { /* Should never happen */
		log.Panicf("duplicate sid %v", cid)
	}
	l.clients[cid] = c
	/* TODO: Start timer */

	/* Put the cid into the a record */
	var ret [4]byte
	binary.BigEndian.PutUint32(ret[:], cid)
	ret[0] = FIRSTABYTE

	return ret, nil
}

/* checkHandshakeTimeout removes c from l's client map if c hasn't finished its
handshake after to elapses. */
func (l *Listener) checkHandshakeTimeout(c *Client, to time.Duration) {
	/* Wait until the timeout elapses */
	time.Sleep(to)

	c.l.Lock()
	defer c.l.Unlock()

	/* If the handshake is done, we're done */
	if nil != c.sharedkey {
		return
	}

	/* We haven't got enough key in time, so consider the handshake dead */
	l.clientsL.Lock()
	defer l.clientsL.Unlock()
	delete(l.clients, c.cid)
}
