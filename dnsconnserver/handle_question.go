package dnsconnserver

/*
 * handle_question.go
 * Process a single, domain-agnostic question
 * By J. Stuart McMurray
 * Created 20181208
 * Last Modified 20181208
 */

import (
	"encoding/base32"
	"encoding/binary"
	"errors"
	"strings"
)

var (
	/* b32decode decodes a base32-encoded message */
	b32decode = base32.HexEncoding.WithPadding(base32.NoPadding).Decode

	/* errARec is the A record indicating an error */
	errARec = [4]byte{FIRSTABYTE, 0, 0, 0}
)

/* handleQuestion unpacks q and either handshakes, or sends the payload to the
right Conn. q must only contain numbers and upper-case letters. */
func (l *Listener) handleQuestion(q string) ([4]byte, error) {
	buf := l.pool.Get().([]byte)
	defer l.pool.Put(buf)

	/* TODO: Custom decoder which handles removing dots and base32 decoding */
	q = strings.Replace(q, ".", "", -1)
	/* Unpack q */
	n, err := b32decode(buf, []byte(strings.ToUpper(q)))
	if nil != err {
		return randARec(), err
	}
	buf = buf[:n]

	/* First uvarint is the connection ID */
	uv, n := binary.Uvarint(buf)
	switch {
	case 0 < n: /* Normal read */
		buf = buf[n:]
	case 0 == n: /* Buffer too small */
		return randARec(), errors.New("too small to read cid")
	case 0 > n: /* Overflow */
		return randARec(), errors.New("cid overflow")
	}
	/* If the SID is too big, the packet's not meant for us */
	if uint64(cidMAX) < uv {
		return randARec(), errors.New("cid too large")
	}
	cid := uint32(uv)

	/* If the cid is 0, it's a new connection */
	if 0 == cid {
		/* If we're not accepting clients, tell this one to go away */
		return l.newConn(buf)
	}

	/* Make sure we have the right client */
	l.clientsL.Lock()
	c, ok := l.clients[cid]
	l.clientsL.Unlock()
	if !ok { /* Don't have this client */
		return errARec, nil
	}

	/* Let the right client handle it. */
	return c.handlePayload(buf)
}
