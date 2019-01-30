package dnsconnclient

/*
 * msgbuf.go
 * Message encoding buffer
 * By J. Stuart McMurray
 * Created 20181219
 * Last Modified 20181219
 */

import (
	"encoding/binary"
	"errors"
	"sync"
)

var (
	// ErrInsufficientPayloadSpace is returned if the space allocated for
	// a payload is too small to hold both the CID returned by the server
	// as well as at least one byte of payload.  In this case,
	// Config.MaxPayloadLen was too small.
	ErrInsufficientPayloadSpace = errors.New("insufficient payload space")
)

/* msgBuf is lockable and holds a buffer for a payload its encoded form. */
type msgBuf struct {
	sync.Mutex
	pbuf  []byte /* Payload buffer */
	ebuf  []byte /* Buffer for encoded data */
	pind  int    /* Payload start index  */
	plen  int    /* Payload length */
	plenL *sync.Mutex
}

/* newMsgBuf returns a pointer to a newly-allocated msgBuf with plenty of
buffer space for a DNS request and the payload start index and payload length
set to the given values.  The payload buffer will be plen bytes long. */
func newMsgBuf(pind, plen uint) *msgBuf {
	return &msgBuf{
		pbuf:  make([]byte, plen),
		ebuf:  make([]byte, buflen),
		pind:  int(pind),
		plen:  int(plen - pind), /* one for the initial cid */
		plenL: new(sync.Mutex),
	}
}

/* setCID sets the beginning of m.pbuf to cid and updates m.pind and m.plen.
An error is returned if there is not enough buffer space for the both cid and a
payload. */
func (m *msgBuf) setCID(cid uint32) error {
	m.Lock()
	m.plenL.Lock()
	defer m.Unlock()
	defer m.plenL.Unlock()

	/* Turn cid into something we can encode */
	cbuf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(cbuf, uint64(cid))

	/* Make sure we'll have room */
	if len(m.pbuf) < n+1 {
		return ErrInsufficientPayloadSpace
	}

	/* Put the encoded cid at the front of pbuf and update how much
	payload we can put in pbuf and where it starts. */
	copy(m.pbuf, cbuf[:n])
	m.pind = n
	m.plen = len(m.pbuf) - n

	return nil
}

// PLen returns the payload length of m.  It is safe to call from multiple
// goroutines simultaneously.  The returned int will always be >0.
func (m *msgBuf) PLen() int {
	m.plenL.Lock()
	defer m.plenL.Unlock()
	return m.plen
}
