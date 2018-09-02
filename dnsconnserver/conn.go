package dnsconnserver

/*
 * conn.go
 * Serverside connections
 * By J. Stuart McMurray
 * Created 20180823
 * Last Modified 20180901
 */

import (
	"bytes"
	"container/list"
	"errors"
	"net"
	"sync"
	"time"
)

// connbuflen is the length of the buffers used for proxying data to/from
// Read and Write calls.
const connbuflen = 4096

// AddrNetwork is the network name returned by Addr.Network.
const AddrNetwork = "dnsconn"

var (
	// ErrLocalClosed is set when Close has been called on a Conn.
	ErrLocalClosed = errors.New("connection closed locally")
	// ErrAckTooHigh indicates a client has acked bytes which haven't been
	// sent.
	ErrAckTooHigh = errors.New("ack too high")
	// ErrClientClosed is returned when the client has closed a Conn.
	ErrClientClosed = errors.New("connection closed by client")
)

// Addr represents the address of a Conn.  Since it is not possible to
// determine the true source due to the nature of the underlying DNS comms,
// Addr holds the Conn's ID.
type Addr string

// Network returns the network name, AddrNetwork.
func (a Addr) Network() string {
	return AddrNetwork
}

// String returns a.
func (a Addr) String() string { return string(a) }

// Conn is a stream-oriented network connection.  It satisfies the net.Conn
// interface.
type Conn struct {
	wg    *sync.WaitGroup /* Used for Conn.l.Done */
	laddr net.Addr
	id    string /* Conn ID */

	/* Network pipe, which handles deadlines niecly for us. */
	ic net.Conn /* Internal conn, used by this library */
	ec net.Conn /* External conn, used by users */

	/* Network to Client message queue */
	n2cQ         *list.List /* Queue of received messages */
	n2cNextIndex uint       /* Index of the next byte needed */
	n2cLock      *sync.Mutex
	n2cCond      *sync.Cond

	/* Client to Network messages */
	c2nBuf   *bytes.Buffer /* Bytes read from the client */
	c2nIndex uint          /* Index of the first byte in the buffer */
	c2nLock  *sync.Mutex
	c2nCond  *sync.Cond

	/* Error which really caused the close */
	err  error
	errl *sync.Mutex
}

/* newConn returns a new conn, ready to be returned by AcceptConn. */
func newConn(id string, localAddr net.Addr, wg *sync.WaitGroup) *Conn {
	/* External<->Internal net.Conn pipe */
	ec, ic := net.Pipe()
	/* Mutexes, which we need for two fields each */
	n2cl := new(sync.Mutex)
	c2nl := new(sync.Mutex)
	c := &Conn{
		wg:      wg,
		laddr:   localAddr,
		id:      id,
		ic:      ic,
		ec:      ec,
		n2cQ:    list.New(),
		n2cLock: n2cl,
		n2cCond: sync.NewCond(n2cl),
		c2nBuf:  new(bytes.Buffer),
		c2nLock: c2nl,
		c2nCond: sync.NewCond(n2cl),
		errl:    new(sync.Mutex),
	}

	/* Start proxy functions going */
	go c.sendToRead()
	go c.recvFromWrite()

	return c
}

/* sendToRead sends bytes from c.n2cQ to c.ic. */
func (c *Conn) sendToRead() {
	/* Buffer for Read */
	buf := make([]byte, 0, connbuflen)
	for {
		/* Reset buffer's length */
		buf = buf[:0]

		/* Wait until we have data */
		c.n2cLock.Lock()
		for 0 == c.n2cQ.Len() {
			c.n2cCond.Wait()
		}

		/* Make sure we weren't woken up because of Close */
		c.errl.Lock()
		if nil != c.err {
			c.errl.Unlock()
			return
		}
		c.errl.Unlock()

		/* Read from the list until we have no more */
		for 0 < c.n2cQ.Len() &&
			(connbuflen-len(buf)) >=
				len(c.n2cQ.Front().Value.([]byte)) {
			/* Add the chunk to buf */
			chunk := c.n2cQ.Remove(c.n2cQ.Front()).([]byte)
			buf = append(buf, chunk...)
		}
		c.n2cLock.Unlock()

		/* Send it out on the conn */
		if _, err := c.ic.Write(buf); nil != err {
			go c.CloseError(err)
			break
		}
	}
}

/* recvFromWrite copies data from c.ic into c.c2nbuf */
func (c *Conn) recvFromWrite() {
	var (
		n   int
		err error
		buf = make([]byte, connbuflen)
	)
	for {
		/* Wait until the buffer's empty */
		c.c2nLock.Lock()
		for 0 != c.c2nBuf.Len() {
			/* Wait until a send signals the buffer's empty */
			c.c2nCond.Wait()
		}

		/* Make sure we weren't woken up because of Close */
		c.errl.Lock()
		if nil != c.err {
			c.errl.Unlock()
			return
		}
		c.errl.Unlock()

		/* Read into buffer */
		n, err = c.ic.Read(buf)
		if nil != err {
			c.c2nLock.Unlock()
			go c.CloseError(err)
		}
		/* Make available for network */
		c.c2nBuf.Write(buf[:n])

		c.c2nLock.Unlock()
	}
}

// Read reads into b from the internal buffer, which will grow limitlessly
// if Read is not called.  Read will only block if the buffer is empty.
func (c *Conn) Read(b []byte) (n int, err error) { return c.ec.Read(b) }

// Write writes b via DNS replies and blocks until either all of b is written,
// the connection is closed, or a timeout occurs.
func (c *Conn) Write(b []byte) (n int, err error) { return c.ec.Write(b) }

// Close closes the connection and returns nil.  Calling Close is equivalent to
// calling CloseError with ErrLocalClosed.  Close always returns nil.  Any
// blocked Read or Write operations will be unblocked and return errors.
func (c *Conn) Close() error {
	return c.CloseError(ErrLocalClosed)
}

// LocalAddr returns the address of the Listener which accepted c.
func (c *Conn) LocalAddr() net.Addr { return c.laddr }

// RemoteAddr returns c's ID.
func (c *Conn) RemoteAddr() net.Addr { return Addr(c.id) }

// SetDeadline sets the read and write deadlines for c.
func (c *Conn) SetDeadline(t time.Time) error { return c.ec.SetDeadline(t) }

// SetReadDeadline sets the read deadline for c.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.ec.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline for c.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.ec.SetWriteDeadline(t)
}

/* psh handles a question with data for c */
func (c *Conn) psh(qn *question) error {
	/* Make sure c isn't closed */
	c.errl.Lock()
	if nil != c.err {
		c.errl.Unlock()
		return c.err
	}
	c.errl.Unlock()

	/* This probably shouldn't happen, but just in case */
	if 0 == len(qn.msg.Payload) {
		return nil
	}

	c.n2cLock.Lock()
	defer c.n2cLock.Unlock()

	/* Make sure the index is the next one in the series.  If not, ask for
	the proper data. */
	if qn.msg.Index != c.n2cNextIndex {
		qn.PutUint(c.n2cNextIndex, true)
		return nil
	}

	/* Add the message to the queue, set the reply to tell the client the
	index of the next byte */
	p := qn.msg.Payload
	/* Push chunks from the Payload */
	end := 0
	for start := 0; start < len(p); start += connbuflen {
		/* Work out the end index */
		end = start + connbuflen
		if len(p) < end {
			end = len(p)
		}
		c.n2cQ.PushBack(p[start:end])
	}
	c.n2cNextIndex += uint(len(p))
	qn.PutUint(c.n2cNextIndex, true)

	/* Wake up the routine servicing Read */
	c.n2cCond.Signal()

	return nil
}

/* req handles a question requesting data from c */
func (c *Conn) req(qn *question) error {
	/* Make sure c isn't closed */
	c.errl.Lock()
	if nil != c.err {
		c.errl.Unlock()
		return c.err
	}
	c.errl.Unlock()

	c.c2nLock.Lock()
	defer c.c2nLock.Unlock()

	/* If we've no buffered bytes, life's easy */
	if 0 == c.c2nBuf.Len() {
		return nil
	}

	/* If the request is for previous bytes, we've already sent them */
	if qn.msg.Index < c.c2nIndex {
		return nil
	}

	/* Remove bytes up to the requested index, if we've unacked bytes */
	if qn.msg.Index > c.c2nIndex {
		off := qn.msg.Index - c.c2nIndex
		/* If we've got more acked than we've sent, that's a
		misbehaving client. */
		if uint(c.c2nBuf.Len()) < off {
			go c.CloseError(ErrAckTooHigh)
			return ErrAckTooHigh
		}

		/* Remove ack'd bytes */
		c.c2nBuf.Next(int(off))
		c.c2nIndex = qn.msg.Index
	}

	/* Number of bytes to get */
	n := qn.DataLen()
	if uint(c.c2nBuf.Len()) < n {
		n = uint(c.c2nBuf.Len())
	}

	/* Reply to the question */
	buf := make([]byte, n)
	copy(buf, c.c2nBuf.Bytes())
	qn.Push(buf, c.c2nIndex+n-1) /* TODO: Check for off-by-one */

	return nil
}

/* rindex handles a request to reset the index.  This is only allowed if the
client agrees on the index of the next byte. */
func (c *Conn) rindex(qn *question) {
	c.n2cLock.Lock()
	defer c.n2cLock.Unlock()
	c.c2nLock.Lock()
	defer c.c2nLock.Unlock()
	c.n2cNextIndex = 0
	c.c2nIndex = 0
}

/* fin handles a request to end the Conn */
func (c *Conn) fin(qn *question) error {
	return c.CloseError(ErrClientClosed)
}

// ID returns c's ID as a string.
func (c *Conn) ID() string { return c.id }

// Err returns the error which caused c to close.  This may be different than
// the errors returned by Read and Write.
func (c *Conn) Err() error {
	c.errl.Lock()
	defer c.errl.Unlock()
	return c.err
}

// CloseError closes the Conn and sets the error returned by c.Err to err.
// Subseuent calls to CloseError will have no effect.
func (c *Conn) CloseError(err error) error {
	c.errl.Lock()
	defer c.errl.Unlock()

	/* Don't double-close */
	if nil != c.err {
		return nil
	}

	/* Decrement wg when we're done to let listener know. */
	defer c.wg.Done()

	/* Set the error */
	c.err = err

	/* Wake up the goroutine which buffers data from DNS.  We add something
	to the queue so it won't go back to sleep. */
	c.n2cLock.Lock()
	c.n2cQ.PushBack([]byte{})
	c.n2cLock.Unlock()
	c.n2cCond.Signal()

	/* Wake up the goroutine which buffers data from the Conn */
	c.c2nLock.Lock()
	c.c2nBuf.Next(c.c2nBuf.Len())
	c.c2nBuf.Reset()
	c.c2nLock.Unlock()
	c.c2nCond.Signal()

	/* Close internal conn */
	return c.ic.Close()
}

/* resetIndex resets the index of the next expected received byte to 0 */
func (c *Conn) resetIndex() {
	c.n2cLock.Lock()
	defer c.n2cLock.Unlock()
	c.n2cNextIndex = 0
}
