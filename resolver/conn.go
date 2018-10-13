package resolver

/*
 * conn.go
 * Connection to a DNS server
 * By J. Stuart McMurray
 * Created 20181009
 * Last Modified 20181013
 */

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

/* ansOrError holds an answer or an error.  */
type ansOrErr struct {
	answer *dnsmessage.Message
	err    error
}

/* conn represents a connection to a DNS server. */
type conn struct {
	r *resolver /* Parent resolver */

	isPC bool /* c.(net.PacketConn)? */
	c    net.Conn
	txL  *sync.Mutex /* Send lock */

	/* Answers to queries are sent here */
	ansCh  map[uint16]chan<- ansOrErr
	ansChL *sync.Mutex

	/* Set by stop(), makes future calls return this */
	err  error
	errL *sync.Mutex
}

/* newAnsChannel registers a channel in r on which will be sent a reply to a
query with the returned ID.  The channel will be closed after the timeout. */
func (c *conn) newAnsChannel() (
	id uint16,
	ch <-chan ansOrErr,
	err error,
) {
	/* If the conn is already stopped, return that */
	c.errL.Lock()
	defer c.errL.Unlock()
	if nil != c.err {
		return 0, nil, c.err
	}

	c.ansChL.Lock()
	defer c.ansChL.Unlock()

	/* If there's already uint16Max outstanding queries, give up */
	if 0xFFFF <= len(c.ansCh) {
		return 0, nil, ErrTooManyQueries
	}

	/* Find a unique ID */
	id, err = c.r.randUint16()
	if nil != err {
		return 0, nil, err
	}
	for {
		if _, inUse := c.ansCh[id]; !inUse {
			break
		}
		id++
	}

	/* Register the channel */
	nch := make(chan ansOrErr)
	c.ansCh[id] = nch

	/* Close the channel if the message takes too long to come back */
	go func() {
		/* Work out how long to sleep before killing the channel */
		c.r.qtoL.RLock()
		to := c.r.qto
		c.r.qtoL.RUnlock()
		/* Wait until the timeout */
		time.Sleep(to)
		/* Grab hold of the channel if we have one */
		c.ansChL.Lock()
		defer c.ansChL.Unlock()
		ach, ok := c.ansCh[id]
		/* If we don't actually have a channel or if this isn't the
		right channel for this ID (because of ID reuse), we're done */
		if !ok || ach != nch {
			return
		}
		/* Close the channel and remove it from the map */
		delete(c.ansCh, id)
		close(ach)
		/* Drain the channel after we closed it to avoid
		channel leakage.  There's a small race here where the answer
		could come in right before the close and the drain loop gets it
		before the real reader which is more or less equivalent to the
		answer coming past the timeout. */
		for range nch {
			/* Drain */
		}
	}()

	return id, nch, nil
}

/* listenForAnswers listens on c.c for DNS answers and sends them to the
appropriate channel in c.ansCh. */
func (c *conn) listenForAnswers() {
	var (
		/* Read buffers */
		sbuf = c.r.upool.Get().([]byte)
		pbuf = c.r.bufpool.Get().([]byte)
		n    int
		size uint16
		err  error
	)

	for {
		/* Reset the size */
		size = uint16(len(pbuf))

		/* Grab a query */
		if !c.isPC {
			/* Grab the size */
			_, err = io.ReadFull(c.c, sbuf)
			if nil != err {
				c.stop(err)
				return
			}
			size = binary.BigEndian.Uint16(sbuf)
			/* Grab the query */
			_, err = io.ReadFull(c.c, pbuf[:size])
			if nil != err {
				c.stop(err)
				return
			}
		} else {
			n, err = c.c.Read(pbuf)
			if nil != err {
				c.stop(err)
				return
			}
			size = uint16(n)
		}

		/* Unmarshal it */
		msg := new(dnsmessage.Message)
		if err := msg.Unpack(pbuf[:size]); nil != err {
			c.stop(errors.New(
				"misbehaving server, unable to parse reply: " +
					err.Error(),
			))
			return
		}

		/* Send it to the right place */
		go c.sendAnsChannel(msg)
	}
}

/* sendAnsChannel sends the answer a to the proper answer channel in c */
func (c *conn) sendAnsChannel(a *dnsmessage.Message) {
	c.ansChL.Lock()
	defer c.ansChL.Unlock()

	/* Grab the answer channel */
	ch, ok := c.ansCh[a.Header.ID]

	/* If we don't have it, we got a resend of an answer */
	if !ok {
		return
	}

	/* Prevent double-sends */
	delete(c.ansCh, a.Header.ID)

	/* Send it back, make sure the channel closes */
	go func() {
		defer close(ch)
		ch <- ansOrErr{answer: a}
	}()
}

/* query makes a query via c */
func (c *conn) query(qm *dnsmessage.Message) (
	[]dnsmessage.Resource,
	dnsmessage.RCode,
	error,
) {
	/* Get the query ID as well as the channel from which to read it */
	id, ch, err := c.newAnsChannel()

	/* Add the ID and roll the message */
	qm.Header.ID = id
	qbuf := c.r.bufpool.Get().([]byte)
	defer c.r.bufpool.Put(qbuf)
	m, err := qm.AppendPack(qbuf[:0])
	if nil != err {
		return nil, 0xFFFF, err
	}

	/* If we're not sending on a packetconn, add the size */
	if !c.isPC {
		sm := c.r.bufpool.Get().([]byte)
		defer c.r.bufpool.Put(sm)
		if len(sm)-2 < len(m) {
			return nil, 0, errors.New("message too large")
		}
		binary.BigEndian.PutUint16(sm, uint16(len(m)))
		copy(sm[2:], m)
		m = sm[:len(m)+2]

	}

	/* Send the message */
	if err := c.send(m); nil != err {
		return nil, 0xFFFF, err
	}

	/* If we've a packetconn, keep sending the request until we've a reply
	or something else happens */
	var (
		done = make(chan struct{})
		wg   sync.WaitGroup
	)
	if c.isPC {
		wg.Add(1)
		go func() {
			wg.Done()

			/* Retry interval */
			c.r.qtoL.Lock()
			rint := c.r.rint
			c.r.qtoL.Unlock()
			for {
				select {
				case <-done:
					break
				case <-time.After(rint):
					err = c.send(m)
				}
			}
		}()
	}

	/* Wait for the reply */
	ans, ok := <-ch
	close(done)
	wg.Wait() /* Wait for resender, maybe */

	/* If we got an error back, that's that */
	if nil != ans.err {
		return nil, 0xFFFF, ans.err
	}

	/* If we didn't get a better error, but the answer channel was closed,
	it's a timeout */
	if !ok && nil == err {
		return nil, 0xFFFF, ErrAnswerTimeout
	}

	return ans.answer.Answers, ans.answer.Header.RCode, err
}

/* stop sends an error message to every channel and closes the conn.  This
is intended for when the conn is no longer usable.  Calls to stop after the
first call have no effect. */
func (c *conn) stop(err error) {
	/* Make sure we don't already have an error, and set the error */
	c.errL.Lock()
	defer c.errL.Unlock()
	if nil != c.err {
		return
	}
	c.err = err

	/* Remove the channels from the map, send the error to the channel, and
	close the channel. */
	c.ansChL.Lock()
	defer c.ansChL.Unlock()
	for id, ch := range c.ansCh {
		delete(c.ansCh, id)
		go func() {
			ch <- ansOrErr{err: err}
			close(ch)
		}()
	}
}

/* getErr threadsafely returns c.err */
func (c *conn) getErr() error {
	c.errL.Lock()
	defer c.errL.Unlock()
	return c.err
}

/* send sends b to c.c while holding c.txL to prevent interleaved sends. */
func (c *conn) send(b []byte) error {
	c.txL.Lock()
	defer c.txL.Unlock()
	_, err := c.c.Write(b)
	return err
}
