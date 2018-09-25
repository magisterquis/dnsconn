package dnsconnserver

/*
 * conn.go
 * Server-side dnsconn conn
 * By J. Stuart McMurray
 * Created 20180923
 * Last Modified 20180923
 */

import (
	"net"
	"time"
)

// Conn is an implementation of the net.Conn interface using DNS as its
// transport.  Conn uses the underlying transport of its Server.
type Conn struct {
	ic net.Conn /* Internal conn */
	oc net.Conn /* External conn */
}

func newConn() *Conn {
	/* TODO: Finish this */
	return nil
}

/* TODO: Finish this */
func (c *Conn) Read(b []byte) (n int, err error) { return 0, nil }

/* TODO: Finish this */
func (c *Conn) Write(b []byte) (n int, err error) { return 0, nil }

/* TODO: Finish this */
func (c *Conn) Close() error { return nil }

/* TODO: Finish this */
func (c *Conn) LocalAddr() net.Addr { return nil }

/* TODO: Finish this */
func (c *Conn) RemoteAddr() net.Addr { return nil }

/* TODO: Finish this */
func (c *Conn) SetDeadline(t time.Time) error { return nil }

/* TODO: Finish this */
func (c *Conn) SetReadDeadline(t time.Time) error { return nil }

/* TODO: Finish this */
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }

/* handleQuery queues the payload from q to be sent to the conn, as well as
tries to read from the conn into q.  It sets q's rcode to NXDOMAIN if q's
message index is incorrect.  A cached answer will be sent if it exists. */
func (c *Conn) handleQuery(q *query) {
	/* TODO: Finish this */
}
