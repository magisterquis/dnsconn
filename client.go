package dnsconn

/*
 * client.go
 * Dial side of dnsconn
 * By J. Stuart McMurray
 * Created 20180822
 * Last Modified 20180826
 */

func init() {} /* TODO: Remove this */

// ClientConn is a connection made to a server.  It implements net.Conn.
/*
type ClientConn struct{}

func (c *ClientConn) Dial() Conn
func (c *ClientConn) Read(b []byte) (n int, err error)
func (c *ClientConn) Write(b []byte) (n int, err error)
func (c *ClientConn) Close() error
func (c *ClientConn) LocalAddr() net.Addr
func (c *ClientConn) RemoteAddr() net.Addr
func (c *ClientConn) SetDeadline(t time.Time) error
func (c *ClientConn) SetReadDeadline(t time.Time) error
func (c *ClientConn) SetWriteDeadline(t time.Time) error
*/

/* TODO: Exchange messages with own-rolled UDP socket, not net.LookupIP */

/* ClientConfig is used to configure a new client connection. */
/*
type ClientConfig struct{}
*/
