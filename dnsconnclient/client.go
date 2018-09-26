// dnsconnclient is the client side of DNSConn.
package dnsconnclient

/*
 * client.go
 * Client side of dnsconn
 * By J. Stuart McMurray
 * Created 20180925
 * Last Modified 20180925
 */

import "net"

// Config is used to configure a new client
type Config struct {
	/* TODO: Finish this */
}

// Conn represents the client side of dnsconn.
/* TODO: Document handshake */
type Conn struct {
	/* TODO: Finish this */
}

// Dial uses the default resolver to connect to a dnsconnserver with requests
// for the specified parent domain.  Conns returned by Dial do not treat
// requests for A records and requests for AAAA records as separate due to the
// underlying use of net.LookupIP.  To prevent requests for one record type but
// not the other use another Dial function.  Queries for the AC pseudotype will
// not be made by Conns returned by Dial.
func Dial(parent string, conf Config) (*Conn, error) {
	/* TODO: Finish this */
	/* TODO: Make sure we don't use AC */
}

// DialWithPacketConn uses the given net.PacketConn to connect to a
// dnsconnserver with requests for the specified parent domain.  The
// net.PacketConn should be associated with a peer, such as with net.DialUDP
// or net.DialUnix with "unixpacket" as the network.
func DialWithPacketConn(parent string, pc net.PacketConn, conf Config) (*Conn, error) {
	return DialWithResolver(
		parent,
		dnsconn.NewResolverFromPacketConn(pc),
		conf,
	)
}

// DialWithResolver uses the provided resolver to connect to a dnsconnserver
// with requests for the specified parent domain.
func DialWithResolver(parent string, resolver dnsconn.Resolver, conf Config) (*Conn, error) {
	/* TODO: Finish this */
}
