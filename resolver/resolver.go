// Package resolver implements a lightweight DNS resolver
package resolver

/*
 * resolver.go
 * Lightweight DNS resolver
 * By J. Stuart McMurray
 * Created 20180925
 * Last Modified 20180925
 */

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

// QueryMethod is used to configure which server(s) are queried by resolver
// returned by NewResolver.
type QueryMethod int

const (
	// RoundRobin causes a different server to be used for every query.
	RoundRobin QueryMethod = iota

	// NextOnFail causes the servers to be tried in order until one
	// returns an answer or the list of servers is exhausted.
	NextOnFail

	// QueryAll causes all servers to be tried for every query.
	QueryAll
)

// StdlibResolver is a Resolver which wraps the net.Lookup* functions.  The
// Resolver's LookupAC and LookupAAAAC methods will always return errors and
// its LookupA and LookupAAAA methods will both make queries for both A and
// AAAA records.
var StdlibResolver Resolver = stdlibResolver()

// MX represents an MX record.
type MX struct {
	Preference uint16
	Name       string
}

// SRV represents a SRV record.
type SRV struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

// Resolver implements a lightweight DNS resolver.
type Resolver interface {
	// LookupA returns the A records (IPv4 addresses) for the given name.
	// CNAME records, if returned, will be resolved into A records.
	LookupA(name string) ([][4]byte, error)

	//// LookupAC performs a query for A records for the given name, but
	//// expects and returns only CNAME records sent in the reply.
	//LookupAC(name string) ([]string, error)

	//// LookupNS returns the NS records for the given name.
	//LookupNS(name string) ([]string, error)

	//// LookupCNAME returns the CNAME records for the given name.
	//LookupCNAME(name string) ([]string, error)

	//// LookupPTR looks up the PTR records for the given IP address.
	//LookupPTR(addr net.IP) ([]string, error)

	//// LookupMX looks up the MX records for the given name.
	//LookupMX(name string) ([]MX, error)

	//// LookupTXT looks up the TXT records for the given name.
	//LookupTXT(name string) ([]string, error)

	//// LookupAAAA looks up the AAAA records (IPv6 addresses) for the given
	//// name.  CNAME records, if returned, will be resolved into AAAA
	//// records.
	//LookupAAAA(name string) ([][16]byte, error)

	//// LookupAAAAC performs a query for AAAA records for the given name,
	//// but expects and returns only CNAME records sent in the reply.
	//LookupAAAAC(name string) ([]string, error)

	//// LookupSRV looks up the SRV records for the given name.
	//LookupSRV(name string) ([]SRV, error)
}

/* buflen is the size of the buffers kept in the resolver's pool */
const buflen = 10240

/* resolver is the built-in implementation of Resolver */
type resolver struct {
	packetConn  net.PacketConn
	servers     []net.IP
	queryMethod QueryMethod
	bufpool     *sync.Pool
	upool       *sync.Pool
}

// NewResolver returns a resolver which makes queries to the given servers.
// How the servers are queried is determined by method.
func NewResolver(servers []net.IP, method QueryMethod) (Resolver, error) {
	/* Make sure we actually have servers */
	if 0 == len(servers) {
		return nil, errors.New("no servers specified")
	}

	return &resolver{
		servers:     servers,
		queryMethod: method,
		bufpool:     newBufPool(buflen),
		upool:       newBufPool(2),
	}, nil

}

// NewResolverFromPacketConn returns a Resolver which sends its queries on the
// provided net.PacketConn.  The net.PacketConn should be associated with a
// peer, such as with net.DialUDP or net.DialUnix with "unixpacket" as the
// network.
func NewResolverFromPacketConn(pc net.PacketConn) Resolver {
	return &resolver{
		packetConn: pc,
		bufpool:    newBufPool(buflen),
		upool:      newBufPool(2),
	}
}

/* newBufPool returns a new sync.Pool which holds buffers of the given size. */
func newBufPool(size uint) *sync.Pool {
	return &sync.Pool{New: func() interface{} {
		return make([]byte, int(size))
	}}
}

/* randUint16 returns a random uint16 */
func (r *resolver) randUint16() (uint16, error) {
	b := r.upool.Get().([]byte)
	defer r.upool.Put(b)
	if _, err := rand.Read(b); nil != err {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}
