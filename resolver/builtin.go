package resolver

/*
 * builtin.go
 * Wraps the net.Lookup* functions
 * By J. Stuart McMurray
 * Created 20180925
 * Last Modified 20180925
 */

import (
	"errors"
	"net"
)

// ErrNotImplemented is returned by StdlibResolver's LookupAC and LookupAAAAAC
// methods.
var ErrNotImplemented = errors.New("not implemented")

/* stdlib exists only to define methods on */
type stdlib struct{}

/* returns a Resolver using stdlib functions */
func stdlibResolver() Resolver { return stdlib{} }

// LookupA wraps net.LookupIP but only returns A records.
func (s stdlib) LookupA(name string) ([][4]byte, error) {
	/* Get only IPv4 IPs */
	ips, err := s.lookupIPFilter(
		name,
		func(i net.IP) net.IP { return i.To4() },
	)
	if nil != err {
		return nil, err
	}

	/* Convert to byte slices */
	ret := make([][4]byte, len(ips))
	for i, ip := range ips {
		copy(ret[i][:], ip)
	}

	return ret, nil
}

/* lookupIPSize looks up IP addresses as filtered throuh check. */
func (s stdlib) lookupIPFilter(
	name string,
	check func(i net.IP) net.IP,
) ([]net.IP, error) {
	/* Lookup the addresses */
	as, err := net.LookupIP(name)
	if nil != err {
		return nil, err
	}

	/* Grab only the A records */
	r := make([]net.IP, 0)
	for _, a := range as {
		/* Try to convert to IPv4 */
		i := check(a)
		if nil == i {
			continue
		}
		r = append(r, i)
	}

	return r, nil
}

// LookupAC can't be implemented with stdlib net.Lookup* calls.
func (s stdlib) LookupAC(string) ([]string, error) {
	return nil, ErrNotImplemented
}

// LookupNS wraps net.LookupNS.
func (s stdlib) LookupNS(name string) ([]string, error) {
	/* Wrap call */
	ns, err := net.LookupNS(name)
	if nil != err {
		return nil, err
	}

	/* Dig out answers */
	ret := make([]string, len(ns))
	for i, n := range ns {
		ret[i] = n.Host
	}

	return ret, nil
}

// LookupCNAME wraps net.LookupCNAME
func (s stdlib) LookupCNAME(name string) ([]string, error) {
	n, err := net.LookupCNAME(name)
	return []string{n}, err
}

// LookupPTR wraps net.LookupAddr
func (s stdlib) LookupPTR(ip net.IP) ([]string, error) {
	return net.LookupAddr(ip.String())
}

// LookupMX wraps net.LookupMX
func (s stdlib) LookupMX(name string) ([]MX, error) {
	/* Wrap call */
	mxs, err := net.LookupMX(name)
	if nil != err {
		return nil, err
	}

	/* Convert answers */
	ret := make([]MX, len(mxs))
	for i, mx := range mxs {
		ret[i].Preference = mx.Pref
		ret[i].Name = mx.Host
	}

	return ret, nil
}

// LookupTXT wraps net.LookupTXT
func (s stdlib) LookupTXT(name string) ([]string, error) {
	return net.LookupTXT(name)
}

// LookupAAAA wraps net.LookupIP but only returns AAAA records.
func (s stdlib) LookupAAAA(name string) ([][16]byte, error) {
	/* Get only IPv4 IPs */
	ips, err := s.lookupIPFilter(
		name,
		func(i net.IP) net.IP {
			/* Make sure it's not an IPv4 address */
			if nil != i.To4() {
				return nil
			}
			return i.To16()
		},
	)
	if nil != err {
		return nil, err
	}

	/* Convert to byte slices */
	ret := make([][16]byte, len(ips))
	for i, ip := range ips {
		copy(ret[i][:], ip)
	}

	return ret, nil
}

// LookupAAAAC can't be implemented with stdlib net.Lookup* calls.
func (s stdlib) LookupAAAAC(string) ([]string, error) {
	return nil, ErrNotImplemented
}

// LookupSRV wraps net.LookupSRV
func (s stdlib) LookupSRV(name string) ([]SRV, error) {
	/* Wrap call */
	_, srvs, err := net.LookupSRV("", "", name)
	if nil != err {
		return nil, err
	}

	/* Convert answers */
	ret := make([]SRV, len(srvs))
	for i, srv := range srvs {
		ret[i].Priority = srv.Priority
		ret[i].Weight = srv.Weight
		ret[i].Port = srv.Port
		ret[i].Target = srv.Target
	}

	return ret, nil
}
