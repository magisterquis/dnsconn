package resolver

/*
 * query.go
 * perform a query
 * By J. Stuart McMurray
 * Created 20180926
 * Last Modified 20180926
 */

import (
	"errors"

	"golang.org/x/net/dns/dnsmessage"
)

// The following errors correspond to non-success (i.e. not NOERROR) Response
// Codes returned from DNS servers.
var (
	ErrRCFormErr  = errors.New("formerr")  /* Format Error */
	ErrRCServFail = errors.New("servfail") /* Server Failure */
	ErrRCNXDomain = errors.New("nxdomain") /* Nonexistent domain */
	ErrRCNotImp   = errors.New("notimp")   /* Not implemented */
	ErrRCRefused  = errors.New("refused")  /* Query refused */
)

/* query makes a query for the name and given type and returns all of the
answers of type atype it gets. */
func (r *resolver) query(
	name string,
	qtype dnsmessage.Type,
	atype dnsmessage.Type,
	depth uint, /* TODO: We'll need to follow CNAMES for some things */
) ([]dnsmessage.Resource, error) {
	var err error

	/* Roll query */
	buf := r.bufpool.Get().([]byte)
	defer r.bufpool.Put(buf)
	qm := dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
	}
	qm.Header.ID, err = r.randUint16()
	if nil != err {
		return nil, err
	}
	qm.Questions[0].Name, err = dnsmessage.NewName(name)
	if nil != err {
		return nil, err
	}
	qb, err := qm.AppendPack(buf[0:])
	if nil != err {
		return nil, err
	}

	/* Query either via the packetconn or server(s) */
	var anss []dnsmessage.Resource
	if nil != r.packetConn {
		anss, err = r.queryPC(qb)
	} else {
		anss, err = r.queryServers(qb)
	}
	if nil != err {
		return nil, err
	}

	/* Filter output by ans.Header.Type */
	last := 0
	for _, ans := range anss {
		/* Make sure answer comes back for the right name */
		if ans.Header.Name.String() != name {
			continue
		}

		/* Skip if the answer type and qtype don't match */
		switch ans.Body.(type) {
		case *dnsmessage.AResource:
			if atype != dnsmessage.TypeA {
				continue
			}
		case *dnsmessage.NSResource:
			if atype == dnsmessage.TypeNS {
			}
		case *dnsmessage.CNAMEResource:
			if atype == dnsmessage.TypeCNAME {
			}
		case *dnsmessage.SOAResource:
			if atype == dnsmessage.TypeSOA {
			}
		case *dnsmessage.PTRResource:
			if atype == dnsmessage.TypePTR {
			}
		case *dnsmessage.MXResource:
			if atype == dnsmessage.TypeMX {
			}
		case *dnsmessage.TXTResource:
			if atype == dnsmessage.TypeTXT {
			}
		case *dnsmessage.AAAAResource:
			if atype == dnsmessage.TypeAAAA {
			}
		case *dnsmessage.SRVResource:
			if atype == dnsmessage.TypeSRV {
			}
		default:
			continue
		}
		anss[last] = ans
		last++
	}
	anss = anss[:last]

	return anss[:last], nil
}

/* queryPC makes a query via the "connected" packetconn */
func (r *resolver) queryPC(m []byte) (
	[]dnsmessage.Resource,
	dnsmessage.Rcode,
	error,
) {
	buf := r.bufpool.Get().([]byte)
	defer r.bufpool.Put(buf)
	/* TODO: Finish this */

	return nil, nil /* DEBUG */
}

/* queryServers makes a query via the configured server(s) */
func (r *resolver) queryServers(m []byte) (
	[]dnsmessage.Resource,
	dnsmessage.Rcode,
	error,
) {
	/* Work out how to query based on r.queryMethod */
	switch r.queryMethod {
	/* TODO: Finish this */
	}

	/* TODO: Finish this */
	return nil, nil /* DEBUG */
}
