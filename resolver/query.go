package resolver

/*
 * query.go
 * perform a query
 * By J. Stuart McMurray
 * Created 20180926
 * Last Modified 20181013
 */

import (
	"errors"
	"strconv"
	"strings"

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

// ErrAnswerTimeout is returned if the answer did not return before the timeout
// elapsed.
var ErrAnswerTimeout = errors.New("timeout waiting for answer")

/* query makes a query for the name and given type and returns all of the
answers of type atype it gets. */
func (r *resolver) query(
	name string,
	qtype dnsmessage.Type,
	atype dnsmessage.Type,
) ([]dnsmessage.Resource, error) {
	var err error

	/* Roll query */
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	qm := &dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
	}
	qm.Questions[0].Name, err = dnsmessage.NewName(name)
	if nil != err {
		return nil, err
	}

	/* Send it out as appropriate */
	var (
		anss  []dnsmessage.Resource
		rcode dnsmessage.RCode
	)
	switch r.queryMethod {
	case RoundRobin:
		anss, rcode, err = r.roundRobin(qm)
	case NextOnFail:
		anss, rcode, err = r.nextOnFail(qm)
	case QueryAll:
		anss, rcode, err = r.queryAll(qm)
	default:
		panic(
			"unknown query method " +
				strconv.Itoa(int(r.queryMethod)),
		)
	}
	if nil != err {
		return nil, err
	}

	/* If we got a non-success rcode, return that */
	switch rcode {
	case dnsmessage.RCodeFormatError:
		return nil, ErrRCFormErr
	case dnsmessage.RCodeServerFailure:
		return nil, ErrRCServFail
	case dnsmessage.RCodeNameError:
		return nil, ErrRCNXDomain
	case dnsmessage.RCodeNotImplemented:
		return nil, ErrRCNotImp
	case dnsmessage.RCodeRefused:
		return nil, ErrRCRefused
	}

	/* Filter output by ans.Header.Type */
	last := 0
	for _, ans := range anss {
		/* Make sure answer comes back for the right name */
		if ans.Header.Name.String() != name {
			continue
		}

		/* Skip if the answer type and atype don't match */
		switch ans.Body.(type) {
		case *dnsmessage.AResource:
			if atype != dnsmessage.TypeA {
				continue
			}
		case *dnsmessage.NSResource:
			if atype != dnsmessage.TypeNS {
				continue
			}
		case *dnsmessage.CNAMEResource:
			if atype != dnsmessage.TypeCNAME {
				continue
			}
		case *dnsmessage.SOAResource:
			if atype != dnsmessage.TypeSOA {
				continue
			}
		case *dnsmessage.PTRResource:
			if atype != dnsmessage.TypePTR {
				continue
			}
		case *dnsmessage.MXResource:
			if atype != dnsmessage.TypeMX {
				continue
			}
		case *dnsmessage.TXTResource:
			if atype != dnsmessage.TypeTXT {
				continue
			}
		case *dnsmessage.AAAAResource:
			if atype != dnsmessage.TypeAAAA {
				continue
			}
		case *dnsmessage.SRVResource:
			if atype != dnsmessage.TypeSRV {
				continue
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

/* roundRobin tries each server in turn */
func (r *resolver) roundRobin(qm *dnsmessage.Message) (
	[]dnsmessage.Resource,
	dnsmessage.RCode,
	error,
) {
	/* If we were passed-in a conn and no address, use that */
	if 1 == len(r.conns) && nil == r.servers {
		/* Even if we get an error back, never remove the conn so that
		each query will return the error. */
		return r.conns[0].query(qm)
	}

	/* Try the next conn in the list */
	c, err := r.nextRRConn()
	if nil != err {
		return nil, 0xFFFF, err
	}
	return c.query(qm)
}

/* nextOnFail queries all of the resolvers in turn */
func (r *resolver) nextOnFail(qm *dnsmessage.Message) ([]dnsmessage.Resource, dnsmessage.RCode, error) {
	var (
		c   *conn
		rs  []dnsmessage.Resource
		rc  dnsmessage.RCode
		err error
	)
	/* Try each server in turn */
	for i := 0; 0 == len(rs) && len(r.servers) > i; i++ {
		c, err = r.getOrDialConn(i)
		if nil != err {
			/* TODO: Can we find something better to do here? */
			continue
		}
		rs, rc, err = c.query(qm)
	}
	return rs, rc, err
}

/* queryAll queries all of the resolvers simultaneously */
func (r *resolver) queryAll(qm *dnsmessage.Message) ([]dnsmessage.Resource, dnsmessage.RCode, error) {
	var (
		err  error
		n    int /* Number of servers queried */
		rsch = make(chan []dnsmessage.Resource)
		rcch = make(chan dnsmessage.RCode)
		ech  = make(chan error)
	)
	/* Fire off all the queries */
	for i := range r.servers {
		/* Grab a conn */
		var c *conn
		c, err = r.getOrDialConn(i)
		if nil != err {
			continue
		}
		/* New query, to prevent IDs being overwritten */
		q := *qm
		/* Do the query */
		go func() {
			ors, orc, oerr := c.query(&q)
			rsch <- ors
			rcch <- orc
			ech <- oerr
		}()
		n++
	}

	/* Gather query results */
	var (
		success bool /* True if we got a non-nxdomain */
		rs      []dnsmessage.Resource
		rc      dnsmessage.RCode
	)
	for i := 0; i < n; i++ {
		/* Get any resources we have */
		trs := <-rsch
		if nil != trs {
			rs = append(rs, trs...)
		}

		/* Get an rcode, we'll return the last one we get */
		rc = <-rcch
		/* Though, if any of them are SUCCESS, use that */
		if dnsmessage.RCodeSuccess == rc {
			success = true
		}

		/* We'll also use the last error we got. */
		err = <-ech
	}

	/* If we at all got answers, we have success */
	if 0 != len(rs) {
		err = nil
		rc = dnsmessage.RCodeSuccess
	}
	/* If we had a SUCCESS but no answers, that counts */
	if success {
		rc = dnsmessage.RCodeSuccess
	}

	return rs, rc, err
}
