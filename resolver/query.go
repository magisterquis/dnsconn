package resolver

/*
 * query.go
 * perform a query
 * By J. Stuart McMurray
 * Created 20180926
 * Last Modified 20181011
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

/* TODO: Finish this */
func (c *resolver) roundRobin(qm *dnsmessage.Message) ([]dnsmessage.Resource, dnsmessage.RCode, error) {
	return nil, 0, nil
}

/* TODO: Finish this */
func (c *resolver) nextOnFail(qm *dnsmessage.Message) ([]dnsmessage.Resource, dnsmessage.RCode, error) {
	return nil, 0, nil
}

/* TODO: Finish this */
func (c *resolver) queryAll(qm *dnsmessage.Message) ([]dnsmessage.Resource, dnsmessage.RCode, error) {
	return nil, 0, nil
}
