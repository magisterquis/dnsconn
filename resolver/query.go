package resolver

/*
 * query.go
 * perform a query
 * By J. Stuart McMurray
 * Created 20180926
 * Last Modified 20181009
 */

import (
	"encoding/binary"
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

	/* Query either via the packetconn or server(s) */
	var (
		anss  []dnsmessage.Resource
		rcode dnsmessage.RCode
	)
	if nil != r.conn {
		anss, rcode, err = r.queryPC(qm)
	} else {
		anss, rcode, err = r.queryServers(qm)
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

/* queryPC makes a query via the "connected" packetconn */
func (r *resolver) queryPC(qm *dnsmessage.Message) (
	[]dnsmessage.Resource,
	dnsmessage.RCode,
	error,
) {

	/* Get the query ID as well as the channel from which to read it */
	id, ch, err := r.newAnsChannel()

	/* Add the ID and roll the message */
	qm.Header.ID = id
	qbuf := r.bufpool.Get().([]byte)
	defer r.bufpool.Put(qbuf)
	m, err := qm.AppendPack(qbuf[:0])
	if nil != err {
		return nil, 0, err
	}

	/* If we're not sending on a packetconn, add the size */
	if !r.isPC {
		sm := r.bufpool.Get().([]byte)
		defer r.bufpool.Put(sm)
		if len(sm)-2 < len(m) {
			return nil, 0, errors.New("message too large")
		}
		binary.BigEndian.PutUint16(sm, uint16(len(m)))
		copy(sm[2:], m)
		m = sm[:len(m)+2]

	}

	/* Send the message */
	r.connL.Lock()
	_, err = r.conn.Write(m)
	r.connL.Unlock()
	if nil != err {
		return nil, 0xFFFF, err
	}

	/* Wait for the reply */
	ans, ok := <-ch
	if !ok {
		/* Answer didn't arrive in time */
		return nil, 0xFFFF, ErrAnswerTimeout
	}

	return ans.Answers, ans.Header.RCode, nil
}

/* queryServers makes a query via the configured server(s) */
func (r *resolver) queryServers(qm *dnsmessage.Message) (
	[]dnsmessage.Resource,
	dnsmessage.RCode,
	error,
) {
	/* Work out how to query based on r.queryMethod */
	switch r.queryMethod {
	case RoundRobin:
	case NextOnFail:
	case QueryAll:
	default: /* Should never happen */
		panic("unknown query method " + strconv.Itoa(r.queryMethod))
	}

	/* TODO: Finish this */
	return nil, 0xFFFF, nil /* DEBUG */
}
