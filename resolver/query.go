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
	"time"

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
	if nil != r.packetConn {
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

		/* Skip if the answer type and qtype don't match */
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
	dnsmessage.Rcode,
	error,
) {
	/* Find a unique ID and register an answer channel */
	/* TODO: Put in own function */
	var (
		qid   uint16
		inUse = true
		ach   = make(chan []byte)
	)
	r.ansChL.Lock()
	for inUse {
		qid, err = randUint16()
		if nil != err {
			r.ansChL.Unock()
			return nil, 0, err
		}
		_, inUse = r.ansCh[qid]
	}
	/* Register for a response */
	r.ansCh[qid] = ach
	/* Work out how long to sleep */
	var to time.Duration
	r.qtoL.RLock()
	to = r.qto
	r.qtoL.RUnlock()
	/* Close the channel after the timeout, if it's still there */
	r.ansChL.Unock()

	/* Add the ID and roll the message */
	qm.Header.ID = qid
	qbuf := r.bufpool.Get().([]byte)
	defer r.bufpool.Put(buf)
	m, err := qm.AppendPack(buf[:0])
	if nil != err {
		return nil, 0, err
	}

	/* Close the channel if the message takes too long to come back */
	go func() {
		time.Sleep(to)
		r.ansChL.Lock()
		if ch, ok := r.ansCh[qid]; ch == ach {
			close(ach)
		}
		r.ansChL.Unock()
	}()
	if n,err:=r.pc.Write
	/* TODO: Send the message */

	/* TODO: Wait for the reply */

	/* TODO: Unmarshal and return rcode and answers */

	return nil, nil /* DEBUG */
}

/* queryServers makes a query via the configured server(s) */
func (r *resolver) queryServers(qm *dnsmessage.Message) (
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
