package resolver

/*
 * lookup.go
 * LookupX methods
 * By J. Stuart McMurray
 * Created 20180926
 * Last Modified 20181003
 */

import (
	"log"

	"golang.org/x/net/dns/dnsmessage"
)

/* lookupA looks up A records */
func (r *resolver) LookupA(name string) ([][4]byte, error) {
	/* Make the query */
	rs, err := r.query(name, dnsmessage.TypeA, dnsmessage.TypeA)
	if nil != err {
		return nil, err
	}

	/* Extract the important bits */
	as := make([][4]byte, len(rs))
	for i, r := range rs {
		a, ok := r.Body.(*dnsmessage.AResource)
		if !ok { /* Should never happen */
			log.Panicf("invalid A record type %T", r)
		}
		as[i] = a.A
	}

	return as, nil
}
