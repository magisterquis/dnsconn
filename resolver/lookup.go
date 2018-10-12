package resolver

/*
 * lookup.go
 * LookupX methods
 * By J. Stuart McMurray
 * Created 20180926
 * Last Modified 20181003
 */

import (
	"golang.org/x/net/dns/dnsmessage"
)

// LookupA looks up A records
func (r *resolver) LookupA(name string) ([][4]byte, error) {
	/* Make the query */
	rs, err := r.query(name, dnsmessage.TypeA, dnsmessage.TypeA)
	if nil != err {
		return nil, err
	}

	/* Extract the important bits */
	as := make([][4]byte, len(rs))
	for i, r := range rs {
		as[i] = r.Body.(*dnsmessage.AResource).A
	}

	return as, nil
}

// LookupAC does queries for A records and expects CNAMEs in reply
func (r *resolver) LookupAC(name string) ([]string, error) {
	/* Make the query */
	rs, err := r.query(name, dnsmessage.TypeA, dnsmessage.TypeCNAME)
	if nil != err {
		return nil, err
	}

	/* Extract the important bits */
	cs := make([]string, len(rs))
	for i, r := range rs {
		cs[i] = r.Body.(*dnsmessage.CNAMEResource).CNAME.String()
	}

	return cs, nil
}

// LookupNS looks up NS records
func (r *resolver) LookupNS(name string) ([]string, error) {
	/* Make the query */
	rs, err := r.query(name, dnsmessage.TypeNS, dnsmessage.TypeNS)
	if nil != err {
		return nil, err
	}

	/* Extract the important bits */
	as := make([]string, len(rs))
	for i, r := range rs {
		as[i] = r.Body.(*dnsmessage.NSResource).NS.String()
	}

	return as, nil
}

/* TODO: Finish implementing these */
