package resolver

/*
 * lookup.go
 * LookupX methods
 * By J. Stuart McMurray
 * Created 20180926
 * Last Modified 20181003
 */

import (
	"net"
	"strings"

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

// LookupCNAME looks up CNAME records
func (r *resolver) LookupCNAME(name string) ([]string, error) {
	/* Make the query */
	rs, err := r.query(name, dnsmessage.TypeCNAME, dnsmessage.TypeCNAME)
	if nil != err {
		return nil, err
	}

	/* Extract the important bits */
	as := make([]string, len(rs))
	for i, r := range rs {
		as[i] = r.Body.(*dnsmessage.CNAMEResource).CNAME.String()
	}

	return as, nil
}

// LookupPTR looks up PTR (IP-to-name) records
func (r *resolver) LookupPTR(addr net.IP) ([]string, error) {
	/* Make the query */
	rs, err := r.query(
		reverseaddr(addr),
		dnsmessage.TypePTR,
		dnsmessage.TypePTR,
	)
	if nil != err {
		return nil, err
	}

	/* Extract the important bits */
	as := make([]string, len(rs))
	for i, r := range rs {
		as[i] = r.Body.(*dnsmessage.PTRResource).PTR.String()
	}

	return as, nil
}

// LookupMX looks up MX records
func (r *resolver) LookupMX(name string) ([]MX, error) {
	/* Make the query */
	rs, err := r.query(name, dnsmessage.TypeMX, dnsmessage.TypeMX)
	if nil != err {
		return nil, err
	}

	/* Extract the important bits */
	as := make([]MX, len(rs))
	for i, r := range rs {
		b := r.Body.(*dnsmessage.MXResource)
		as[i] = MX{
			Preference: b.Pref,
			Name:       b.MX.String(),
		}
	}

	return as, nil
}

// LookupTXT looks up TXT records
func (r *resolver) LookupTXT(name string) ([]string, error) {
	/* Make the query */
	rs, err := r.query(name, dnsmessage.TypeTXT, dnsmessage.TypeTXT)
	if nil != err {
		return nil, err
	}

	/* Extract the important bits */
	as := make([]string, len(rs))
	for i, r := range rs {
		as[i] = strings.Join(r.Body.(*dnsmessage.TXTResource).TXT, "")
	}

	return as, nil
}

// LookupAAAA looks up AAAA (IPv6 address) records
func (r *resolver) LookupAAAA(name string) ([][16]byte, error) {
	/* Make the query */
	rs, err := r.query(name, dnsmessage.TypeAAAA, dnsmessage.TypeAAAA)
	if nil != err {
		return nil, err
	}

	/* Extract the important bits */
	as := make([][16]byte, len(rs))
	for i, r := range rs {
		as[i] = r.Body.(*dnsmessage.AAAAResource).AAAA
	}

	return as, nil
}

// LookupAAAAC does queries for AAAAA records and expects CNAMEs in reply
func (r *resolver) LookupAAAAC(name string) ([]string, error) {
	/* Make the query */
	rs, err := r.query(name, dnsmessage.TypeAAAA, dnsmessage.TypeCNAME)
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

// LookupSRV looks up SRV records
func (r *resolver) LookupSRV(name string) ([]SRV, error) {
	/* Make the query */
	rs, err := r.query(name, dnsmessage.TypeSRV, dnsmessage.TypeSRV)
	if nil != err {
		return nil, err
	}

	/* Extract the important bits */
	as := make([]SRV, len(rs))
	for i, r := range rs {
		b := r.Body.(*dnsmessage.SRVResource)
		as[i] = SRV{
			Priority: b.Priority,
			Weight:   b.Weight,
			Port:     b.Port,
			Target:   b.Target.String(),
		}
	}

	return as, nil
}
