package dnsconnserver

/*
 * listen_test.go
 * Test functions for listen.go
 * By J. Stuart McMurray
 * Created 20180826
 * Last Modified 20180826
 */

import (
	"fmt"
	"net"
	"testing"
)

func ExampleListener_ServedName() {
	/* Simple listener */
	pc, err := net.ListenPacket("udp", ":")
	if nil != err {
		panic(err)
	}
	defer pc.Close()
	l, err := Listen(pc, &Config{
		Domains: []string{"example.com"},
	})
	defer l.Close()
	if nil != err {
		panic(err)
	}

	/* Get the parent and child for a served subdomain */
	parent, child, ok := l.ServedName("foo.bar.example.com")
	fmt.Printf("Parent: %v\n", parent)
	fmt.Printf("Child: %v\n", child)
	fmt.Printf("Ok: %v\n", ok)

	// Output:
	// Parent: foo.bar
	// Child: example.com
	// Ok: true
}

func TestListener_ServesName(t *testing.T) {
	/* Simple listener */
	pc, err := net.ListenPacket("udp", ":")
	if nil != err {
		panic(err)
	}
	defer pc.Close()
	l, err := Listen(pc, &Config{
		Domains: []string{"example.com"},
	})
	defer l.Close()
	if nil != err {
		panic(err)
	}

	for _, tc := range []struct {
		domain string
		have   string
		wantc  string
		wantp  string
		wantok bool
	}{
		{"foo.com", "t.bar.foo.com", "t.bar", "foo.com", true},
		{"foo.com", "a.beer.com", "", "", false},
		{".", "a.b.c", "a.b.c", ".", true},
	} {
		l.AddDomain(tc.domain)
		c, p, ok := l.ServedName(tc.have)
		l.RemoveDomain(tc.domain)
		if tc.wantc != c || tc.wantp != p || tc.wantok != ok {
			t.Errorf(
				"Have: %v/%v Got: %v/%v/%v Want: %v/%v/%v",
				tc.have, tc.domain,
				c, p, ok,
				tc.wantc, tc.wantp, tc.wantok,
			)
		}

	}
}
