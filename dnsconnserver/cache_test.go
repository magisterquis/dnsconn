package dnsconnserver

/*
 * cache_test.go
 * Test functions for cache.go
 * By J. Stuart McMurray
 * Created 20180902
 * Last Modified 20180902
 */

import (
	"fmt"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

type answerCacheElement struct {
	qn  dnsmessage.Question
	ans dnsmessage.ResourceBody
}

func TestAnswerCache(t *testing.T) {
	aces := make([]answerCacheElement, 4)
	for i := range aces {
		aces[i] = answerCacheElement{
			qn: dnsmessage.Question{
				Name: dnsmessage.MustNewName(
					fmt.Sprintf("E%v", i),
				),
			},
			ans: new(dnsmessage.AResource),
		}
	}

	ac := newAnswerCache(2)

	/* Make sure we can insert a single element */
	ac.Put(aces[0].qn, aces[0].ans)
	g := ac.Get(aces[0].qn)
	if g != aces[0].ans {
		t.Fatalf(
			"After first insert: %v got: %p want: %p",
			aces[0].qn,
			g,
			aces[0].ans,
		)
	}

	/* Make sure we can handle multiple elements */
	ac.Put(aces[1].qn, aces[1].ans)

	g = ac.Get(aces[0].qn)
	if g != aces[0].ans {
		t.Fatalf(
			"After second insert, element 0: "+
				"have: %v got: %p want: %p",
			aces[0].qn,
			g,
			aces[0].ans,
		)
	}

	g = ac.Get(aces[1].qn)
	if g != aces[1].ans {
		t.Fatalf(
			"After second insert, element 1: "+
				"have: %v got: %p want: %p",
			aces[1].qn,
			g,
			aces[1].ans,
		)
	}

	/* Make sure eviction works */
	q0, a0 := ac.Put(aces[2].qn, aces[2].ans)
	if q0 != aces[0].qn || a0 != aces[0].ans {
		t.Fatalf(
			"Eviction failed: got: %v/%p want: %v/%p",
			q0, a0,
			aces[0].qn, aces[0].ans,
		)
	}

	/* Make sure evicted and non-existent elements return nil */
	g = ac.Get(aces[0].qn)
	if nil != g {
		t.Fatalf(
			"Got an evicted element: have: %v got: %p want: %v",
			aces[0].qn,
			g,
			nil,
		)
	}
	g = ac.Get(aces[3].qn)
	if nil != g {
		t.Fatalf(
			"Got a non-existent element: "+
				"have: %v got: %p want: %v",
			aces[3].qn,
			g,
			nil,
		)
	}
}
