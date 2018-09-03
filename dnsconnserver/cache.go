package dnsconnserver

/*
 * cache.go
 * Reply cache
 * By J. Stuart McMurray
 * Created 20180902
 * Last Modified 20180902
 */

import (
	"container/list"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

/* answerCache is used to cache answers to DNS queries.  It has a fixed size,
O(1) lookups, and O(1) inserts.  When the cache is full, new entries cause the
oldest entries (not least recently used) entries to be discarded.  It is safe
to call answerCache's methods from multiple goroutines. */
type answerCache struct {
	q *list.List
	m map[dnsmessage.Question]dnsmessage.ResourceBody
	l *sync.Mutex
	n uint
}

/* newAnswerCache returns an answerCache of the given size. */
func newAnswerCache(size uint) answerCache {
	if 0 == size {
		panic("answer cache size must be at least 1")
	}
	return answerCache{
		q: list.New(),
		m: make(map[dnsmessage.Question]dnsmessage.ResourceBody),
		l: new(sync.Mutex),
		n: size,
	}
}

// Get gets the resource for a question.  It returns nil if the answer to the
// question is unknown.
func (a answerCache) Get(qn dnsmessage.Question) dnsmessage.ResourceBody {
	a.l.Lock()
	defer a.l.Unlock()
	return a.m[qn]
}

// Put caches the answer for a question.  It returns the evicted question and
// resource, if any.  Calling add with a previously-cached question updates
// the cached answer, but does not change the order in which cached data will
// be evicted.
func (a answerCache) Put(
	qn dnsmessage.Question,
	ans dnsmessage.ResourceBody,
) (dnsmessage.Question, dnsmessage.ResourceBody) {
	a.l.Lock()
	defer a.l.Unlock()

	var (
		retq dnsmessage.Question
		retr dnsmessage.ResourceBody
		ok   bool
	)

	/* If we already have it, update the value without changing anything
	else */
	var update bool
	if _, ok = a.m[qn]; ok {
		update = true
	}
	a.m[qn] = ans

	/* Not just a simple update, queue the question for eviction */
	if !update {
		a.q.PushBack(qn)

		/* If we've too many, remove one */
		if uint(a.q.Len()) > a.n {
			retq = a.q.Remove(a.q.Front()).(dnsmessage.Question)
			retr, ok = a.m[retq]
			if !ok {
				panic("missing cached resource")
			}
			delete(a.m, retq)
		}
	}

	return retq, retr
}
