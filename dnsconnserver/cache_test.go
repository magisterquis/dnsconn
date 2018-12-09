package dnsconnserver

/*
 * cache_test.go
 * Test Cache
 * By J. Stuart McMurray
 * Created 20181129
 * Last Modified 20181129
 */

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

func TestCache(t *testing.T) {
	var (
		b  bytes.Buffer
		wg sync.WaitGroup
	)

	/* Create a cache.  The waitgroup will be decremented by the onEvict
	function */
	wg.Add(1)
	c, err := NewCache(2, func(k string, v interface{}) {
		defer wg.Done()
		i, ok := v.(int)
		if !ok {
			t.Fatalf("Invalid type %T passed to onEvict", v)
		}
		fmt.Fprintf(&b, "%v", i)
	})
	if nil != err {
		t.Fatalf("Failed to create cache: %v", err)
	}

	/* Add enough elements to fill the cache plus one (which will call
	wg.Done */
	if c.Put("one", 1) {
		t.Fatalf("Cache of size 2 evicted after 1 put")
	}

	if c.Put("two", 2) {
		t.Fatalf("Cache of size 2 evicted after 2 puts")
	}

	if !c.Put("three", 3) {
		t.Fatalf("Cache of size 2 did not evict after 3 puts")
	}

	/* Make sure an element was evicted */
	wg.Wait()
	v, ok := c.Get("one")
	if ok {
		t.Fatalf("First put not evicted, got %#v", v)
	}
	if "1" != b.String() {
		t.Fatalf(
			"After evict, onEvict stored %q (want: %q)",
			b.String(),
			"1",
		)
	}

	/* Make sure the other two elements are as expected */
	v, ok = c.Get("two")
	if !ok {
		t.Fatalf("Don't have two")
	}
	if i, ok := v.(int); !ok {
		t.Fatalf("Type for two's value %T (want: %T)", v, 2)
	} else if 2 != i {
		t.Fatalf("Two's value %v (want: 2)", i)
	}

	v, ok = c.Get("three")
	if !ok {
		t.Fatalf("Don't have three")
	}
	if i, ok := v.(int); !ok {
		t.Fatalf("Type for three's value %T (want: %T)", v, 3)
	} else if 3 != i {
		t.Fatalf("Three's value %v (want: 3)", i)
	}
}
