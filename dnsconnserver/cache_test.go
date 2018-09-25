package dnsconnserver

/*
 * cache_test.go
 * Test the LRU cache
 * By J. Stuart McMurray
 * Created 20180924
 * Last Modified 20180924
 */

/* The below license is included in this file itself to facilitate inclusion of
this file in other projects. */

/*
 * Copyright (C) 2018 J. Stuart McMurray
 *
 * This software is provided 'as-is', without any express or implied
 * warranty.  In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 */

import (
	"testing"
)

func TestCache(t *testing.T) {
	four := "four"
	five := struct{ s string }{"five"}
	c := NewCache(3)

	/* Add a few elements */
	c.Add(1, 2)
	c.Add("three", &four)
	c.Add(five, []byte{6})

	/* Test retrieval */
	v, ok := c.Get(1)
	if !ok {
		t.Fatalf("Failed to get value for 1")
	}
	n, ok := v.(int)
	if !ok {
		t.Fatalf("Got incorrect type for value 2: %T", v)
	}
	if 2 != n {
		t.Fatalf("Got invalid value for value 2: %v", n)
	}
	v, ok = c.Get("three")
	if !ok {
		t.Fatalf("Failed to get value for \"three\"")
	}
	p, ok := v.(*string)
	if !ok {
		t.Fatalf("Got incorrect type for value &four: %T", v)
	}
	if four != *p {
		t.Fatalf("Got incorrect value for value &four: %v", *p)
	}
	v, ok = c.Get(five)
	if !ok {
		t.Fatalf("Failed to get value for five")
	}
	s, ok := v.([]byte)
	if !ok {
		t.Fatalf("Got incorrect type for []byte{6}: %T", v)
	}
	if 1 != len(s) {
		t.Fatalf("Got incorrect length for []byte{6}: %v", len(s))
	}
	if 6 != s[0] {
		t.Fatalf("Got incorrect value for []byte{6}[0]: %v", s[0])
	}

	/* Test eviction */
	c.Add(7, 8)
	if v, ok = c.Get(1); ok {
		t.Fatalf("Got value %v (%T) for evicted key 1", v, v)
	}
	v, ok = c.Get(7)
	if !ok {
		t.Fatalf("Failed to get value for 7")
	}
	n, ok = v.(int)
	if !ok {
		t.Fatalf("Got incorrect type for 8: %T", v)
	}
	if 8 != n {
		t.Fatalf("Got incorrect value for 8: %v", n)
	}
}
