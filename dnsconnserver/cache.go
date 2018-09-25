package dnsconnserver

/*
 * cache.go
 * Simple LRU cache
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
	"container/list"
	"sync"
)

// Cache implements a simple least-recently-used cache usable from multiple
// goroutines.
type Cache struct {
	l *sync.Mutex
	m map[interface{}]interface{}
	q *list.List
	n uint
}

/* cacheValue holds a value in a Cache's map */
type cacheValue struct {
	e *list.Element
	v interface{}
}

// NewCache returns a new, initialized key/value LRU cache which holds n
// elements.  A cache which holds 0 elements is allowed, but calls to the
// returned Cache's Add method will never add any key/value pairs, and calls to
// its Get method will always return nil, false.
func NewCache(n uint) *Cache {
	return &Cache{
		l: new(sync.Mutex),
		m: make(map[interface{}]interface{}),
		q: list.New(),
		n: n,
	}
}

// Add adds or updates the key/value pair to c.  Adding or updating a value
// causes the key to be considered recently-used.
func (c *Cache) Add(key, value interface{}) {
	c.l.Lock()
	defer c.l.Unlock()

	/* Can't add if we haven't space */
	if 0 == c.n {
		return
	}

	/* If we already have the key, update it */
	if v, ok := c.m[key]; ok {
		cv := v.(*cacheValue)
		cv.v = value
		c.q.MoveToBack(cv.e)
		return
	}

	/* New key, make sure we have space in the list */
	for uint(c.q.Len()) >= c.n {
		k := c.q.Remove(c.q.Front())
		delete(c.m, k)
	}

	/* Add the key and value to the cache */
	c.m[key] = &cacheValue{
		e: c.q.PushBack(key),
		v: value,
	}
}

// Get gets the value for the key from c as well as whether the value existed
// in c.
func (c *Cache) Get(k interface{}) (interface{}, bool) {
	c.l.Lock()
	defer c.l.Unlock()

	/* No elements will be in the cache if we haven't space */
	if 0 == c.n {
		return nil, false
	}

	/* Try to get it from the cache */
	v, ok := c.m[k]

	/* If it's not there, tell the caller */
	if !ok {
		return nil, false
	}

	/* Return the actual value */
	cv := v.(*cacheValue)
	return cv.v, true
}
