package dnsconnserver

/*
 * cache.go
 * Cache answers
 * By J. Stuart McMurray
 * Created 20181129
 * Last Modified 20181208
 */

import (
	"container/list"
	"errors"
	"sync"
)

/* cacheEntry holds an entry in the cache as well as a pointer to the entry
in the list */
type cacheEntry struct {
	k string
	v interface{}
}

// Cache is a threadsafe LRU cache which makes inserts and removals in O(1)
// time.
type Cache struct {
	l       *sync.Mutex
	q       *list.List
	m       map[string]*list.Element
	n       int
	onEvict func(string, interface{})
}

// NewCache returns a new Cache which will hold n entries.  If onEvict is not
// nil, it will be called when an entry is evicted.
func NewCache(n int, onEvict func(key string, value interface{})) (*Cache, error) {
	if 0 >= n {
		return nil, errors.New("cache must hold at least one entry")
	}

	return &Cache{
		l:       new(sync.Mutex),
		q:       list.New(),
		m:       make(map[string]*list.Element),
		n:       n,
		onEvict: onEvict,
	}, nil
}

// Get returns the cached value for the key and whether the key existed in the
// Cache.
func (c *Cache) Get(key string) (interface{}, bool) {
	c.l.Lock()
	defer c.l.Unlock()
	return c.unlockedGet(key)

}

/* unlockedGet gets the value for the key.  It is not threadsafe. */
func (c *Cache) unlockedGet(key string) (interface{}, bool) {
	/* Grab the cache entry */
	e, ok := c.m[key]
	if !ok {
		return nil, false
	}

	/* Update the LRU list */
	if c.q.Back() != e {
		c.q.MoveToBack(e)
	}

	return e.Value.(cacheEntry).v, true
}

// Put puts the key/value pair in the cache, evicting the oldest entry if
// necessary.  It returns true if an entry was evicted.
func (c *Cache) Put(key string, value interface{}) bool {
	c.l.Lock()
	defer c.l.Unlock()
	return c.unlockedPut(key, value)
}

/* unlockedPut puts the value in for the key.  It is not threadsafe. */
func (c *Cache) unlockedPut(key string, value interface{}) bool {
	var evicted bool /* True if something was evicted */

	/* If the cache is full, remove the oldest entry */
	if c.n == c.q.Len() {
		f := c.q.Front().Value.(cacheEntry)
		k := f.k
		/* Call the onEvict function if there is one */
		if nil != c.onEvict {
			go c.onEvict(k, f.v)
		}
		/* Remove the entry from the map and queue */
		delete(c.m, k)
		c.q.Remove(c.q.Front())
		evicted = true
	}

	/* Add the entry to the cache */
	c.m[key] = c.q.PushBack(cacheEntry{key, value})

	return evicted
}

// GetOrPut gets the cached value for the key if it exists, or caches the value
// if not.  In either case, the returned value is the cached value for the key.
func (c *Cache) GetOrPut(key string, value interface{}) interface{} {
	c.l.Lock()
	defer c.l.Unlock()

	/* Try a get */
	v, ok := c.unlockedGet(key)
	if ok {
		return v
	}

	/* If we didn't have it, put the key in */
	c.unlockedPut(key, value)
	return value
}

/* TODO: Note this file is copy/pastable */
