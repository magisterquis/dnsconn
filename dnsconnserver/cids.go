package dnsconnserver

/*
 * cids.go
 * Allocate and reclaim sids
 * By J. Stuart McMurray
 * Created 20181208
 * Last Modified 20181219
 */

const (
	// cidMAX is the highest possible cid to use
	cidMAX = 0x00ffffff

	// cidCBMAX is the highest CID with results in one byte in requests
	cidCBMAX = 63
)

/* getCID gets an unused CID.  The returned bool will be false if there were
no more cids to get. */
func (l *Listener) getCID() (uint32, bool) {
	l.freeCIDsL.Lock()
	defer l.freeCIDsL.Unlock()
	var c uint32

	/* If we have a CID in the free set, return that */
	if 0 != len(l.freeCIDs) {
		/* Extract one from the set at random */
		for c = range l.freeCIDs {
			break
		}
		delete(l.freeCIDs, c)
		return c, true
	}

	/* If we're at the max CID, give up */
	if cidMAX == l.freeCIDLast {
		return 0, false
	}

	/* Give out the next CID */
	l.freeCIDLast++
	return l.freeCIDLast, true
}

/* putCID returns the cid to the pool of free cids. */
func (l *Listener) putCID(cid uint32) {
	l.freeCIDsL.Lock()
	defer l.freeCIDsL.Lock()

	/* Always cache one-byte cids */
	if cidCBMAX >= cid {
		l.freeCIDs[cid] = struct{}{}
		return
	}

	/* If it's a multibyte cid, only cache it for reuse if there's a higher
	cid in use */
	if cid < l.freeCIDLast {
		l.freeCIDs[cid] = struct{}{}
	}

	/* If we're putting back the highest cid, don't actually put it back.
	Instead, remove all of the highest contiguous cids in the cache and set
	l.freeCIDLast to be the highest one still in use, down to the
	single-byte cids. */
	l.freeCIDLast-- /* "Put" the argument */
	for {
		/* Don't touch the single-byte CIDs */
		if cidCBMAX >= l.freeCIDLast {
			break
		}
		/* If we don't have this one in the cache (i.e. it's in use)
		don't lose any more */
		if _, ok := l.freeCIDs[l.freeCIDLast]; !ok {
			break
		}

		/* Remove the cid from the cache and let it be used next
		time */
		delete(l.freeCIDs, l.freeCIDLast)
		l.freeCIDLast--
	}
}

/* precacheCIDs adds all of the single-byte cids to the cid cache.  This should
only be called once. */
func (l *Listener) precacheCIDs() {
	l.freeCIDsL.Lock()
	defer l.freeCIDsL.Unlock()

	for i := uint32(1); i <= cidCBMAX; i++ {
		l.freeCIDs[i] = struct{}{}
		l.freeCIDLast = i
	}
}

/* TODO: Revise our idea of one-byte cids knowing they're going to be shifted. */
