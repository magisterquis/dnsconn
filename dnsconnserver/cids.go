package dnsconnserver

/*
 * cids.go
 * Allocate and reclaim sids
 * By J. Stuart McMurray
 * Created 20181208
 * Last Modified 20181208
 */

// cidMAX is the highest possible cid to use
const cidMAX = 0x00ffffff

/* getCID gets an unused CID.  The returned bool will be false if there were
no more cids to get. */
func (l *Listener) getCID() (uint32, bool) {
	l.freeCIDsL.Lock()
	defer l.freeCIDsL.Unlock()

	/* If there's none in the list, return a new one */
	if 0 == l.freeCIDs.Len() {
		/* Make sure we can return one */
		if cidMAX == l.freeCIDNext {
			return 0, false
		}
		l.freeCIDNext++
		return l.freeCIDNext, true
	}

	/* Pop a cid off the list and return it */
	return l.freeCIDs.Remove(l.freeCIDs.Front()).(uint32), true
}

/* putCID returns the cid to the pool of free cids. */
func (l *Listener) putCID(cid uint32) {
	l.freeCIDsL.Lock()
	defer l.freeCIDsL.Lock()

	l.freeCIDs.PushBack(cid)
}
