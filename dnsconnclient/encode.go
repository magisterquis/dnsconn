package dnsconnclient

/*
 * encode.go
 * Encode messages to queries
 * By J. Stuart McMurray
 * Created 20181209
 * Last Modified 20181219
 */

import (
	"encoding/base32"
	"errors"
	"sync"
)

var (
	/* b32er handles base32-encoding things */
	b32er = base32.HexEncoding.WithPadding(base32.NoPadding)

	/* pool holds the buffer pool for the package */
	pool = sync.Pool{New: func() interface{} {
		return make([]byte, buflen)
	}}
)

var (

	// ErrBufferTooSmall is returned by AddLabelDots if the buffer doesn't
	// have enough room for the dots which would be added.
	ErrBufferTooSmall = errors.New("insufficient buffer space")
)

// An EncodingFunc encodes payload such that it can be sent as a DNS request
// and places it in out (which will be at least long enough to handle a DNS
// name) and returns the number of bytes placed in out.  The encoded data may
// end with a dot, but this is not necessary.
type EncodingFunc func(out, payload []byte) int

// Base32Encode is the default EncodingFunc used by Dial.
func Base32Encode(o, p []byte) int {
	/* Encode */
	el := b32er.EncodedLen(len(p))
	b32er.Encode(o, p)

	/* Add dots */
	n, err := AddLabelDots(o, uint(el))
	if nil != err {
		/* There will never be a too-small buffer passed in */
		panic(err)
	}

	return int(n)
}

// AddLabelDots adds dots to the first n bytes of q every 63 bytes, to allow
// string(q) to be used as part of a DNS query and returns the number of bytes
// used in the buffer.  q must contain enough space for the additional dots,
// which works out to be one dot per 63 bytes.  ErrBufferToSmall is returned if
// q is too small.  If n <= 63, q is unchanged and n is returned.
func AddLabelDots(q []byte, n uint) (uint, error) {
	/* Make sure we have enough space */
	if n+(n/63) > uint(len(q)) {
		return 0, ErrBufferTooSmall
	}

	/* If there's less than a full label, nothing to do */
	if 63 >= n {
		return n, nil
	}

	/* Work out the new length */
	newLen := n + (n / 63)
	if 0 == n%63 {
		/* We won't have a trailing dot */
		newLen--
	}

	/* Move each label, starting with the right */
	var start, end uint
	for chunk := (n / 63); chunk > 0; chunk -= 1 {
		/* Work out the start of each label to move */
		start = chunk * 63
		/* Work out the end of each label to move */
		end = start + 63
		if end > n {
			end = n
		}
		/* Move it, add a dot if it's not the last label */
		copy(q[start+chunk:end+chunk], q[start:end])
		q[start+chunk-1] = '.'
	}

	return newLen, nil
}
