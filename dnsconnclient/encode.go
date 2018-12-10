package dnsconnclient

/*
 * encode.go
 * Encode messages to queries
 * By J. Stuart McMurray
 * Created 20181209
 * Last Modified 20181209
 */

import "encoding/base32"

/* b32er handles base32-encoding things */
var b32er = base32.HexEncoding.WithPadding(base32.NoPadding)

// An EncodingFunc encodes payload such that it can be sent as a DNS request
// and places it in out (which will be at least long enough to handle a DNS
// name) and returns the number of bytes placed in out.  The encoded data may
// end with a dot, but this is not necessary.
type EncodingFunc func(out, payload []byte) int

// Base32Encode is the default EncodingFunc used by Dial.
func Base32Encode(o, p []byte) int {
	/* Encode */
	el := b32er.EncodedLen(len(p))
	ebuf := pool.Get().([]byte)
	defer pool.Put(ebuf)
	b32er.Encode(ebuf, p)
	ebuf = ebuf[:el]

	/* Add dots every so often */
	if 63 < len(ebuf) {
		dbuf := pool.Get().([]byte)
		defer pool.Put(dbuf)
		n := SplitIntoLabels(dbuf, ebuf)
		ebuf = dbuf[:n]
	}

	return copy(o, ebuf)
}

// SplitIntoLabels places in out the result of splitting q into dot-separated
// 63-byte chunks and returns the number of bytes placed in out.
func SplitIntoLabels(out, q []byte) int {
	/* Copy each chunk */
	var (
		next int
		buf  = q
	)
	for 0 < len(buf) {
		/* If we're at the last chunk, copy it and give up */
		if len(buf) < 63 {
			next += copy(out[next:], buf)
			break
		}
		/* Copy the next chunk */
		next += copy(out[next:], buf[:63])
		buf = buf[63:]
		/* Add the dot */
		out[next] = '.'
		next++
	}

	return next
}
