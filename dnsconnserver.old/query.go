package dnsconnserver

/*
 * query.go
 * Definition of an answerable DNS query
 * By J. Stuart McMurray
 * Created 20180923
 * Last Modified 20180924
 */

import (
	"golang.org/x/net/dns/dnsmessage"
)

/* query represents a DNS query */
type query struct {
	header    dnsmessage.Header   /* Response header */
	parsedMsg ParsedMessage       /* Parsed Message from the question */
	question  dnsmessage.Question /* Question with the message */
}

// AnswerLen returns the number of bytes the answer will hold.
/* TODO: Finish this */

// ReadPayload reads a payload from r into q.
/* TODO: Finish this */

// SetPayload sets the payload for q.  The length of the payload must be at
// most q.AnswerLen() bytes.
/* TODO: Finish this */

// Error sets q's answer to the given error code.
/* TODO: Finsih this */

// AppendAnswer appends to b the answer to q, ready to be sent on the wire.  b
// is returned.
func (q *query) AppendAnswer(b []byte) []byte {
	/* TODO: Finish this */
	return nil
}

/* TODO: Finish this */
