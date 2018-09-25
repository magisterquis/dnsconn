package dnsconnserver

import (
	"encoding/base32"
	"log"
	"strconv"
	"strings"
)

/* unb32 is a function which decodes base32hex'd data */
var unb32h = base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString

// ParsedMessage holds the results of parsing a message.  It is returned by a
// Parser.
type ParsedMessage struct {
	ID      uint   /* Connection ID */
	Index   uint   /* Message Index */
	Payload []byte /* Message Payload */
	Domain  string /* Parent domain */
}

// Parser is responsible for parsing received names in DNS questions into a
// usable form.  It extracts the Connection ID, Message Index, and Message
// Payload and returns them in a ParsedMessage struct along with the domain the
// DNS question used.  Aside from the ParsedMessage, it returns a boolean
// indicating whether the message was parsed successfully or not.
type Parser func(string) (ParsedMessage, bool)

// DefaultParser parses DNS questions of the form
//  id.index.payload.domain
// expecting the ID and Index to be base36-encoded integers and the payload to
// be unpadded base32hex encoded.  Anything after the third (payload) label is
// placed in the Domain field of the returned ParseMessage.
func DefaultParser(q string) (ParsedMessage, bool) {
	var (
		pm  ParsedMessage
		err error
		n   uint64
	)

	/* Split off the first three labels */
	parts := strings.SplitN(q, ".", 4)
	if 4 != len(parts) {
		return pm, false
	}

	/* Parse the numbers */
	if n, err = strconv.ParseUint(parts[0], 36, 0); nil != err {
		return pm, false
	}
	pm.ID = uint(n)
	if n, err = strconv.ParseUint(parts[1], 36, 0); nil != err {
		return pm, false
	}
	pm.Index = uint(n)

	/* Un-base32hex the palyoad */
	if pm.Payload, err = unb32h(parts[2]); nil != err {
		log.Printf("Err %q: %v", parts[2], err) /* DEBUG */
		return pm, false
	}

	/* The rest is the domain */
	pm.Domain = parts[3]

	return pm, true
}
