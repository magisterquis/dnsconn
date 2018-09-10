package dnsconnserver

/*
 * serverparse.go
 * Parse messages, server-side
 * By J. Stuart McMurray
 * Created 20180823
 * Last Modified 20180909
 */

import (
	"encoding/base32"
	"errors"
	"strconv"
	"strings"
)

// ErrUnknownMessageType indicates a Message was returned from a MessageParser
// with an unknown MessageType.
var ErrUnknownMessageType = errors.New("unknown message type")

// MessageType is the type of message sent from the client.
type MessageType uint16

// The following can be set in Message.Type:
const (
	// MTNew indicates a request for a new connection
	MTNew MessageType = 1
	// MTData indicates a message with Conn data
	MTData MessageType = 2
	// MTDReq indicates a request for Conn data
	MTDReq MessageType = 3
	// MTGIndex gets the index of the next byte to be sent or the next byte
	// expected to be received.  The sent payload's last bit determines
	// whether or not the value returned is the index of the next byte to
	// be sent (0) or the index of the next byte expected to be received
	// (1).  A 0-byte payload is treated as a payload ending in a 0 bit.
	MTGIndex MessageType = 4
	// MTRIndex indicates that the next index should be 0
	MTRIndex MessageType = 5
	// MTEnd indicates the last message in a Conn
	MTEnd MessageType = 6
	// MTUnknown represents an unknown message type.  This can be used in
	// a message returned by a MessageParser which will have the same
	// effect as the MessageParser returning ErrUnknownMessageType.
	MTUnknown MessageType = 0
)

/* messageTypeNames holds the string form of the client message types */
var messageTypeNames = map[MessageType]string{
	MTNew:     "MTNnew",
	MTData:    "MTData",
	MTDReq:    "MTDReq",
	MTGIndex:  "MTGIndex",
	MTRIndex:  "MTRIndex",
	MTEnd:     "MTEnd",
	MTUnknown: "unknown", /* Unknown message type */
}

// String implements fmt.Stringer.String.
func (r MessageType) String() string {
	if n, ok := messageTypeNames[r]; ok {
		return n
	}
	return messageTypeNames[MTUnknown]
}

// Message contains a decoded message from a client.  Each question sent by a
// client in a query is decoded by the Listener's MessageParser into a Message.
type Message struct {
	Type    MessageType
	ID      string /* Client ID */
	Payload []byte /* Message payload, which may be nil */
	Index   uint   /* Index of first byte in Payload */
}

// MessageParser takes a string sent as a question in a DNS query and parses
// it into a Message.
type MessageParser func(string) (Message, error)

// DefaultParser is the default parser to use if Parser is unset in a Config
var DefaultParser MessageParser = ParseMessage

// MessageParseError is the error type returned by ParseMessage.  It indicates
// an error occurred in parsing a specific name in a query.
type MessageParseError struct {
	Name string /* The name which was was unable to be parsed */
	Err  error  /* The error encountered parsing Name */
}

// Error satisfies the error interface.  It is a wrapper for m.Err.Error().
func (m MessageParseError) Error() string {
	return m.Err.Error()
}

// ParseMessage is the default Parser used if nil is passed as the  parser to
// Listen.  It may be called by custom parsers which simply provide a layer on
// top of the default format, such as encryption or encoding.
//
// The default message format is
//  type.id.payload.index.anything
//
// The first four fields of the message format are as follows:
//
// Type is a number corresponding to one of the MessageType constants.
//
// ID is the stream ID as a number.
//
// Payload is unpadded base32-encoded bytes.
//
// Index is the highest byte index number of this payload.
//
// The rest of s is ignored, but should be unique per query to avoid caching
// by intermediate resolvers.  Several random characters or a counter should be
// sufficient.
//
// TODO: Document what the above values are used for.
func ParseMessage(s string) (Message, error) {
	var (
		m   Message
		err error
	)
	/* Format: type.id.payload.index.anything */

	/* Split the message into the right parts */
	parts := strings.SplitN(s, ".", 5)
	if 4 < len(parts) {
		return Message{}, errors.New("not enough lables")
	}

	/* Type */
	if 0 == len(parts[0]) {
		return Message{}, errors.New("empty type field")
	}
	t, err := strconv.ParseUint(parts[0], 0, 16)
	if nil != err {
		return Message{}, err
	}
	m.Type = MessageType(t)

	/* ID */
	m.ID = parts[0]

	/* Payload */
	m.Payload, err = base32.HexEncoding.WithPadding(
		base32.NoPadding,
	).DecodeString(parts[2])
	if nil != err {
		return Message{}, err
	}

	/* Index */
	i, err := strconv.ParseUint(parts[3], 0, 0)
	m.Index = uint(i)

	return m, err
}
