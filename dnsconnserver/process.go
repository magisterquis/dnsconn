package dnsconnserver

/*
 * process.go
 * Process received queries
 * By J. Stuart McMurray
 * Created 20180923
 * Last Modified 20180924
 */

import (
	"log"
	"net"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

/* buflen is the size of the message buffer.  10k should be larger than any DNS message. */
const buflen = 10240

// NewConnID is the Conn ID to use to request a new connection.
const NewConnID = 0

/* bufpool is a buffer pool for reading, unmarshalling, and marshalling
messages. */
var bufpool = sync.Pool{
	New: func() interface{} { return make([]byte, buflen) },
}

/* process receives incoming queries, unmarshals them, and either sends them to
the appropriate Conn, makes a a new Conn, or sends an appropriate
NXDOMAIN/SERVFAIL/REFUSED reply. */
func (s *Server) process() {
	/* If we're done with this, make sure the waitgroup is decremented */
	defer s.Close()

	var stop bool

	for !stop {
		/* Read buffer */
		buf := bufpool.Get().([]byte)
		/* Get a packet */
		n, a, err := s.packetConn.ReadFrom(buf)

		/* If we got any data, process it */
		if 0 != n {
			go func() {
				s.processPacket(buf[:n], a)
				bufpool.Put(buf)
			}()
		}

		/* Not s's error if we have one */
		if nil != err {
			s.lock.Lock()
			s.err = err
			s.lock.Unlock()
		}

		/* If s has an error, give up */
		s.lock.Lock()
		stop = nil != s.err
		s.lock.Unlock()
	}
}

/* processPacket unmarshals a packet and either sends a negative response,
sends a cached answer, makes a new connection, or hands the unmarshalled
query to the appropriate Conn.  When it returns, pkt can be reused.  If b does
not contain a valid DNS query, no response is returned. */
func (s *Server) processPacket(pkt []byte, a net.Addr) {
	/* Start processing packet and get header */
	var p dnsmessage.Parser
	h, err := p.Start(pkt)
	if nil != err { /* Bad header */
		log.Printf("Bad packet header in %02X", pkt) /* DEBUG */
		return
	}

	/* If this isn't a query, drop it */
	if h.Response {
		log.Printf("Not a query: %02X", pkt) /* DEBUG */
		return
	}

	/* Change the header into a response */
	h.Response = true
	h.Authoritative = true
	h.RecursionAvailable = false

	/* Try to find a name we can use */
	var (
		dq dnsmessage.Question
		pm ParsedMessage
		ok bool
	)
	for dq, err = p.Question(); nil != err; dq, err = p.Question() {
		/* Try to parse this question */
		pm, ok = s.parse(strings.Trim(dq.Name.String(), "."))
		if !ok {
			continue
		}

		/* Make sure the domain is something we handle */
		s.domainsL.Lock()
		_, ok = s.domains[pm.Domain]
		s.domainsL.Unlock()
		if !ok {
			continue
		}

		/* TODO: Make sure the class and type are ok */

		/* Found something useful */
		break
	}
	/* Don't bother with malformed packets */
	if nil != err {
		log.Printf("Error parsing questions from %02X: %v", pkt, err) /* DEBUG */
	}

	/* Roll into an answerable query */
	q := &query{
		header:    h,
		parsedMsg: pm,
		question:  dq,
	}

	ans := bufpool.Get().([]byte)
	defer bufpool.Put(ans)

	/* If we got a request for a new Conn, handle that */
	if NewConnID == pm.ID {
		s.NewConn(q)
		s.send(a, q.AppendAnswer(ans[:0]))
		return
	}

	/* Try to get the Conn with the ID */
	s.connsL.Lock()
	c, ok := s.conns[pm.ID]
	s.connsL.Unlock()

	/* If we got a Conn, have the conn handle the query. */
	if ok {
		c.handleQuery(q)
	} else { /* Or NXDomain if not */
		q.header.RCode = dnsmessage.RCodeNameError
	}

	/* Send the reply */
	s.send(a, q.AppendAnswer(ans[:0]))
	return
}

/* reply sends the reply in q to a as a DNS packet, via s's underlying
transport. */
func (s *Server) reply(a net.Addr, q query) error {
	/* TODO: Finish this */
	return nil
}
