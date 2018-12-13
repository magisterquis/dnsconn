package dnsconnserver

/*
 * dnsconnserver.go
 * Server side of dnsconn
 * By J. Stuart McMurray
 * Created 20181202
 * Last Modified 20181212
 */

import (
	"container/list"
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/magisterquis/dnsconn/keys"
)

var (
	// ErrListenerClosed is returned when a Listener's Accept or
	// AcceptClient methods are called after a call to its Close method.
	ErrListenerClosed = errors.New("listener closed")
)

const (
	PACKETBUFLEN = 1024 /* Packet buffer length */ /* TODO: Lowercase? */

	// DEBUGENVVAR is the name of an environment variable which, if set,
	// causes debugging messages to be logged.
	DEBUGENVVAR = "DNSCONNSERVER_DEBUG"
)

const (
	cacheSize = 1024 * 1024 /* Number of cached answers to hold */
)

// Config is used to configure a Listener.
type Config struct {

	/* Pubkey and Privkey are the public and private keys to be used by the
	server.  If unset, a keypair will be generated and retrieved with
	Listener.Keypair.  */
	Pubkey  *[32]byte
	Privkey *[32]byte
}

/* defaultConfig is used by Listen if config is nil */
var defaultConfig = &Config{}

/* TODO: Document better */
// Listener listens for new connections.  It satisfies net.Listener.
type Listener struct {
	/* Domain to be served */
	domain string
	cache  *Cache

	/* Keys */
	pubkey  *[32]byte
	privkey *[32]byte

	/* Underlying net.PacketConn */
	pc   net.PacketConn
	pcWG *sync.WaitGroup /* Done when pc isn't used */
	pool *sync.Pool      /* Packet buffer pool */

	/* Accepted clients */
	clients  map[uint32]*Client
	clientsL *sync.Mutex

	/* Queue of not-yet-accepted clients */
	noMoreClients bool /* Accept no more Clients */
	newClients    *list.List
	newClientsL   *sync.Mutex
	newClientsC   *sync.Cond /* Wake up calls to AcceptClient */

	/* Keeps track of cids which can be used */
	freeCIDNext uint32     /* Next cid to return */
	freeCIDs    *list.List /* Available cids */
	freeCIDsL   *sync.Mutex

	/* Error which caused the listener to close, returned by calls to
	Accept* and Wait */
	err  error
	errL *sync.RWMutex

	/* Switch on debugging */
	debug func(f string, a ...interface{})
}

// Listen returns a new Listener which will accept Clients using the given
// domain and net.PacketConn, which will be shared with accepted Clients.
// The returned Listener's Wait function can be used to wait until all
// clients have disconnected.  If config is nil, sensible defaults will be
// used.
func Listen(domain string, pc net.PacketConn, config *Config) (*Listener, error) {
	/* Maybe use the default config */
	if nil == config {
		config = defaultConfig
	}

	/* Make the answer cache */
	cache, err := NewCache(cacheSize, nil)
	if nil != err {
		return nil, err
	}

	/* TODO: Take config */
	l := &Listener{
		domain:   strings.ToLower("." + strings.Trim(domain, ".") + "."),
		cache:    cache,
		pubkey:   config.Pubkey,
		privkey:  config.Privkey,
		clients:  make(map[uint32]*Client),
		clientsL: new(sync.Mutex),
		pc:       pc,
		pcWG:     new(sync.WaitGroup),
		pool: &sync.Pool{New: func() interface{} {
			return make([]byte, PACKETBUFLEN)
		}},
		newClients:  list.New(),
		newClientsL: new(sync.Mutex),
		errL:        new(sync.RWMutex),
		freeCIDs:    list.New(),
		freeCIDsL:   new(sync.Mutex),
	}
	l.newClientsC = sync.NewCond(l.newClientsL)
	l.pcWG.Add(1)

	/* Set debug using DEBUGENVVAR */
	if _, ok := os.LookupEnv(DEBUGENVVAR); ok {
		l.debug = log.Printf
	} else {
		l.debug = func(string, ...interface{}) {}
	}

	/* If we only have one key, someone goofed */
	if (nil == l.pubkey && nil != l.privkey) ||
		(nil != l.pubkey && nil == l.privkey) {
		return nil, errors.New("keypair cannot have one nil member")
	}

	/* Generate keys if we ought */
	if nil == l.pubkey {
		l.pubkey, l.privkey, err = keys.GenerateKeypair()
		if nil != err {
			return nil, err
		}
	}

	/* If we haven't keys, make them */
	if nil == l.pubkey || nil == l.privkey {
	}

	/* Start handling packets */
	go l.handle()

	return l, nil
}

// Accept returns the next client which has made a connection to the listener.
// It is a wrapper around AcceptClient()
func (l *Listener) Accept() (net.Conn, error) { return l.AcceptClient() }

// AcceptClient returns the next Client which has made a connection to the
// listener.
func (l *Listener) AcceptClient() (*Client, error) {
	l.newClientsL.Lock()
	defer l.newClientsL.Unlock()

	/* If we don't either have a client or we're not accepting more, wait
	until something like that happens */
	for 0 >= l.newClients.Len() && !l.noMoreClients {
		l.newClientsC.Wait()
	}

	/* If we're not accepting any more clients, tell the user */
	if l.noMoreClients {
		l.errL.RLock()
		defer l.errL.RUnlock()
		return nil, l.err
	}

	/* If there's a client in the queue, return it */
	if 0 < l.newClients.Len() {
		c := l.newClients.Front().Value.(*Client)
		l.newClients.Remove(l.newClients.Front())
		return c, nil
	}

	/* Unpossible */
	panic("still accepting clients, no clients, not waiting")
}

// Close is equivalent to calling l.CloseWithError with ErrListenerClosed.
func (l *Listener) Close() error {
	return l.CloseWithError(ErrListenerClosed)
}

// CloseWithError stops accepting new clients, but does not close l's
// underlying net.PacketConn.  It must be called when l is no longer needed to
// prevent memory and goroutine leaks.  CloseWithError will return err unless
// l was previously closed with another error, in which case that error will be
// returned.  The error will be returned by future calls to Accept,
// AcceptClient, Close, CloseWithError, and Wait.
func (l *Listener) CloseWithError(err error) error {
	l.newClientsL.Lock()
	defer l.newClientsL.Unlock()

	/* Idempotency */
	if l.noMoreClients {
		return l.err
	}
	l.noMoreClients = true

	/* Tell not-yet-accepted clients that a disconnect happened */
	for e := l.newClients.Front(); nil != e; e = e.Next() {
		// e.Value.(*Client).Disconnect() /* TODO: Finish this */
		l.newClients.Remove(e)
	}

	/* Tell accepted clients that a disconnect happened */
	l.closeClientsWithError(err) /* TODO: Should be in a goroutine? */

	/* Fire the cond to kill the listeners */
	l.newClientsC.Broadcast()

	/* One fewer user of the conn */
	l.pcWG.Done()

	/* Note the error for Wait */
	l.errL.Lock()
	defer l.errL.Unlock()
	l.err = err

	return l.err
}

// Addr returns l's underlying net.PacketConn's address.
func (l *Listener) Addr() net.Addr { return l.pc.LocalAddr() }

// Wait blocks until l.Close has been called and all clients have disconnected.
// If an error caused the listener to close, it is returned.
func (l *Listener) Wait() error {
	l.pcWG.Wait()
	l.errL.RLock()
	defer l.errL.RUnlock()
	return l.err
}

/* closeClientsWithError closes all of the clients with the given error */
func (l *Listener) closeClientsWithError(err error) {
	/* TODO: Finish this */
}

/* Keypair returns a copy of l's keys */
func (l *Listener) Keypair() (pubkey, privkey *[32]byte) {
	pubkey = new([32]byte)
	privkey = new([32]byte)
	copy((*pubkey)[:], (*l.pubkey)[:])
	copy((*privkey)[:], (*l.privkey)[:])

	return pubkey, privkey
}
