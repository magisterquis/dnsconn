package dnsconn

/*
 * dnsconn_test.go
 * Test ALL the dnsconns
 * By J. Stuart McMurray
 * Created 20181207
 * Last Modified 20181207
 */

import (
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/magisterquis/dnsconn/dnsconnclient"
	"github.com/magisterquis/dnsconn/dnsconnserver"
	"github.com/magisterquis/dnsconn/keys"
)

// TestDNSConn tests both the client and server.
func TestDNSConn(t *testing.T) {
	/* Test domain */
	domain := "kittens.com"

	/* Make a server */
	d, err := ioutil.TempDir("", "")
	if nil != err {
		t.Fatalf("Unable to create temporary directory: %v", err)
	}
	defer func() {
		if err := os.RemoveAll(d); nil != err {
			t.Fatalf(
				"Unable to remove temporary directory %v: %v",
				d,
				err,
			)
		}
	}()
	laddr := filepath.Join(d, "sock")
	l, err := net.ListenPacket("unixgram", laddr)
	if nil != err {
		t.Fatalf("Unable to listen on unix socket %v: %v", laddr, err)
	}
	defer l.Close()
	dcs, err := dnsconnserver.Listen(domain, l, &dnsconnserver.Config{
		Pubkey:  keys.MustDecode("XfDvh7y6eqIaX3tioUX2OKUmjpxezFH5QcRbfEOlxmg"),
		Privkey: keys.MustDecode("d6LiPh3OAUgit1xMerpMaZHEUbRdmfU3ZZQzprmw99I"),
	})
	if nil != err {
		log.Fatalf("Unable to start the server: %v", err)
	}
	ku, _ := dcs.Keypair()
	_ = ku /* DEBUG */

	/* Test client */
	lf, err := dnsconnclient.LookupWithAddress(
		"unixgram",
		laddr,
		10*time.Second,
	)
	if nil != err {
		t.Fatalf("Unable to create LookupFunc: %v", err)
	}
	c, err := dnsconnclient.Dial(domain, ku, &dnsconnclient.Config{
		Lookup: lf,
	})
	if nil != err {
		t.Fatalf("Dial: %v", err)
	}

	_ = c /* DEBUG */

	/* TODO: Test a client with a small qlen and another with a big qlen */
	/* TODO: Make some clients */
	/* TODO: Test both sides sending large amounts of data */
	/* TODO: Test bursty comms */
	/* TODO: Test one-way comms */
	/* TODO: Test simulated shell command and output */
	/* TODO: Test lots of connections */
	/* TODO: Test long handshake */
}
