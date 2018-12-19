package dnsconnclient

/*
 * client_test.go
 * Test functions for Client
 * By J. Stuart McMurray
 * Created 20181212
 * Last Modified 20181219
 */

import (
	"testing"

	"github.com/magisterquis/dnsconn/keys"
)

func TestClient_marshalPayload(t *testing.T) {
	/* Dummy keys */
	ku, _, err := keys.GenerateKeypair()
	if nil != err {
		t.Fatalf("Error generating keys: %v", err)
	}

	/* Dummy client */
	var c Client
	if err := c.init("kittens.com", ku, nil); nil != err {
		t.Fatalf("Unable to create Client: %v", err)
	}
	c.setCIDs([4]byte{0x01, 0x00, 0x00, 0xFF})

	/* Encode some payloads */
	for _, tc := range []struct {
		have string
		want string
		err  error
	}{
		{"a", "vs1m200000000000.kittens.com.", nil},
		{"abcdefghijkl", "", errPayloadTooBig},
		{"", "vs1g000000000000.kittens.com.", nil},
		{"moose", "vs1mqrrfedig0000.kittens.com.", nil},
		{"abcdefg", "vs1m2oj3chimcpo0.kittens.com.", nil},
		{"abcdefgh", "vs1m2oj3chimcpr8.kittens.com.", nil},
		{"abcdefghi", "", errPayloadTooBig},
	} {
		n, err := c.marshalPayload(c.rxBuf, []byte(tc.have))
		/* Make sure we got the right error */
		if err != tc.err {
			t.Fatalf(
				"Incorrect error: have:%v got:%v want:%v",
				tc.have,
				err,
				tc.err,
			)
		}
		if nil != tc.err {
			continue
		}
		got := string(c.rxBuf.ebuf[:n])
		if got != tc.want {
			t.Fatalf(
				"Client.marshalPayload failed: "+
					"have:%v got:%v want:%v",
				tc.have,
				got,
				tc.want,
			)
		}
	}
}
