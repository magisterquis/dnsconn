// Package keys contains functions to manipulate dnsconn keys.
package keys

/*
 * keys.go
 * Makes dealing with keys a bit nicer
 * By J. Stuart McMurray
 * Created 20181208
 * Last Modified 20181208
 */

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/nacl/box"
)

// Decode decodes the base64 representation of a key.  It is the inverse of
// Encode.
func Decode(k string) (*[32]byte, error) {
	var key [32]byte

	/* Un-b64 */
	b, err := base64.RawURLEncoding.DecodeString(k)
	if nil != err {
		return &key, err
	}

	/* Make sure it's the right length */
	if 32 != len(b) {
		return &key, errors.New("invalid length")
	}

	/* Put it in an array */
	copy(key[:], b)
	return &key, nil
}

// MustDecode is like Decode but panics on error.
func MustDecode(h string) *[32]byte {
	k, err := Decode(h)
	if nil != err {
		panic(err)
	}
	return k
}

// GeneratePair generates a keypair.  It is a wrapper around
// golang.org/x/crypto/nacl/box.GenerateKey.
func GenerateKeypair() (publicKey, privateKey *[32]byte, err error) {
	return box.GenerateKey(rand.Reader)
}

// Encode returns the base64 representation of a key.  It is the inverse of
// Decode.
func Encode(k *[32]byte) string {
	return base64.RawURLEncoding.EncodeToString((*k)[:])
}
