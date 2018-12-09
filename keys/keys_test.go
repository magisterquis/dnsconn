package keys

/*
 * keys_test.go
 * Make sure keys works
 * By J. Stuart McMurray
 * Created 20181208
 * Last Modified 20181208
 */

import "testing"

// NRandPair is the number of random keypairs to create
const NRandPair = 100

func TestKeys(t *testing.T) {
	/* Keys to test */
	var cases []*[32]byte

	/* Generate quite a lot since we're dealing with random data */
	for i := 0; i < NRandPair; i++ {
		ku, kr, err := GenerateKeypair()
		if nil != err {
			t.Fatalf("Error generating keys: %v", err)
		}
		cases = append(cases, ku)
		cases = append(cases, kr)
	}

	/* Make sure encoding and decoding back works */
	for _, c := range cases {
		e := Encode(c)
		d, err := Decode(e)
		if nil != err {
			t.Fatalf("Unable to decode %v (%02x): %v", d, *c, err)
		}
		if *c != *d {
			t.Fatalf(
				"Encode/Decode failed, Key:%02x "+
					"Encoded:%v Decoded:%02x",
				*c,
				e,
				d,
			)
		}
	}
}
