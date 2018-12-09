package dnsconnclient

/*
 * client_test.go
 * Test client functions
 * By J. Stuart McMurray
 * Created 20181208
 * Last Modified 20181208
 */

import "testing"

func TestMarshalPayload(t *testing.T) {
	out := make([]byte, 1024)
	for i, c := range []struct {
		cid     []byte
		payload []byte
		domain  string
		want    string
	}{
		{
			[]byte{0},
			[]byte("This is a test"),
			"kittens.com",
			"01A6GQBJ41KN683141Q6ASRK.kittens.com",
		},
		{
			[]byte{0xc4, 0xe6, 0x88, 0x89, 0x01},
			[]byte("In taberna quando sumus, " +
				"non curamus quid sit humus, " +
				"sed ad ludum properamus, " +
				"cui semper insudamus. " +
				"Quid agatur in taberna"),
			"a.b.c.co.uk",
			"OJJ8H28195N20T31C9IN4RJ141ONAOBECHNI0SRLDLQN6B10DPNMS833ELP62RB.LECG72TB9CGG76QBK41K7ARBLECM20SR5CGG62P10DHQM8TBD41O74RRGCLP62R.BLECM20ORLD4G76PBDE1IN4839DPPNAP31DLQN6BH0A5QMIP10C5JM2T3LE8G6I.RH0EHGM4PBIDPGG.a.b.c.co.uk",
		},
	} {
		/* Roll the query */
		n, err := marshalPayload(out, c.cid, c.payload, c.domain)
		if nil != err {
			t.Fatalf("Error in test case %v: %v", i, err)
		}
		s := string(out[:n])

		/* Make sure it matches */
		if c.want != s {
			t.Fatalf(
				"marshalPayload failed: "+
					"Case:%v Got:%v Want:%v",
				i,
				s,
				c.want,
			)
		}

	}
}
