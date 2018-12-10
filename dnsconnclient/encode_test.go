package dnsconnclient

/*
 * client_test.go
 * Test client functions
 * By J. Stuart McMurray
 * Created 20181208
 * Last Modified 20181209
 */

import "testing"

func TestBase32Encode(t *testing.T) {
	out := make([]byte, 1024)
	for _, c := range []struct {
		have string
		want string
	}{
		{"moose", "DLNMUSR5"},
		{"a", "C4"},
		{
			"In taberna quando sumus, " +
				"non curamus quid sit humus, " +
				"sed ad ludum properamus, " +
				"cui semper insudamus. " +
				"Quid agatur in taberna",
			"95N20T31C9IN4RJ141ONAOBECHNI0SRL" +
				"DLQN6B10DPNMS833ELP62RBLECG72TB." +
				"9CGG76QBK41K7ARBLECM20SR5CGG62P1" +
				"0DHQM8TBD41O74RRGCLP62RBLECM20O." +
				"RLD4G76PBDE1IN4839DPPNAP31DLQN6B" +
				"H0A5QMIP10C5JM2T3LE8G6IRH0EHGM4." +
				"PBIDPGG",
		},
		{
			"62ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJ",
			"6OP42GI38H2KCHQ89554MJ2D9P7L0KAI" +
				"ADA5ALINB1CLKGA28D24AHI7914KK",
		},
		{
			"63ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJK",
			"6OPK2GI38H2KCHQ89554MJ2D9P7L0KAI" +
				"ADA5ALINB1CLKGA28D24AHI7914KKIO",
		},
		{
			"64ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKL",
			"6OQ42GI38H2KCHQ89554MJ2D9P7L0KAI" +
				"ADA5ALINB1CLKGA28D24AHI7914KKIQ." +
				"C",
		},
		{
			"66ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLM",
			"6OR42GI38H2KCHQ89554MJ2D9P7L0KAI" +
				"ADA5ALINB1CLKGA28D24AHI7914KKIQ." +
				"C9K",
		},
		{
			"124ABCDEFGHIJKLMNOPQRSTUVWXYZABC" +
				"DEFGHIJKLMNOPQRSTUVWXYZABCDEFGHI" +
				"JKLMNOPQRSTUV",
			"64P38GA28D24AHI7914KKIQC9L74UK2H" +
				"A99L8LAMATC5IMI1891K8HA68T44III." +
				"B9H6KSJQGA5956L2LAPBLGMAQ85146H2" +
				"58P3KGIAA9D64QJIFA18L4KQKALB0",
		},
		{
			"125ABCDEFGHIJKLMNOPQRSTUVWXYZABC" +
				"DEFGHIJKLMNOPQRSTUVWXYZABCDEFGHI" +
				"JKLMNOPQRSTUVW",
			"64P3AGA28D24AHI7914KKIQC9L74UK2H" +
				"A99L8LAMATC5IMI1891K8HA68T44III." +
				"B9H6KSJQGA5956L2LAPBLGMAQ85146H2" +
				"58P3KGIAA9D64QJIFA18L4KQKALB5E",
		},
		{
			"127ABCDEFGHIJKLMNOPQRSTUVWXYZABC" +
				"DEFGHIJKLMNOPQRSTUVWXYZABCDEFGHI" +
				"JKLMNOPQRSTUVWX",
			"64P3EGA28D24AHI7914KKIQC9L74UK2H" +
				"A99L8LAMATC5IMI1891K8HA68T44III." +
				"B9H6KSJQGA5956L2LAPBLGMAQ85146H2" +
				"58P3KGIAA9D64QJIFA18L4KQKALB5EM." +
				"0",
		},
		{
			"128ABCDEFGHIJKLMNOPQRSTUVWXYZABC" +
				"DEFGHIJKLMNOPQRSTUVWXYZABCDEFGHI" +
				"JKLMNOPQRSTUVWXY",
			"64P3GGA28D24AHI7914KKIQC9L74UK2H" +
				"A99L8LAMATC5IMI1891K8HA68T44III." +
				"B9H6KSJQGA5956L2LAPBLGMAQ85146H2" +
				"58P3KGIAA9D64QJIFA18L4KQKALB5EM." +
				"2P",
		},
	} {
		n := Base32Encode(out, []byte(c.have))
		got := string(out[:n])
		if got != c.want {
			t.Fatalf(
				"Base32Encode failed: have:%v got:%v want:%v",
				c.have,
				got,
				c.want,
			)
		}
	}
}

/*
95N20T31C9IN4RJ141ONAOBECHNI0SRLDLQN6B10DPNMS833ELP62RBLECG72TB
*/
//func TestMarshalPayload(t *testing.T) {
//	out := make([]byte, 1024)
//	for i, c := range []struct {
//		cid     []byte
//		payload []byte
//		domain  string
//		want    string
//	}{
//		{
//			[]byte{0},
//			[]byte("This is a test"),
//			"kittens.com",
//			"01A6GQBJ41KN683141Q6ASRK.kittens.com",
//		},
//		{
//			[]byte{0xc4, 0xe6, 0x88, 0x89, 0x01},
//			[]byte("In taberna quando sumus, " +
//				"non curamus quid sit humus, " +
//				"sed ad ludum properamus, " +
//				"cui semper insudamus. " +
//				"Quid agatur in taberna"),
//			"a.b.c.co.uk",
//			"OJJ8H28195N20T31C9IN4RJ141ONAOBECHNI0SRLDLQN6B10DPNMS833ELP62RB.LECG72TB9CGG76QBK41K7ARBLECM20SR5CGG62P10DHQM8TBD41O74RRGCLP62R.BLECM20ORLD4G76PBDE1IN4839DPPNAP31DLQN6BH0A5QMIP10C5JM2T3LE8G6I.RH0EHGM4PBIDPGG.a.b.c.co.uk",
//		},
//	} {
//		/* Roll the query */
//		n, err := marshalPayload(out, c.cid, c.payload, c.domain)
//		if nil != err {
//			t.Fatalf("Error in test case %v: %v", i, err)
//		}
//		s := string(out[:n])
//
//		/* Make sure it matches */
//		if c.want != s {
//			t.Fatalf(
//				"marshalPayload failed: "+
//					"Case:%v Got:%v Want:%v",
//				i,
//				s,
//				c.want,
//			)
//		}
//
//	}
//}
