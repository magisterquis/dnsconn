package dnsconnclient

/*
 * client_test.go
 * Test client functions
 * By J. Stuart McMurray
 * Created 20181208
 * Last Modified 20181209
 */

import (
	"fmt"
	"testing"
)

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

func TestAddLabelDots(t *testing.T) {
	b := make([]byte, 1024)
	for _, c := range []struct {
		have string
		want string
	}{
		{"abc", "abc"},
		{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
				"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
				"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
				"cccccccccccccccccccccccccccccccc" +
				"ccccccccccccccccccccccccccccccc" +
				"ddddd",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa." +
				"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
				"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb." +
				"cccccccccccccccccccccccccccccccc" +
				"ccccccccccccccccccccccccccccccc." +
				"ddddd",
		},
		{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
				"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
				"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
				"cccccccccccccccccccccccccccccccc" +
				"ccccccccccccccccccccccccccccccc",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa." +
				"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
				"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb." +
				"cccccccccccccccccccccccccccccccc" +
				"ccccccccccccccccccccccccccccccc",
		},
		{"", ""},
	} {
		copy(b, []byte(c.have))
		n, err := AddLabelDots(b, uint(len(c.have)))
		if nil != err {
			t.Fatalf(
				"AddLabelDots error (have:%q): %v",
				c.have,
				err,
			)
			continue
		}
		if string(b[:n]) != c.want {
			t.Fatalf(
				"AddLabelDots failed: have:%q got:%q "+
					"n:%v want:%q",
				c.have,
				b[:n],
				n,
				c.want,
			)
		}
	}

	/* Make sure we get an error when the buffer's too small */
	if _, err := AddLabelDots(b, uint(len(b))); ErrBufferTooSmall != err {
		t.Fatalf("Incorrect buffer too small error: %v", err)
	}
}

func ExampleAddLabelDots() {
	/* DNS name to split into labels */
	l := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
		"bbb"

	/* Put in a buffer */
	b := make([]byte, 512)
	copy(b, l)

	/* Add dots */
	n, err := AddLabelDots(b, uint(len(l)))
	if nil != err {
		panic(err)
	}
	fmt.Printf("%s\n", b[:n])

	// Output:
	// aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbb
}
