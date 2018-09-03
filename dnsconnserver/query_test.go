package dnsconnserver

/*
 * query_test.go
 * Test functions for query.go
 * By J. Stuart McMurray
 * Created 20180901
 * Last Modified 20180902
 */

import (
	"bytes"
	"reflect"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestMakeAAAA(t *testing.T) {
	for have, want := range map[string][]byte{
		"4141:4242:4343:4444": []byte("AABBCCDD"),
	} {
		got := makeAAAA(have)
		if !bytes.Equal(got, want) {
			t.Errorf("Have: %v Got: %v Want: %v", have, got, want)
		}
	}
}

func TestQuestion_PutUint(t *testing.T) {
	stdQ := uint(0xabc123)
	stdA := dnsmessage.MustNewName("17.LF0I6.com")
	for _, tc := range []struct {
		/* Have */
		q  *question
		n  uint
		ok bool

		want dnsmessage.ResourceBody
	}{
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeA,
			}},
			n:  stdQ,
			ok: true,
			want: &dnsmessage.AResource{
				A: [4]byte{AOk, 0xab, 0xc1, 0x23},
			},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeA,
			}},
			n:  0x1,
			ok: true,
			want: &dnsmessage.AResource{
				A: [4]byte{AOk, 0x00, 0x00, 0x01},
			},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeA,
			}},
			n:  stdQ,
			ok: false,
			want: &dnsmessage.AResource{
				A: [4]byte{ABad, 0xab, 0xc1, 0x23},
			},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeAAAA,
			}},
			n:  0x1,
			ok: true,
			want: &dnsmessage.AAAAResource{AAAA: [16]byte{
				0x26, 0x07, 0xf8, 0xb0, 0x40, 0x04, 0x08, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			}},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeAAAA,
			}},
			n:  0xabcdef0123456789,
			ok: false,
			want: &dnsmessage.AAAAResource{AAAA: [16]byte{
				0x20, 0x01, 0x18, 0x90, 0x1c, 0x00, 0x31, 0x13,
				0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
			}},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeTXT,
			}},
			n:  stdQ,
			ok: true,
			want: &dnsmessage.TXTResource{TXT: []string{
				"11=q8Ej",
			}},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeTXT,
			}},
			n:  stdQ,
			ok: false,
			want: &dnsmessage.TXTResource{TXT: []string{
				"10=q8Ej",
			}},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeNS,
			}},
			n:    stdQ,
			ok:   true,
			want: &dnsmessage.NSResource{NS: stdA},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeNS,
			}},
			n:  stdQ,
			ok: false,
			want: &dnsmessage.NSResource{
				NS: dnsmessage.MustNewName("16.LF0I6.com"),
			},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeCNAME,
			}},
			n:  stdQ,
			ok: true,
			want: &dnsmessage.CNAMEResource{
				CNAME: stdA,
			},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeSOA,
			}},
			n:  stdQ,
			ok: true,
			want: &dnsmessage.SOAResource{
				NS:      stdA,
				MBox:    rname,
				Serial:  0,
				Refresh: soaRefresh,
				Retry:   soaRetry,
				Expire:  soaExpire,
				MinTTL:  soaMinTTL,
			},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypePTR,
			}},
			n:    stdQ,
			ok:   true,
			want: &dnsmessage.PTRResource{PTR: stdA},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeMX,
			}},
			n:    stdQ,
			ok:   true,
			want: &dnsmessage.MXResource{Pref: 0, MX: stdA},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeSRV,
			}},
			n:  stdQ,
			ok: true,
			want: &dnsmessage.SRVResource{
				Priority: 0,
				Weight:   0,
				Port:     0,
				Target:   stdA,
			},
		},
	} {
		tc.q.PutUint(tc.n, tc.ok)

		/* zero random values */
		switch r := tc.q.ans.Body.(type) {
		case *dnsmessage.SOAResource:
			r.Serial = 0
		case *dnsmessage.MXResource:
			r.Pref = 0
		case *dnsmessage.SRVResource:
			r.Priority = 0
			r.Weight = 0
			r.Port = 0
		}

		if !reflect.DeepEqual(tc.q.ans.Body, tc.want) {
			t.Errorf(
				"Have: %v/%#02x/%v Got: %#v Want: %#v",
				tc.q.q.Type, tc.n, tc.ok,
				tc.q.ans.Body,
				tc.want,
			)
		}
	}
}

func TestQuestion_PutBytes(t *testing.T) {
	for _, tc := range []struct {
		/* Have */
		q *question
		b []byte

		want dnsmessage.ResourceBody
	}{
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeA,
			}},
			b: []byte{0xab},
			want: &dnsmessage.AResource{
				A: [4]byte{AOk, 0x00, 0x00, 0xab},
			},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeA,
			}},
			b: []byte{0xab, 0xcd, 0x12},
			want: &dnsmessage.AResource{
				A: [4]byte{AOk, 0xab, 0xcd, 0x12},
			},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeAAAA,
			}},
			b: []byte{0x01},
			want: &dnsmessage.AAAAResource{AAAA: [16]byte{
				0x26, 0x07, 0xf8, 0xb0, 0x40, 0x04, 0x08, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			}},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeAAAA,
			}},
			b: []byte{
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
			},
			want: &dnsmessage.AAAAResource{AAAA: [16]byte{
				0x26, 0x07, 0xf8, 0xb0, 0x40, 0x04, 0x08, 0x00,
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
			}},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeTXT,
			}},
			b: []byte("A"),
			want: &dnsmessage.TXTResource{TXT: []string{
				"11=QQ",
			}},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeTXT,
			}},
			b: []byte("Beatus vir, qui non abiit in consilio " +
				"impiorum et in via peccatorum non stetit " +
				"et in conventu derisorum non sedit, sed in " +
				"lege Domini voluntas eius, et in lege eius " +
				"meditatur die ac nocte. "),
			want: &dnsmessage.TXTResource{TXT: []string{
				"11=QmVhdHVzIHZpciwgcXVpIG5vbiBhYmlpdCBpbiBj" +
					"b25zaWxpbyBpbXBpb3J1bSBldCBpbiB2aWE" +
					"gcGVjY2F0b3J1bSBub24gc3RldGl0IGV0IG" +
					"luIGNvbnZlbnR1IGRlcmlzb3J1bSBub24gc" +
					"2VkaXQsIHNlZCBpbiBsZWdlIERvbWluaSB2" +
					"b2x1bnRhcyBlaXVzLCBldCBpbiBsZWdlIGV" +
					"pdXMgbWVkaXRhdHVyIGRpZSBhYyBub2N0ZS" +
					"4g",
			}},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeNS,
			}},
			b: []byte("A"),
			want: &dnsmessage.NSResource{
				NS: dnsmessage.MustNewName("17.84.com"),
			},
		},
		{
			q: &question{q: dnsmessage.Question{
				Type: dnsmessage.TypeNS,
			}},
			b: []byte("Quare fremuerunt gentes, et populi " +
				"meditati sunt inania? Astiterunt reges " +
				"terrae, et principes convenerunt in unum " +
				"adversus Dominum et adversus christum"),
			want: &dnsmessage.NSResource{
				NS: dnsmessage.MustNewName("17.A5QM2SJ541J74" +
					"PBDELIN4TBEEGG6EPBEEHIN6B10CLQ20S3F" +
					"E1QMOQ90DLIM8QB.KC5Q6I83JELN78839DP" +
					"GMSQB17SG42SRKD5Q6ASJLDPQ20SJ5CTIN6" +
					"83KCLP74O.B55GG6AT10E1P6IRJ3D5O6ASP" +
					"0CDNMSTJ5DPIN4TBEEGG6IRH0ELN7AR90C5" +
					"I7C.PBIEDQN6824DTMMIRJLDKG6AT10C5I7" +
					"CPBIEDQN6833D1P6ISRKELMG.com"),
			},
		},
	} {
		tc.q.PutBytes(tc.b, true)
		if !reflect.DeepEqual(tc.q.ans.Body, tc.want) {
			t.Errorf(
				"Have: %v/%#02x Got: %#v Want: %#v",
				tc.q.q.Type, tc.b,
				tc.q.ans.Body,
				tc.want,
			)
		}
	}
}
