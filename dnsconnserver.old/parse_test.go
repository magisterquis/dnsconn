package dnsconnserver

/*
 * parse_test.go
 * Tester for DefaultParser
 * By J. Stuart McMurray
 * Created 20180924
 * Last Modified 20180924
 */

import (
	"reflect"
	"testing"
)

func TestDefaultParser(t *testing.T) {
	for _, tc := range []struct {
		have   string
		wantok bool
		want   ParsedMessage
	}{
		{"a", false, ParsedMessage{}},
		{
			"a.b.04.c.com",
			true,
			ParsedMessage{10, 11, []byte{1}, "c.com"},
		},
	} {
		got, ok := DefaultParser(tc.have)
		if ok != tc.wantok {
			t.Fatalf(
				"Parse have:%q gotok:%v wantok:%v",
				tc.have,
				ok,
				tc.wantok,
			)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf(
				"Parse have:%q got:%v want:%v",
				tc.have,
				got,
				tc.want,
			)
		}
	}
}
