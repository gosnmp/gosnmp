// Copyright 2012-2018 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// +build all helper

package gosnmp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// https://www.scadacore.com/tools/programming-calculators/online-hex-converter/ is useful

func TestOidToString(t *testing.T) {
	oid := []int{1, 2, 3, 4, 5}
	expected := ".1.2.3.4.5"
	result := oidToString(oid)

	if result != expected {
		t.Errorf("oidToString(%v) = %s, want %s", oid, result, expected)
	}
}

func TestWithAnotherOid(t *testing.T) {
	oid := []int{4, 3, 2, 1, 3}
	expected := ".4.3.2.1.3"
	result := oidToString(oid)

	if result != expected {
		t.Errorf("oidToString(%v) = %s, want %s", oid, result, expected)
	}
}

func BenchmarkOidToString(b *testing.B) {
	oid := []int{1, 2, 3, 4, 5}
	for i := 0; i < b.N; i++ {
		oidToString(oid)
	}
}

type testsMarshalUint32T struct {
	value     uint32
	goodBytes []byte
}

var testsMarshalUint32 = []testsMarshalUint32T{
	{0, []byte{0x00}},
	{2, []byte{0x02}},                          // 2
	{257, []byte{0x01, 0x01}},                  // FF + 2
	{65537, []byte{0x01, 0x00, 0x01}},          // FFFF + 2
	{16777217, []byte{0x01, 0x00, 0x00, 0x01}}, // FFFFFF + 2
	{18542501, []byte{0x01, 0x1a, 0xef, 0xa5}},
}

func TestMarshalUint32(t *testing.T) {
	for i, test := range testsMarshalUint32 {
		result, err := marshalUint32(test.value)
		if err != nil {
			t.Errorf("%d: expected %0x got err %v", i, test.goodBytes, err)
		}
		if !checkByteEquality2(test.goodBytes, result) {
			t.Errorf("%d: expected %0x got %0x", i, test.goodBytes, result)
		}
	}
}

var testsMarshalInt32 = []struct {
	value     int
	goodBytes []byte
}{
	{0, []byte{0x00}},
	{2, []byte{0x02}},                          // 2
	{257, []byte{0x01, 0x01}},                  // FF + 2
	{65537, []byte{0x01, 0x00, 0x01}},          // FFFF + 2
	{16777217, []byte{0x01, 0x00, 0x00, 0x01}}, // FFFFFF + 2
	{2147483647, []byte{0x7f, 0xff, 0xff, 0xff}},
	{-2147483648, []byte{0x80, 0x00, 0x00, 0x00}},
	{-16777217, []byte{0xfe, 0xff, 0xff, 0xff}},
	{-16777216, []byte{0xff, 0x00, 0x00, 0x00}},
	{-65537, []byte{0xff, 0xfe, 0xff, 0xff}},
	{-65536, []byte{0xff, 0xff, 0x00, 0x00}},
	{-257, []byte{0xff, 0xff, 0xfe, 0xff}},
	{-256, []byte{0xff, 0xff, 0xff, 0x00}},
	{-2, []byte{0xff, 0xff, 0xff, 0xfe}},
	{-1, []byte{0xff, 0xff, 0xff, 0xff}},
}

func TestMarshalInt32(t *testing.T) {
	for _, aTest := range testsMarshalInt32 {
		result, err := marshalInt32(aTest.value)
		assert.NoErrorf(t, err, "value %d", aTest.value)
		assert.EqualValues(t, aTest.goodBytes, result, "bad marshalInt32()")
	}
}

func TestParseUint64(t *testing.T) {
	tests := []struct {
		data []byte
		n    uint64
	}{
		{[]byte{}, 0},
		{[]byte{0x00}, 0},
		{[]byte{0x01}, 1},
		{[]byte{0x01, 0x01}, 257},
		{[]byte{0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1e, 0xb3, 0xbf}, 18446744073694786495},
	}
	for _, test := range tests {
		if ret, err := parseUint64(test.data); err != nil || ret != test.n {
			t.Errorf("parseUint64(%v) = %d, %v want %d, <nil>", test.data, ret, err, test.n)
		}
	}
}

func checkByteEquality2(a, b []byte) bool {

	if a == nil && b == nil {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
