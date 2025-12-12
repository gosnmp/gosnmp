// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build all || helper

package gosnmp

import (
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

// https://www.scadacore.com/tools/programming-calculators/online-hex-converter/ is useful

func TestParseObjectIdentifier(t *testing.T) {
	oid := []byte{43, 6, 1, 2, 1, 31, 1, 1, 1, 10, 143, 255, 255, 255, 127}
	expected := ".1.3.6.1.2.1.31.1.1.1.10.4294967295"
	expectedComponents := []uint32{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10, 4294967295}

	buf, components, err := parseObjectIdentifier(oid)
	if err != nil {
		t.Errorf("parseObjectIdentifier(%v) want %s, error: %v", oid, expected, err)
	}
	result := string(buf)

	if string(result) != expected {
		t.Errorf("parseObjectIdentifier(%v) = %s, want %s", oid, result, expected)
	}
	if !reflect.DeepEqual(components, expectedComponents) {
		t.Errorf("parseObjectIdentifier(%v) components = %v, want %v", oid, components, expectedComponents)
	}
}

func TestParseObjectIdentifierWithOtherOid(t *testing.T) {
	oid := []byte{43, 6, 3, 30, 11, 1, 10}
	expected := ".1.3.6.3.30.11.1.10"
	expectedComponents := []uint32{1, 3, 6, 3, 30, 11, 1, 10}

	buf, components, err := parseObjectIdentifier(oid)
	if err != nil {
		t.Errorf("parseObjectIdentifier(%v) want %s, error: %v", oid, expected, err)
	}
	result := string(buf)
	if string(result) != expected {
		t.Errorf("parseObjectIdentifier(%v) = %s, want %s", oid, result, expected)
	}
	if !reflect.DeepEqual(components, expectedComponents) {
		t.Errorf("parseObjectIdentifier(%v) components = %v, want %v", oid, components, expectedComponents)
	}
}

func TestParseObjectIdentifierOverflow(t *testing.T) {
	// OID with sub-identifier 4294967296 (2^32), which exceeds uint32 max.
	// Base-128 encoding of 4294967296: 0x90 0x80 0x80 0x80 0x00
	oid := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x90, 0x80, 0x80, 0x80, 0x00}

	_, _, err := parseObjectIdentifier(oid)
	if err == nil {
		t.Error("parseObjectIdentifier should reject sub-identifiers > 2^32-1")
	}
}

func TestParseBase128Uint32(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		offset   int
		expected uint32
		newOff   int
		wantErr  bool
	}{
		{"zero", []byte{0x00}, 0, 0, 1, false},
		{"one", []byte{0x01}, 0, 1, 1, false},
		{"max single byte (127)", []byte{0x7f}, 0, 127, 1, false},
		{"min two byte (128)", []byte{0x81, 0x00}, 0, 128, 2, false},
		{"two byte (255)", []byte{0x81, 0x7f}, 0, 255, 2, false},
		{"two byte (256)", []byte{0x82, 0x00}, 0, 256, 2, false},
		{"three byte (16383)", []byte{0xff, 0x7f}, 0, 16383, 2, false},
		{"three byte (16384)", []byte{0x81, 0x80, 0x00}, 0, 16384, 3, false},
		{"max uint32", []byte{0x8f, 0xff, 0xff, 0xff, 0x7f}, 0, 4294967295, 5, false},
		{"overflow (2^32)", []byte{0x90, 0x80, 0x80, 0x80, 0x00}, 0, 0, 0, true},
		{"truncated (continuation set, no more bytes)", []byte{0x81}, 0, 0, 0, true},
		{"empty input", []byte{}, 0, 0, 0, true},
		{"offset into buffer", []byte{0x00, 0x81, 0x00}, 1, 128, 3, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, newOff, err := parseBase128Uint32(tc.input, tc.offset)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got value %d", got)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tc.expected {
				t.Errorf("value = %d, want %d", got, tc.expected)
			}
			if newOff != tc.newOff {
				t.Errorf("offset = %d, want %d", newOff, tc.newOff)
			}
		})
	}
}

func BenchmarkParseObjectIdentifier(b *testing.B) {
	oid := []byte{43, 6, 3, 30, 11, 1, 10}
	for i := 0; i < b.N; i++ {
		_, _, _ = parseObjectIdentifier(oid)
	}
}

func BenchmarkMarshalObjectIdentifier(b *testing.B) {
	oid := ".1.3.6.3.30.11.1.10"
	for i := 0; i < b.N; i++ {
		marshalObjectIdentifier(oid)
	}
}

type testsMarshalUint32T struct {
	value     uint32
	goodBytes []byte
}

var testsMarshalUint32 = []testsMarshalUint32T{
	{0, []byte{0x00}},
	{2, []byte{0x02}}, // 2
	{128, []byte{0x00, 0x80}},
	{257, []byte{0x01, 0x01}},                  // FF + 2
	{65537, []byte{0x01, 0x00, 0x01}},          // FFFF + 2
	{16777217, []byte{0x01, 0x00, 0x00, 0x01}}, // FFFFFF + 2
	{18542501, []byte{0x01, 0x1a, 0xef, 0xa5}},
	{2147483647, []byte{0x7f, 0xff, 0xff, 0xff}},
	{2147483648, []byte{0x00, 0x80, 0x00, 0x0, 0x0}},
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

func TestMarshalUint64(t *testing.T) {
	tests := []struct {
		value    interface{}
		expected []byte
	}{
		// RFC 2578 Section 7.1.15: Counter64 is an unsigned 64-bit integer.
		// X.690 Section 8.3.1: Integers shall be encoded in two's complement binary.
		// X.690 Section 8.3.2: Use the minimum number of octets.

		// Case 1: Zero should be encoded as a single byte: 0x00
		{uint64(0), []byte{0x00}},

		// Case 2: 127 (0x7F) has MSB clear, encoded as single byte
		{uint64(127), []byte{0x7F}},

		// Case 3: 128 (0x80) has MSB set, must prepend 0x00
		{uint64(128), []byte{0x00, 0x80}},

		// Case 4: 255 (0xFF) has MSB set, must prepend 0x00
		{uint64(255), []byte{0x00, 0xFF}},

		// Case 5: 256 (0x0100) MSB of first byte is 0, no need to prepend
		{uint64(256), []byte{0x01, 0x00}},

		// Case 6: 2^32 - 1 = 0xFFFFFFFF MSB set in first byte, must prepend 0x00
		{uint64(0xFFFFFFFF), []byte{0x00, 0xFF, 0xFF, 0xFF, 0xFF}},

		// Case 7: 2^63 = 0x8000000000000000 MSB set in trimmed output, must prepend 0x00
		{uint64(0x8000000000000000), []byte{
			0x00, // prepend
			0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}},

		// Case 8: Max uint64 = 0xFFFFFFFFFFFFFFFF, must prepend 0x00 to keep positive
		{uint64(0xFFFFFFFFFFFFFFFF), []byte{
			0x00, // prepend
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		}},
	}

	for _, test := range tests {
		actual, err := marshalUint64(test.value)
		if err != nil {
			t.Errorf("marshalUint64(%v) returned unexpected error: %v", test.value, err)
			continue
		}
		if !reflect.DeepEqual(actual, test.expected) {
			t.Errorf("marshalUint64(%v) = %x, expected %x", test.value, actual, test.expected)
		}
	}
}

var testsMarshalInt32 = []struct {
	value     int
	goodBytes []byte
}{
	{0, []byte{0x00}},
	{2, []byte{0x02}}, // 2
	{128, []byte{0x00, 0x80}},
	{257, []byte{0x01, 0x01}},                  // FF + 2
	{65537, []byte{0x01, 0x00, 0x01}},          // FFFF + 2
	{16777217, []byte{0x01, 0x00, 0x00, 0x01}}, // FFFFFF + 2
	{2147483647, []byte{0x7f, 0xff, 0xff, 0xff}},
	{-2147483648, []byte{0x80, 0x00, 0x00, 0x00}},
	{-16777217, []byte{0xfe, 0xff, 0xff, 0xff}},
	{-16777216, []byte{0xff, 0x00, 0x00, 0x00}},
	{-65537, []byte{0xfe, 0xff, 0xff}},
	{-65536, []byte{0xff, 0x00, 0x00}},
	{-257, []byte{0xfe, 0xff}},
	{-256, []byte{0xff, 0x00}},
	{-2, []byte{0xfe}},
	{-1, []byte{0xff}},
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

var testsInvalidSNMPResponses = []string{
	"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",
	"MBoCAQEEB3ByaXZhdGWiDAIESESkywIBBQIBAA==",
	"MEo=",
}

func TestInvalidSNMPResponses(t *testing.T) {

	g := &GoSNMP{
		Target:    "127.0.0.1",
		Port:      161,
		Community: "public",
		Version:   Version2c,
	}

	for i, test := range testsInvalidSNMPResponses {
		testBytes, _ := base64.StdEncoding.DecodeString(test)
		result, err := g.SnmpDecodePacket(testBytes)
		if err == nil {
			t.Errorf("#%d, failed to error %v", i, result)
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
