// Copyright 2013 Sonia Hamilton. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package gosnmp

import (
	"fmt"
	"reflect"
	"testing"
)

var _ = fmt.Sprintf("dummy") // dummy

// Tests in alphabetical order of function being tested

// -----------------------------------------------------------------------------

var testsMarshalLength = []struct {
	length   int
	expected []byte
}{
	{1, []byte{0x01}},
	{129, []byte{0x81, 0x81}},
}

func TestMarshalLength(t *testing.T) {
	for i, test := range testsMarshalLength {
		testBytes, err := marshalLength(test.length)
		if err != nil {
			t.Errorf("%d: length %d got err %v", i, test.length, err)
		}
		if !reflect.DeepEqual(testBytes, test.expected) {
			t.Errorf("%d: length %d got |%x| expected |%x|",
				i, test.length, testBytes, test.expected)
		}
	}
}

// -----------------------------------------------------------------------------

var testsPartition = []struct {
	currentPosition int
	partitionSize   int
	sliceLength      int
	ok               bool
}{
	{-1, 3, 8, false}, // test out of range
	{8, 3, 8, false},  // test out of range
	{0, 3, 8, false},  // test 0-7/3 per doco
	{1, 3, 8, false},
	{2, 3, 8, true},
	{3, 3, 8, false},
	{4, 3, 8, false},
	{5, 3, 8, true},
	{6, 3, 8, false},
	{7, 3, 8, true},
	{-1, 1, 3, false}, // partition size of one
	{0, 1, 3, true},
	{1, 1, 3, true},
	{2, 1, 3, true},
	{3, 1, 3, false},
}

func TestPartition(t *testing.T) {
	for i, test := range testsPartition {
		ok := Partition(test.currentPosition, test.partitionSize, test.sliceLength)
		if ok != test.ok {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, ok, test.ok)
		}
	}
}

// ---------------------------------------------------------------------

var testsSnmpVersionString = []struct {
	in  SnmpVersion
	out string
}{
	{Version1, "1"},
	{Version2c, "2c"},
}

func TestSnmpVersionString(t *testing.T) {
	for i, test := range testsSnmpVersionString {
		result := test.in.String()
		if result != test.out {
			t.Errorf("#%d, got %v expected %v", i, result, test.out)
		}
	}
}

// ---------------------------------------------------------------------
