// Copyright 2012-2014 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"testing"
)

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
