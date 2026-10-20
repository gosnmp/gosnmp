// Copyright 2025 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build all || walk

package gosnmp

import "testing"

func TestOidCompare(t *testing.T) {
	tests := []struct {
		name     string
		oid1     string
		oid2     string
		expected int
	}{
		// oid1 == oid2 (returns 0)
		{"equal", ".1.3.6.1", ".1.3.6.1", 0},
		{"equal ignores leading dot", ".1.3.6.1", "1.3.6.1", 0},

		// oid1 < oid2 (returns -1)
		{"less by component value", ".1.3.6.1", ".1.3.6.2", -1},
		{"less by length", ".1.3.6.1", ".1.3.6.1.4", -1},
		{"less by numeric not string order", ".1.3.6.1.2", ".1.3.6.1.10", -1},
		{"less at uint32 max", ".1.3.4294967294", ".1.3.4294967295", -1},
		{"empty less than any oid", "", ".1.3.6.1", -1},

		// oid1 > oid2 (returns 1)
		{"greater by component value", ".1.3.6.2", ".1.3.6.1", 1},
		{"greater when response decreases", ".1.3.6.1.4.1.2636.3.60.1.2.1.1.6.578.227", ".1.3.6.1.4.1.2636.3.60.1.2.1.1.6.578.0", 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := oidCompare(tc.oid1, tc.oid2)
			if got != tc.expected {
				t.Errorf("oidCompare(%q, %q) = %d, want %d", tc.oid1, tc.oid2, got, tc.expected)
			}
		})
	}
}
