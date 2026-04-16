// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestTrapSecurityParametersTable_ConcurrentSetGet exercises the race
// between a goroutine swapping the SNMPv3 security parameters table
// (as a production trap receiver does on config reload) and a goroutine
// reading it per incoming packet (as the trap decode path does).
//
// Before SetTrapSecurityParametersTable / GetTrapSecurityParametersTable
// were introduced, production code had to reassign GoSNMP.TrapSecurityParametersTable
// directly; running this test with -race against that version produced a
// DATA RACE on the field. With the atomic-backed accessors, the race
// detector must stay silent.
//
// Run with: go test -race -run TestTrapSecurityParametersTable_ConcurrentSetGet
func TestTrapSecurityParametersTable_ConcurrentSetGet(t *testing.T) {
	const (
		writers    = 4
		readers    = 16
		iterations = 10000
	)

	x := &GoSNMP{}

	// Seed with an initial table so readers never observe nil.
	x.SetTrapSecurityParametersTable(NewSnmpV3SecurityParametersTable(Logger{}))

	var (
		wg       sync.WaitGroup
		stopFlag atomic.Bool
	)

	// Writers: repeatedly install a fresh table, as a config-reload
	// goroutine would.
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations && !stopFlag.Load(); j++ {
				t := NewSnmpV3SecurityParametersTable(Logger{})
				x.SetTrapSecurityParametersTable(t)
			}
		}()
	}

	// Readers: repeatedly load, as the trap decode path would before
	// calling t.Get(user).
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations && !stopFlag.Load(); j++ {
				if got := x.GetTrapSecurityParametersTable(); got == nil {
					t.Errorf("GetTrapSecurityParametersTable returned nil after Set")
					stopFlag.Store(true)
					return
				}
			}
		}()
	}

	wg.Wait()
}

// TestTrapSecurityParametersTable_DeprecatedFieldFallback verifies that
// callers who still initialise the table via the deprecated struct field
// continue to work: if the atomic pointer was never set, Get must return
// the field value.
func TestTrapSecurityParametersTable_DeprecatedFieldFallback(t *testing.T) {
	tbl := NewSnmpV3SecurityParametersTable(Logger{})

	//nolint:staticcheck // deprecated field is exactly what we're testing
	x := &GoSNMP{TrapSecurityParametersTable: tbl}

	if got := x.GetTrapSecurityParametersTable(); got != tbl {
		t.Fatalf("GetTrapSecurityParametersTable returned %p, want %p (the deprecated field)", got, tbl)
	}

	// After Set, the atomic value wins.
	replacement := NewSnmpV3SecurityParametersTable(Logger{})
	x.SetTrapSecurityParametersTable(replacement)
	if got := x.GetTrapSecurityParametersTable(); got != replacement {
		t.Fatalf("after Set, Get returned %p, want %p", got, replacement)
	}
}
