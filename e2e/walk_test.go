// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func TestWalk(t *testing.T) {
	gs := connectV2c(t)

	t.Run("system subtree", func(t *testing.T) {
		results, err := gs.WalkAll(systemOID)
		if err != nil {
			t.Fatalf("WalkAll: %v", err)
		}
		if len(results) == 0 {
			t.Fatal("WalkAll returned 0 results")
		}
		for _, pdu := range results {
			if !strings.HasPrefix(pdu.Name, systemOID) {
				t.Errorf("OID %s not in subtree %s", pdu.Name, systemOID)
			}
		}
		t.Logf("WalkAll returned %d PDUs", len(results))
	})

	t.Run("ordering", func(t *testing.T) {
		results, err := gs.WalkAll(systemOID)
		if err != nil {
			t.Fatalf("WalkAll: %v", err)
		}
		for i := 1; i < len(results); i++ {
			if !oidLess(results[i-1].Name, results[i].Name) {
				t.Errorf("OIDs not numerically ordered: %s >= %s", results[i-1].Name, results[i].Name)
				break
			}
		}
	})
}

func TestBulkWalk(t *testing.T) {
	gs := connectV2c(t)

	t.Run("system subtree", func(t *testing.T) {
		results, err := gs.BulkWalkAll(systemOID)
		if err != nil {
			t.Fatalf("BulkWalkAll: %v", err)
		}
		if len(results) == 0 {
			t.Fatal("BulkWalkAll returned 0 results")
		}
		for _, pdu := range results {
			if !strings.HasPrefix(pdu.Name, systemOID) {
				t.Errorf("OID %s not in subtree %s", pdu.Name, systemOID)
			}
		}
		t.Logf("BulkWalkAll returned %d PDUs", len(results))
	})

	t.Run("ordering", func(t *testing.T) {
		results, err := gs.BulkWalkAll(systemOID)
		if err != nil {
			t.Fatalf("BulkWalkAll: %v", err)
		}
		for i := 1; i < len(results); i++ {
			if !oidLess(results[i-1].Name, results[i].Name) {
				t.Errorf("OIDs not numerically ordered: %s >= %s", results[i-1].Name, results[i].Name)
				break
			}
		}
	})

	t.Run("subtree boundary", func(t *testing.T) {
		// BulkWalk a small subtree — agent may return OIDs past the subtree
		// in a single response. Verify BulkWalkAll correctly truncates at the boundary.
		results, err := gs.BulkWalkAll(sysDescr) // single leaf OID
		if err != nil {
			t.Fatalf("BulkWalkAll: %v", err)
		}
		for _, pdu := range results {
			if !strings.HasPrefix(pdu.Name, sysDescr) {
				t.Errorf("OID %s outside subtree %s", pdu.Name, sysDescr)
			}
		}
	})

	t.Run("v1 bulk walk fails", func(t *testing.T) {
		target, port := getTarget(t)
		gs1 := &gosnmp.GoSNMP{
			Target:    target,
			Port:      port,
			Version:   gosnmp.Version1,
			Community: "public",
			Timeout:   5 * time.Second,
			Retries:   1,
		}
		if err := gs1.Connect(); err != nil {
			t.Fatalf("Connect: %v", err)
		}
		t.Cleanup(func() { gs1.Conn.Close() })
		_, err := gs1.BulkWalkAll("")
		if err == nil {
			t.Fatal("expected error for BulkWalk on V1")
		}
	})
}
