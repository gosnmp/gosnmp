// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package e2e

import (
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func TestClose(t *testing.T) {
	t.Run("idempotent", func(t *testing.T) {
		target, port := getTarget(t)
		gs := &gosnmp.GoSNMP{
			Target: target, Port: port,
			Version: gosnmp.Version2c, Community: "public",
			Timeout: 5 * time.Second, Retries: 1,
		}
		if err := gs.Connect(); err != nil {
			t.Fatalf("Connect: %v", err)
		}
		if err := gs.Close(); err != nil {
			t.Fatalf("first Close: %v", err)
		}
		if err := gs.Close(); err != nil {
			t.Errorf("second Close: %v", err)
		}
	})

	t.Run("nil connection", func(t *testing.T) {
		gs := &gosnmp.GoSNMP{Conn: nil}
		if err := gs.Close(); err != nil {
			t.Errorf("Close nil Conn: %v", err)
		}
	})

	t.Run("concurrent", func(t *testing.T) {
		target, port := getTarget(t)
		gs := &gosnmp.GoSNMP{
			Target: target, Port: port,
			Version: gosnmp.Version2c, Community: "public",
			Timeout: 5 * time.Second, Retries: 1,
		}
		if err := gs.Connect(); err != nil {
			t.Fatalf("Connect: %v", err)
		}
		var wg sync.WaitGroup
		for range 100 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = gs.Close()
			}()
		}
		wg.Wait()
	})
}

func TestReconnect(t *testing.T) {
	target, port := getTarget(t)
	gs := &gosnmp.GoSNMP{
		Target: target, Port: port,
		Version: gosnmp.Version2c, Community: "public",
		Timeout: 5 * time.Second, Retries: 1,
	}

	// First connection
	if err := gs.Connect(); err != nil {
		t.Fatalf("first Connect: %v", err)
	}
	getSysDescr(t, gs)
	gs.Conn.Close()

	// Reconnect
	if err := gs.Connect(); err != nil {
		t.Fatalf("second Connect: %v", err)
	}
	t.Cleanup(func() { gs.Conn.Close() })
	getSysDescr(t, gs)
}

func TestConcurrentGet(t *testing.T) {
	// Verify concurrent GETs on a shared connection don't panic or corrupt state.
	// Not all requests may succeed (UDP request/response matching under load),
	// but the connection should remain usable afterward.
	gs := connectV2c(t)
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			gs.Get([]string{sysDescr}) //nolint:errcheck
		}()
	}
	wg.Wait()

	// Connection should still work after concurrent access.
	getSysDescr(t, gs)
}

func TestTCPConnection(t *testing.T) {
	target, port := getTarget(t)
	gs := &gosnmp.GoSNMP{
		Target:    target,
		Port:      port,
		Transport: "tcp",
		Version:   gosnmp.Version2c,
		Community: "public",
		Timeout:   5 * time.Second,
		Retries:   1,
	}
	if err := gs.Connect(); err != nil {
		t.Skipf("TCP connect failed (snmpd may not have TCP enabled): %v", err)
	}
	t.Cleanup(func() { gs.Conn.Close() })
	getSysDescr(t, gs)
}
