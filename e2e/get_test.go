// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package e2e

import (
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func TestGet(t *testing.T) {
	gs := connectV2c(t)

	t.Run("single OID", func(t *testing.T) {
		desc := getSysDescr(t, gs)
		t.Logf("sysDescr = %q", desc)
	})

	t.Run("multiple OIDs", func(t *testing.T) {
		result, err := gs.Get([]string{sysDescr, sysName})
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if len(result.Variables) != 2 {
			t.Fatalf("got %d variables, want 2", len(result.Variables))
		}
		for _, v := range result.Variables {
			if v.Type != gosnmp.OctetString {
				t.Errorf("variable %s type = %v, want OctetString", v.Name, v.Type)
			}
		}
	})

	t.Run("non-existent OID", func(t *testing.T) {
		result, err := gs.Get([]string{".1.3.6.1.2.1.999999.0"})
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if len(result.Variables) != 1 {
			t.Fatalf("got %d variables, want 1", len(result.Variables))
		}
		v := result.Variables[0]
		if v.Type != gosnmp.NoSuchObject && v.Type != gosnmp.NoSuchInstance {
			t.Errorf("type = %v, want NoSuchObject or NoSuchInstance", v.Type)
		}
	})

	t.Run("max OIDs exceeded", func(t *testing.T) {
		gs2 := connectV2c(t)
		gs2.MaxOids = 1
		_, err := gs2.Get([]string{sysDescr, sysName})
		if err == nil {
			t.Fatal("expected error for exceeding MaxOids")
		}
	})
}

func TestGetIPv4(t *testing.T) {
	target, port := getTarget(t)
	gs := &gosnmp.GoSNMP{
		Target:    target,
		Port:      port,
		Version:   gosnmp.Version2c,
		Community: "public",
		Timeout:   5 * time.Second,
		Retries:   1,
	}
	if err := gs.ConnectIPv4(); err != nil {
		t.Fatalf("ConnectIPv4: %v", err)
	}
	t.Cleanup(func() { gs.Conn.Close() })
	getSysDescr(t, gs)
}

func TestGetNext(t *testing.T) {
	gs := connectV2c(t)
	result, err := gs.GetNext([]string{sysDescr})
	if err != nil {
		t.Fatalf("GetNext: %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("got %d variables, want 1", len(result.Variables))
	}
	if result.Variables[0].Name == sysDescr {
		t.Fatal("GetNext returned same OID, expected next")
	}
}

func TestGetBulk(t *testing.T) {
	gs := connectV2c(t)
	result, err := gs.GetBulk([]string{systemOID}, 0, 5)
	if err != nil {
		t.Fatalf("GetBulk: %v", err)
	}
	if len(result.Variables) == 0 {
		t.Fatal("GetBulk returned 0 variables")
	}
	if len(result.Variables) > 5 {
		t.Logf("GetBulk returned %d variables (max-repetitions=5)", len(result.Variables))
	}
}
