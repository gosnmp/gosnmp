// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package e2e

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

const (
	sysDescr  = ".1.3.6.1.2.1.1.1.0"
	sysName   = ".1.3.6.1.2.1.1.5.0"
	systemOID = ".1.3.6.1.2.1.1"
)

func getTarget(t *testing.T) (string, uint16) {
	t.Helper()
	target := os.Getenv("GOSNMP_TARGET")
	if target == "" {
		t.Skip("GOSNMP_TARGET not set")
	}
	portStr := os.Getenv("GOSNMP_PORT")
	if portStr == "" {
		t.Skip("GOSNMP_PORT not set")
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("invalid GOSNMP_PORT %q: %v", portStr, err)
	}
	return target, uint16(port)
}

// connectV2c returns a connected SNMPv2c session. Connection is closed via t.Cleanup.
func connectV2c(t *testing.T) *gosnmp.GoSNMP {
	t.Helper()
	target, port := getTarget(t)
	gs := &gosnmp.GoSNMP{
		Target:    target,
		Port:      port,
		Version:   gosnmp.Version2c,
		Community: "public",
		Timeout:   5 * time.Second,
		Retries:   1,
	}
	if err := gs.Connect(); err != nil {
		t.Fatalf("connect to %s:%d: %v", target, port, err)
	}
	t.Cleanup(func() { gs.Conn.Close() })
	return gs
}

// connectV3 returns a connected SNMPv3 session for the given credential.
func connectV3(t *testing.T, cred V3Credential, msgFlags gosnmp.SnmpV3MsgFlags) *gosnmp.GoSNMP {
	t.Helper()
	target, port := getTarget(t)
	gs := &gosnmp.GoSNMP{
		Target:        target,
		Port:          port,
		Version:       gosnmp.Version3,
		Timeout:       5 * time.Second,
		Retries:       1,
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      msgFlags,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 cred.UserName,
			AuthenticationProtocol:   cred.AuthProtocol,
			AuthenticationPassphrase: cred.AuthPassphrase,
			PrivacyProtocol:          cred.PrivProtocol,
			PrivacyPassphrase:        cred.PrivPassphrase,
		},
	}
	if err := gs.Connect(); err != nil {
		t.Fatalf("V3 connect (%s/%s) to %s:%d: %v", cred.AuthProtocol, cred.PrivProtocol, target, port, err)
	}
	t.Cleanup(func() { gs.Conn.Close() })
	return gs
}

// oidLess returns true if OID a is numerically less than OID b.
// OIDs are compared component-by-component as integers.
func oidLess(a, b string) bool {
	aParts := strings.Split(strings.TrimPrefix(a, "."), ".")
	bParts := strings.Split(strings.TrimPrefix(b, "."), ".")
	for i := range aParts {
		if i >= len(bParts) {
			return false // a is longer, so a > b
		}
		// Atoi errors (non-numeric components) are treated as 0; acceptable for test use.
		ai, _ := strconv.Atoi(aParts[i])
		bi, _ := strconv.Atoi(bParts[i])
		if ai != bi {
			return ai < bi
		}
	}
	return len(aParts) < len(bParts)
}

// getSysDescr does a GET on sysDescr and returns the string value.
// Fails the test on error or unexpected type.
func getSysDescr(t *testing.T, gs *gosnmp.GoSNMP) string {
	t.Helper()
	result, err := gs.Get([]string{sysDescr})
	if err != nil {
		t.Fatalf("Get(sysDescr): %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Get(sysDescr): got %d variables, want 1", len(result.Variables))
	}
	v := result.Variables[0]
	if v.Type != gosnmp.OctetString {
		t.Fatalf("sysDescr type = %v, want OctetString", v.Type)
	}
	b, ok := v.Value.([]byte)
	if !ok || len(b) == 0 {
		t.Fatal("sysDescr value empty or wrong type")
	}
	return string(b)
}
