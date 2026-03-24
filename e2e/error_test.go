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

func TestConnectionErrors(t *testing.T) {
	t.Run("unknown host", func(t *testing.T) {
		gs := &gosnmp.GoSNMP{
			Target:  "nonexistent.invalid",
			Port:    161,
			Version: gosnmp.Version2c, Community: "public",
			Timeout: 2 * time.Second, Retries: 0,
		}
		err := gs.Connect()
		if err == nil {
			gs.Conn.Close()
			t.Fatal("expected connection error for unknown host")
		}
		lerr := strings.ToLower(err.Error())
		if !strings.Contains(lerr, "no such host") && !strings.Contains(lerr, "i/o timeout") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		gs := &gosnmp.GoSNMP{
			Target:  "127.0.0.1",
			Port:    1, // unlikely to have SNMP
			Version: gosnmp.Version2c, Community: "public",
			Timeout: 2 * time.Second, Retries: 0,
		}
		if err := gs.Connect(); err != nil {
			// UDP Connect may succeed (connectionless); error comes on Get
			t.Logf("Connect error (acceptable for TCP): %v", err)
			return
		}
		defer gs.Conn.Close()
		_, err := gs.Get([]string{sysDescr})
		if err == nil {
			t.Fatal("expected error from Get on refused port")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping slow timeout test")
		}
		gs := &gosnmp.GoSNMP{
			Target:  "198.51.100.1", // RFC 5737 documentation block (black hole)
			Port:    161,
			Version: gosnmp.Version2c, Community: "public",
			Timeout: 1 * time.Second, Retries: 0,
		}
		if err := gs.Connect(); err != nil {
			t.Logf("Connect error: %v", err)
			return
		}
		defer gs.Conn.Close()
		_, err := gs.Get([]string{sysDescr})
		if err == nil {
			t.Fatal("expected timeout error")
		}
		if !strings.Contains(err.Error(), "timeout") {
			t.Fatalf("expected timeout, got: %v", err)
		}
	})
}

func TestV3ValidationErrors(t *testing.T) {
	t.Run("empty privacy passphrase", func(t *testing.T) {
		target, port := getTarget(t)
		gs := &gosnmp.GoSNMP{
			Target: target, Port: port,
			Version: gosnmp.Version3, Timeout: 5 * time.Second,
			SecurityModel: gosnmp.UserSecurityModel,
			MsgFlags:      gosnmp.AuthPriv,
			SecurityParameters: &gosnmp.UsmSecurityParameters{
				UserName:                 "authSHAPrivAESUser",
				AuthenticationProtocol:   gosnmp.SHA,
				AuthenticationPassphrase: authPass,
				PrivacyProtocol:          gosnmp.AES,
				PrivacyPassphrase:        "", // invalid
			},
		}
		err := gs.Connect()
		if err == nil {
			gs.Conn.Close()
			t.Fatal("expected validation error for empty PrivacyPassphrase")
		}
	})

	t.Run("priv protocol with empty passphrase", func(t *testing.T) {
		target, port := getTarget(t)
		gs := &gosnmp.GoSNMP{
			Target: target, Port: port,
			Version: gosnmp.Version3, Timeout: 5 * time.Second,
			SecurityModel: gosnmp.UserSecurityModel,
			MsgFlags:      gosnmp.AuthNoPriv,
			SecurityParameters: &gosnmp.UsmSecurityParameters{
				UserName:                 "authSHAOnlyUser",
				AuthenticationProtocol:   gosnmp.SHA,
				AuthenticationPassphrase: authPass,
				PrivacyProtocol:          gosnmp.AES,
				PrivacyPassphrase:        "", // empty passphrase with priv protocol triggers validation error
			},
		}
		err := gs.Connect()
		if err == nil {
			gs.Conn.Close()
			t.Fatal("expected validation error for PrivacyProtocol with empty passphrase")
		}
	})
}

func TestV3WrongCredentials(t *testing.T) {
	target, port := getTarget(t)
	gs := &gosnmp.GoSNMP{
		Target: target, Port: port,
		Version: gosnmp.Version3, Timeout: 5 * time.Second, Retries: 0,
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      gosnmp.AuthNoPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 "authMD5OnlyUser",
			AuthenticationProtocol:   gosnmp.MD5,
			AuthenticationPassphrase: "wrongpassword",
		},
	}
	if err := gs.Connect(); err != nil {
		// Discovery may fail outright
		t.Logf("Connect failed (acceptable): %v", err)
		return
	}
	defer gs.Conn.Close()
	_, err := gs.Get([]string{sysDescr})
	if err == nil {
		t.Fatal("expected error with wrong credentials")
	}
}
