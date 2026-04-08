// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package e2e

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

var v3TestCases = []struct {
	name     string
	auth     gosnmp.SnmpV3AuthProtocol
	priv     gosnmp.SnmpV3PrivProtocol
	msgFlags gosnmp.SnmpV3MsgFlags
	skip     string
}{
	// NoAuth
	{"NoAuth-NoPriv", gosnmp.NoAuth, gosnmp.NoPriv, gosnmp.NoAuthNoPriv, ""},

	// MD5
	{"MD5-NoPriv", gosnmp.MD5, gosnmp.NoPriv, gosnmp.AuthNoPriv, ""},
	{"MD5-DES", gosnmp.MD5, gosnmp.DES, gosnmp.AuthPriv, ""},
	{"MD5-AES", gosnmp.MD5, gosnmp.AES, gosnmp.AuthPriv, ""},

	// SHA
	{"SHA-NoPriv", gosnmp.SHA, gosnmp.NoPriv, gosnmp.AuthNoPriv, ""},
	{"SHA-DES", gosnmp.SHA, gosnmp.DES, gosnmp.AuthPriv, ""},
	{"SHA-AES", gosnmp.SHA, gosnmp.AES, gosnmp.AuthPriv, ""},

	// SHA-224
	{"SHA224-NoPriv", gosnmp.SHA224, gosnmp.NoPriv, gosnmp.AuthNoPriv, ""},
	{"SHA224-DES", gosnmp.SHA224, gosnmp.DES, gosnmp.AuthPriv, ""},
	{"SHA224-AES", gosnmp.SHA224, gosnmp.AES, gosnmp.AuthPriv, ""},

	// SHA-256
	{"SHA256-NoPriv", gosnmp.SHA256, gosnmp.NoPriv, gosnmp.AuthNoPriv, ""},
	{"SHA256-DES", gosnmp.SHA256, gosnmp.DES, gosnmp.AuthPriv, ""},
	{"SHA256-AES", gosnmp.SHA256, gosnmp.AES, gosnmp.AuthPriv, ""},

	// SHA-384
	{"SHA384-NoPriv", gosnmp.SHA384, gosnmp.NoPriv, gosnmp.AuthNoPriv, ""},
	{"SHA384-DES", gosnmp.SHA384, gosnmp.DES, gosnmp.AuthPriv, ""},
	{"SHA384-AES", gosnmp.SHA384, gosnmp.AES, gosnmp.AuthPriv, ""},

	// SHA-512
	{"SHA512-NoPriv", gosnmp.SHA512, gosnmp.NoPriv, gosnmp.AuthNoPriv, ""},
	{"SHA512-DES", gosnmp.SHA512, gosnmp.DES, gosnmp.AuthPriv, ""},
	{"SHA512-AES", gosnmp.SHA512, gosnmp.AES, gosnmp.AuthPriv, ""},

	// Extended cipher suites - AES-192
	{"SHA512-AES192", gosnmp.SHA512, gosnmp.AES192, gosnmp.AuthPriv, ""},
	{"SHA512-AES192C", gosnmp.SHA512, gosnmp.AES192C, gosnmp.AuthPriv, ""},

	// Extended cipher suites - AES-256
	// MD5/SHA + AES256C fail: Reeder key extension produces insufficient key material
	// from short-hash auth protocols (MD5=16 bytes, SHA1=20 bytes). net-snmp handles
	// this correctly, so this is a gosnmp bug in extendKeyReeder.
	{"MD5-AES256C", gosnmp.MD5, gosnmp.AES256C, gosnmp.AuthPriv, "gosnmp: Reeder key extension fails with MD5 (short hash)"},
	{"SHA-AES256C", gosnmp.SHA, gosnmp.AES256C, gosnmp.AuthPriv, "gosnmp: Reeder key extension fails with SHA1 (short hash)"},
	{"SHA512-AES256C", gosnmp.SHA512, gosnmp.AES256C, gosnmp.AuthPriv, ""},
}

func TestV3AuthPrivMatrix(t *testing.T) {
	for _, tc := range v3TestCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skip(tc.skip)
			}
			cred := lookupCredential(t, tc.auth, tc.priv)
			gs := connectV3(t, cred, tc.msgFlags)
			desc := getSysDescr(t, gs)
			t.Logf("sysDescr = %q", desc)
		})
	}
}
