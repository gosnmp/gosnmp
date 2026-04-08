// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package e2e

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

// V3Credential holds SNMPv3 USM credentials for a single user.
type V3Credential struct {
	UserName       string
	AuthProtocol   gosnmp.SnmpV3AuthProtocol
	AuthPassphrase string
	PrivProtocol   gosnmp.SnmpV3PrivProtocol
	PrivPassphrase string
}

// Consistent passphrases used across most test users.
const (
	authPass = "gosnmpTestAuthPass"
	privPass = "gosnmpTestPrivPass"

	// Non-ASCII passphrases to exercise UTF-8 handling in key derivation.
	authPassUTF8 = "gøsnmp-tëst!äuth"
	privPassUTF8 = "gøsnmp-tëst!prïv"
)

// credentials maps [authProtocol, privProtocol] to configured test users.
// Values must match what is configured in the test snmpd (e2e/testcontainer/).
var credentials = map[[2]string]V3Credential{
	// noAuthNoPriv
	{gosnmp.NoAuth.String(), gosnmp.NoPriv.String()}: {
		UserName: "noAuthNoPrivUser", AuthProtocol: gosnmp.NoAuth, PrivProtocol: gosnmp.NoPriv,
	},

	// MD5
	{gosnmp.MD5.String(), gosnmp.NoPriv.String()}: {
		UserName: "authMD5OnlyUser", AuthProtocol: gosnmp.MD5, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.NoPriv,
	},
	{gosnmp.MD5.String(), gosnmp.DES.String()}: {
		UserName: "authMD5PrivDESUser", AuthProtocol: gosnmp.MD5, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.DES, PrivPassphrase: privPass,
	},
	{gosnmp.MD5.String(), gosnmp.AES.String()}: {
		UserName: "authMD5PrivAESUser", AuthProtocol: gosnmp.MD5, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.AES, PrivPassphrase: privPass,
	},

	// SHA
	{gosnmp.SHA.String(), gosnmp.NoPriv.String()}: {
		UserName: "authSHAOnlyUser", AuthProtocol: gosnmp.SHA, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.NoPriv,
	},
	{gosnmp.SHA.String(), gosnmp.DES.String()}: {
		UserName: "authSHAPrivDESUser", AuthProtocol: gosnmp.SHA, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.DES, PrivPassphrase: privPass,
	},
	{gosnmp.SHA.String(), gosnmp.AES.String()}: {
		UserName: "authSHAPrivAESUser", AuthProtocol: gosnmp.SHA, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.AES, PrivPassphrase: privPass,
	},

	// SHA-224
	{gosnmp.SHA224.String(), gosnmp.NoPriv.String()}: {
		UserName: "authSHA224OnlyUser", AuthProtocol: gosnmp.SHA224, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.NoPriv,
	},
	{gosnmp.SHA224.String(), gosnmp.DES.String()}: {
		UserName: "authSHA224PrivDESUser", AuthProtocol: gosnmp.SHA224, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.DES, PrivPassphrase: privPass,
	},
	{gosnmp.SHA224.String(), gosnmp.AES.String()}: {
		UserName: "authSHA224PrivAESUser", AuthProtocol: gosnmp.SHA224, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.AES, PrivPassphrase: privPass,
	},

	// SHA-256
	{gosnmp.SHA256.String(), gosnmp.NoPriv.String()}: {
		UserName: "authSHA256OnlyUser", AuthProtocol: gosnmp.SHA256, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.NoPriv,
	},
	{gosnmp.SHA256.String(), gosnmp.DES.String()}: {
		UserName: "authSHA256PrivDESUser", AuthProtocol: gosnmp.SHA256, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.DES, PrivPassphrase: privPass,
	},
	{gosnmp.SHA256.String(), gosnmp.AES.String()}: {
		UserName: "authSHA256PrivAESUser", AuthProtocol: gosnmp.SHA256, AuthPassphrase: authPassUTF8,
		PrivProtocol: gosnmp.AES, PrivPassphrase: privPassUTF8,
	},

	// SHA-384
	{gosnmp.SHA384.String(), gosnmp.NoPriv.String()}: {
		UserName: "authSHA384OnlyUser", AuthProtocol: gosnmp.SHA384, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.NoPriv,
	},
	{gosnmp.SHA384.String(), gosnmp.DES.String()}: {
		UserName: "authSHA384PrivDESUser", AuthProtocol: gosnmp.SHA384, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.DES, PrivPassphrase: privPass,
	},
	{gosnmp.SHA384.String(), gosnmp.AES.String()}: {
		UserName: "authSHA384PrivAESUser", AuthProtocol: gosnmp.SHA384, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.AES, PrivPassphrase: privPass,
	},

	// SHA-512
	{gosnmp.SHA512.String(), gosnmp.NoPriv.String()}: {
		UserName: "authSHA512OnlyUser", AuthProtocol: gosnmp.SHA512, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.NoPriv,
	},
	{gosnmp.SHA512.String(), gosnmp.DES.String()}: {
		UserName: "authSHA512PrivDESUser", AuthProtocol: gosnmp.SHA512, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.DES, PrivPassphrase: privPass,
	},
	{gosnmp.SHA512.String(), gosnmp.AES.String()}: {
		UserName: "authSHA512PrivAESUser", AuthProtocol: gosnmp.SHA512, AuthPassphrase: authPassUTF8,
		PrivProtocol: gosnmp.AES, PrivPassphrase: privPassUTF8,
	},

	// Extended cipher suites
	{gosnmp.SHA512.String(), gosnmp.AES192.String()}: {
		UserName: "authSHA512PrivAES192BlmtUser", AuthProtocol: gosnmp.SHA512, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.AES192, PrivPassphrase: privPass,
	},
	{gosnmp.SHA512.String(), gosnmp.AES192C.String()}: {
		UserName: "authSHA512PrivAES192CUser", AuthProtocol: gosnmp.SHA512, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.AES192C, PrivPassphrase: privPass,
	},
	{gosnmp.MD5.String(), gosnmp.AES256C.String()}: {
		UserName: "authMD5PrivAES256CUser", AuthProtocol: gosnmp.MD5, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.AES256C, PrivPassphrase: privPass,
	},
	{gosnmp.SHA.String(), gosnmp.AES256C.String()}: {
		UserName: "authSHAPrivAES256CUser", AuthProtocol: gosnmp.SHA, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.AES256C, PrivPassphrase: privPass,
	},
	{gosnmp.SHA512.String(), gosnmp.AES256C.String()}: {
		UserName: "authSHA512PrivAES256CUser", AuthProtocol: gosnmp.SHA512, AuthPassphrase: authPass,
		PrivProtocol: gosnmp.AES256C, PrivPassphrase: privPass,
	},
}

// lookupCredential returns the V3Credential for the given auth/priv combination.
// Skips the test if no credential is configured.
func lookupCredential(t *testing.T, auth gosnmp.SnmpV3AuthProtocol, priv gosnmp.SnmpV3PrivProtocol) V3Credential {
	t.Helper()
	key := [2]string{auth.String(), priv.String()}
	cred, ok := credentials[key]
	if !ok {
		t.Skipf("no credential configured for %s/%s", auth, priv)
	}
	return cred
}
