// Copyright 2012-2014 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// This set of end-to-end integration tests execute gosnmp against a real
// SNMP MIB-2 host. Potential test systems could include a router, NAS box, printer,
// or a linux box running snmpd, snmpsimd.py, etc.
//
// Ensure "gosnmp-test-host" is defined in your hosts file, and points to your
// generic test system.

package gosnmp

import (
	"fmt"
	//"log"
	//"os"
	"strings"
	"testing"
	"time"
)

const (
	testTarget = "gosnmp-test-host" // Don't modify here - set in your hosts file.
	testPort   = 161
)

func setupConnection(t *testing.T) {
	if len(testTarget) < 1 {
		t.Skip("Skipping Generic tests! Is %s a valid SNMP host?")
	}
	Default.Target = testTarget
	Default.Port = testPort
	err := Default.Connect()
	if err != nil {
		t.Fatalf("Connection failed. Is %s defined in your hosts file? \n(err: %v)",
			testTarget, err)
	}
}

func TestGenericBasicGet(t *testing.T) {
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestGenericMultiGet(t *testing.T) {
	setupConnection(t)
	defer Default.Conn.Close()

	oids := []string{
		".1.3.6.1.2.1.1.1.0", // SNMP MIB-2 sysDescr
		".1.3.6.1.2.1.1.5.0", // SNMP MIB-2 sysName
	}
	result, err := Default.Get(oids)
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 2 {
		t.Fatalf("Expected result of size 2")
	}
	for _, v := range result.Variables {
		if v.Type != OctetString {
			t.Fatalf("Expected OctetString")
		}
	}
}

func TestGenericGetNext(t *testing.T) {
	setupConnection(t)
	defer Default.Conn.Close()

	sysDescrOid := ".1.3.6.1.2.1.1.1.0" // SNMP MIB-2 sysDescr
	result, err := Default.GetNext([]string{sysDescrOid})
	if err != nil {
		t.Fatalf("GetNext() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Name == sysDescrOid {
		t.Fatalf("Expected next OID")
	}
}

func TestGenericWalk(t *testing.T) {
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.WalkAll("")
	if err != nil {
		t.Fatalf("WalkAll() Failed with error => %v", err)
	}
	if len(result) <= 1 {
		t.Fatalf("Expected multiple values, got %d", len(result))
	}
}

func TestGenericBulkWalk(t *testing.T) {
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.BulkWalkAll("")
	if err != nil {
		t.Fatalf("BulkWalkAll() Failed with error => %v", err)
	}
	if len(result) <= 1 {
		t.Fatalf("Expected multiple values, got %d", len(result))
	}
}

// Standard exception/error tests

func TestGenericFailureUnknownHost(t *testing.T) {
	unknownHost := fmt.Sprintf("gosnmp-test-unknown-host-%d", time.Now().UTC().UnixNano())
	Default.Target = unknownHost
	err := Default.Connect()
	if err == nil {
		t.Fatalf("Expected connection failure due to unknown host")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "no such host") {
		t.Fatalf("Expected connection error of type 'no such host'! Got => %v", err)
	}
	_, err = Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err == nil {
		t.Fatalf("Expected get to fail due to missing connection")
	}
}

func TestGenericFailureConnectionTimeout(t *testing.T) {
	Default.Target = "198.51.100.1" // Black hole
	err := Default.Connect()
	if err != nil {
		t.Fatalf("Did not expect connection error with IP address")
	}
	_, err = Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err == nil {
		t.Fatalf("Expected Get() to fail due to invalid IP")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("Expected timeout error. Got => %v", err)
	}
}

func TestGenericFailureConnectionRefused(t *testing.T) {
	Default.Target = "127.0.0.1"
	Default.Port = 1 // Don't expect SNMP to be running here!
	err := Default.Connect()
	if err != nil {
		t.Fatalf("Did not expect connection error with IP address")
	}
	_, err = Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err == nil {
		t.Fatalf("Expected Get() to fail due to invalid port")
	}
	if !(strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "forcibly closed")) {
		t.Fatalf("Expected connection refused error. Got => %v", err)
	}
}

func TestSnmpV3NoAuthNoPrivBasicGet(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = NoAuthNoPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{UserName: "test"}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthNoPrivBasicGet(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = AuthNoPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{UserName: "authTest", AuthenticationProtocol: MD5, AuthenticationPassphrase: "testingpass0123456789"}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}
