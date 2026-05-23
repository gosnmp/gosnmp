// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// This set of end-to-end integration tests execute gosnmp against a real
// SNMP MIB-2 host. Potential test systems could include a router, NAS box, printer,
// or a linux box running snmpd, snmpsimd.py, etc.
//
// Ensure "gosnmp-test-host" is defined in your hosts file, and points to your
// generic test system.

//go:build all || end2end

package gosnmp

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func isUsingSnmpLabs() bool {
	return useSnmpLabsCredentials
}

// conveniently enable demo.snmplabs.com for a one test
func useSnmpLabs(use bool) {
	useSnmpLabsCredentials = use
}

func getTarget(t *testing.T) (string, uint16) {
	var envTarget string
	var envPort string

	// set this flag to true in v3_testing_credentials.go if you want to use the
	// public SNMP demo service for tests
	if isUsingSnmpLabs() {
		envTarget = "demo.snmplabs.com"
		envPort = "161"
	} else {
		envTarget = os.Getenv("GOSNMP_TARGET")
		envPort = os.Getenv("GOSNMP_PORT")
	}

	if len(envTarget) <= 0 {
		t.Skip("environment variable not set: GOSNMP_TARGET")
	}

	if len(envPort) <= 0 {
		t.Skip("environment variable not set: GOSNMP_PORT")
	}
	port, _ := strconv.ParseUint(envPort, 10, 16)

	if port > 65535 {
		t.Skipf("invalid port number %d", port)
	}

	return envTarget, uint16(port)
}

func connectToTarget(t *testing.T, gs *GoSNMP) {
	target, port := getTarget(t)

	gs.Target = target
	gs.Port = port

	err := gs.Connect()
	if err != nil {
		if len(target) > 0 {
			t.Fatalf("Connection failed. Is snmpd reachable on %s:%d?\n(err: %v)",
				target, port, err)
		}
	}
}

func connectToTargetIPv4(t *testing.T, gs *GoSNMP) {
	target, port := getTarget(t)

	gs.Target = target
	gs.Port = port

	err := gs.ConnectIPv4()
	if err != nil {
		if len(target) > 0 {
			t.Fatalf("Connection failed. Is snmpd reachable on %s:%d?\n(err: %v)",
				target, port, err)
		}
	}
}

func TestClose(t *testing.T) {
	gs := newTestGoSNMP()
	gs.Retries = 1

	connectToTarget(t, gs)

	// Ensure connection is open
	if gs.Conn == nil {
		t.Fatal("expected connection to be established, got nil")
	}

	// Close the connection
	err := gs.Close()
	if err != nil {
		t.Fatalf("Close() returned an error: %v", err)
	}

	// Try closing again to make sure it handles idempotency
	err = gs.Close()
	if err != nil {
		t.Errorf("Close() on already-closed connection should not error, got: %v", err)
	}
}

func TestClose_NilConnection(t *testing.T) {
	gs := &GoSNMP{
		Conn: nil,
	}

	err := gs.Close()
	if err != nil {
		t.Errorf("expected nil error when closing nil connection, got: %v", err)
	}
}

func TestClose_Concurrent(t *testing.T) {
	gs := newTestGoSNMP()
	gs.Timeout = time.Second
	gs.Retries = 1

	connectToTarget(t, gs)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ { // simulate 100 concurrent calls
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = gs.Close()
		}()
	}

	wg.Wait()

	if gs.Conn != nil {
		t.Errorf("expected connection to be nil after Close")
	}
}

/*
TODO work out ipv6 networking, etc

func setupConnectionIPv6(t *testing.T) *GoSNMP {
	envTarget := os.Getenv("GOSNMP_TARGET_IPV6")
	envPort := os.Getenv("GOSNMP_PORT_IPV6")
	gs := newTestGoSNMP()

	if len(envTarget) <= 0 {
		t.Error("environment variable not set: GOSNMP_TARGET_IPV6")
	}
	gs.Target = envTarget

	if len(envPort) <= 0 {
		t.Error("environment variable not set: GOSNMP_PORT_IPV6")
	}
	port, _ := strconv.ParseUint(envPort, 10, 16)
	gs.Port = uint16(port)

	err := gs.ConnectIPv6()
	if err != nil {
		if len(envTarget) > 0 {
			t.Fatalf("Connection failed. Is snmpd reachable on %s:%s?\n(err: %v)",
				envTarget, envPort, err)
		}
	}
	return gs
}
*/

func TestGenericBasicGet(t *testing.T) {
	gs := newTestGoSNMP()
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

func TestGenericBasicGetIPv4Only(t *testing.T) {
	gs := newTestGoSNMP()
	connectToTargetIPv4(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

/*
func TestGenericBasicGetIPv6Only(t *testing.T) {
	gs := setupConnectionIPv6(t)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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
*/

func TestGenericMultiGet(t *testing.T) {
	gs := newTestGoSNMP()
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	oids := []string{
		".1.3.6.1.2.1.1.1.0", // SNMP MIB-2 sysDescr
		".1.3.6.1.2.1.1.5.0", // SNMP MIB-2 sysName
	}
	result, err := gs.Get(oids)
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
	gs := newTestGoSNMP()
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	sysDescrOid := ".1.3.6.1.2.1.1.1.0" // SNMP MIB-2 sysDescr
	result, err := gs.GetNext([]string{sysDescrOid})
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
	gs := newTestGoSNMP()
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.WalkAll("")
	if err != nil {
		t.Fatalf("WalkAll() Failed with error => %v", err)
	}
	if len(result) <= 1 {
		t.Fatalf("Expected multiple values, got %d", len(result))
	}
}

func TestGenericBulkWalk(t *testing.T) {
	gs := newTestGoSNMP()
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.BulkWalkAll("")
	if err != nil {
		t.Fatalf("BulkWalkAll() Failed with error => %v", err)
	}
	if len(result) <= 1 {
		t.Fatalf("Expected multiple values, got %d", len(result))
	}
}

func TestV1BulkWalkError(t *testing.T) {
	g := newTestGoSNMP()
	g.Version = Version1
	connectToTarget(t, g)

	g.Conn.Close()

	_, err := g.BulkWalkAll("")
	if err == nil {
		t.Fatalf("BulkWalkAll() should fail in SNMPv1 but returned nil")
	}
}

// Standard exception/error tests

func TestMaxOids(t *testing.T) {
	gs := newTestGoSNMP()
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	gs.MaxOids = 1

	var err error
	oids := []string{".1.3.6.1.2.1.1.7.0",
		".1.3.6.1.2.1.2.2.1.10.1"} // 2 arbitrary Oids
	errString := "oid count (2) is greater than MaxOids (1)"

	_, err = gs.Get(oids)
	if err == nil {
		t.Fatalf("Expected too many oids failure. Got nil")
	} else if err.Error() != errString {
		t.Fatalf("Expected too many oids failure. Got => %v", err)
	}

	_, err = gs.GetNext(oids)
	if err == nil {
		t.Fatalf("Expected too many oids failure. Got nil")
	} else if err.Error() != errString {
		t.Fatalf("Expected too many oids failure. Got => %v", err)
	}

	_, err = gs.GetBulk(oids, 0, 0)
	if err == nil {
		t.Fatalf("Expected too many oids failure. Got nil")
	} else if err.Error() != errString {
		t.Fatalf("Expected too many oids failure. Got => %v", err)
	}
}

func TestGenericFailureUnknownHost(t *testing.T) {
	unknownHost := "nonexistent.invalid" // .invalid is guaranteed by RFC 2606 to never resolve.
	gs := newTestGoSNMP()
	gs.Target = unknownHost
	err := gs.Connect()
	if err == nil {
		t.Fatalf("Expected connection failure due to unknown host")
	}

	lerr := strings.ToLower(err.Error())
	if !strings.Contains(lerr, "no such host") && !strings.Contains(lerr, "i/o timeout") {
		t.Fatalf("Expected connection error of type 'no such host' or 'i/o timeout'! Got => %v", err)
	}

	_, err = gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err == nil {
		t.Fatalf("Expected get to fail due to missing connection")
	}
}

func TestGenericFailureConnectionTimeout(t *testing.T) {
	t.Skip("local testing - skipping this slow one") // TODO test tag, or something
	envTarget := os.Getenv("GOSNMP_TARGET")
	if len(envTarget) <= 0 {
		t.Skip("local testing - skipping this slow one")
	}

	gs := newTestGoSNMP()
	gs.Target = "198.51.100.1" // Black hole
	err := gs.Connect()
	if err != nil {
		t.Fatalf("Did not expect connection error with IP address")
	}
	_, err = gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err == nil {
		t.Fatalf("Expected Get() to fail due to invalid IP")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("Expected timeout error. Got => %v", err)
	}
}

func TestGenericFailureConnectionRefused(t *testing.T) {
	gs := newTestGoSNMP()
	gs.Target = "127.0.0.1"
	gs.Port = 1 // Don't expect SNMP to be running here!
	err := gs.Connect()
	if err != nil {
		t.Fatalf("Did not expect connection error with IP address")
	}
	_, err = gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err == nil {
		t.Fatalf("Expected Get() to fail due to invalid port")
	}
	if !(strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "forcibly closed")) {
		t.Fatalf("Expected connection refused error. Got => %v", err)
	}
}

func TestSnmpV3NoAuthNoPrivBasicGet(t *testing.T) {
	gs := newTestGoSNMPv3(NoAuthNoPriv, &UsmSecurityParameters{UserName: getUserName(t, NoAuth, NoPriv)})
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthMD5NoPrivGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	gs := newTestGoSNMPv3(AuthNoPriv, &UsmSecurityParameters{UserName: getUserName(t, MD5, NoPriv), AuthenticationProtocol: MD5, AuthenticationPassphrase: getAuthKey(t, MD5, NoPriv)})
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

func TestSnmpV3AuthMD5PrivAES256CGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	gs := newTestGoSNMPv3(AuthPriv, &UsmSecurityParameters{
		UserName:               getUserName(t, MD5, AES256C),
		AuthenticationProtocol: MD5, AuthenticationPassphrase: getAuthKey(t, MD5, AES256C),
		PrivacyProtocol: AES256C, PrivacyPassphrase: getPrivKey(t, MD5, AES256C),
	})
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

func TestSnmpV3AuthSHANoPrivGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	gs := newTestGoSNMPv3(AuthNoPriv, &UsmSecurityParameters{UserName: getUserName(t, SHA, NoPriv), AuthenticationProtocol: SHA, AuthenticationPassphrase: getAuthKey(t, SHA, NoPriv)})
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

func TestSnmpV3AuthSHAPrivAESGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	gs := newTestGoSNMPv3(AuthPriv, &UsmSecurityParameters{
		UserName:               getUserName(t, SHA, AES),
		AuthenticationProtocol: SHA, AuthenticationPassphrase: getAuthKey(t, SHA, AES),
		PrivacyProtocol: AES, PrivacyPassphrase: getPrivKey(t, SHA, AES),
	})
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

func TestSnmpV3AuthSHAPrivAES256CGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	gs := newTestGoSNMPv3(AuthPriv, &UsmSecurityParameters{
		UserName:               getUserName(t, SHA, AES256C),
		AuthenticationProtocol: SHA, AuthenticationPassphrase: getAuthKey(t, SHA, AES256C),
		PrivacyProtocol: AES256C, PrivacyPassphrase: getPrivKey(t, SHA, AES256C),
	})
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

func TestSnmpV3AuthSHA224NoPrivGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	gs := newTestGoSNMPv3(AuthNoPriv, &UsmSecurityParameters{UserName: getUserName(t, SHA224, NoPriv), AuthenticationProtocol: SHA224, AuthenticationPassphrase: getAuthKey(t, SHA224, NoPriv)})
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

func TestSnmpV3AuthSHA256NoPrivGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	gs := newTestGoSNMPv3(AuthNoPriv, &UsmSecurityParameters{UserName: getUserName(t, SHA256, NoPriv), AuthenticationProtocol: SHA256, AuthenticationPassphrase: getAuthKey(t, SHA256, NoPriv)})
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

func TestSnmpV3AuthSHA384NoPrivGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	gs := newTestGoSNMPv3(AuthNoPriv, &UsmSecurityParameters{UserName: getUserName(t, SHA384, NoPriv), AuthenticationProtocol: SHA384, AuthenticationPassphrase: getAuthKey(t, SHA384, NoPriv)})
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

func TestSnmpV3AuthSHA512NoPrivGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	gs := newTestGoSNMPv3(AuthNoPriv, &UsmSecurityParameters{UserName: getUserName(t, SHA512, NoPriv), AuthenticationProtocol: SHA512, AuthenticationPassphrase: getAuthKey(t, SHA512, NoPriv)})
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

func TestSnmpV3AuthSHA512PrivAES192Get(t *testing.T) {
	t.Skip("AES-192 Blumenthal is currently known to have issues.")
	gs := newTestGoSNMPv3(AuthPriv, &UsmSecurityParameters{
		UserName:               getUserName(t, SHA512, AES192),
		AuthenticationProtocol: SHA512, AuthenticationPassphrase: getAuthKey(t, SHA512, AES192),
		PrivacyProtocol: AES192, PrivacyPassphrase: getPrivKey(t, SHA512, AES192),
	})
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

func TestSnmpV3AuthSHA512PrivAES192CGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	gs := newTestGoSNMPv3(AuthPriv, &UsmSecurityParameters{
		UserName:               getUserName(t, SHA512, AES192C),
		AuthenticationProtocol: SHA512, AuthenticationPassphrase: getAuthKey(t, SHA512, AES192C),
		PrivacyProtocol: AES192C, PrivacyPassphrase: getPrivKey(t, SHA512, AES192C),
	})
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

// SHA 512 + AES256C (Reeder)
func TestSnmpV3AuthSHA512PrivAES256CGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	gs := newTestGoSNMPv3(AuthPriv, &UsmSecurityParameters{
		UserName:               getUserName(t, SHA512, AES256C),
		AuthenticationProtocol: SHA512, AuthenticationPassphrase: getAuthKey(t, SHA512, AES256C),
		PrivacyProtocol: AES256C, PrivacyPassphrase: getPrivKey(t, SHA512, AES256C),
	})
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

func TestSnmpV3AuthMD5PrivDESGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}

	gs := newTestGoSNMPv3(AuthPriv, &UsmSecurityParameters{UserName: getUserName(t, MD5, DES),
		AuthenticationProtocol:   MD5,
		AuthenticationPassphrase: getAuthKey(t, MD5, DES),
		PrivacyProtocol:          DES,
		PrivacyPassphrase:        getPrivKey(t, MD5, DES)})
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

func TestSnmpV3AuthSHAPrivDESGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	gs := newTestGoSNMPv3(AuthPriv, &UsmSecurityParameters{UserName: getUserName(t, SHA, DES),
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: getAuthKey(t, SHA, DES),
		PrivacyProtocol:          DES,
		PrivacyPassphrase:        getPrivKey(t, SHA, DES)})
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

func TestSnmpV3AuthMD5PrivAESGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}

	gs := newTestGoSNMPv3(AuthPriv, &UsmSecurityParameters{UserName: getUserName(t, MD5, AES),
		AuthenticationProtocol:   MD5,
		AuthenticationPassphrase: getAuthKey(t, MD5, AES),
		PrivacyProtocol:          AES,
		PrivacyPassphrase:        getPrivKey(t, MD5, AES)})
	connectToTarget(t, gs)
	defer gs.Conn.Close()

	result, err := gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
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

func TestSnmpV3PrivEmptyPrivatePassword(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	gs := newTestGoSNMP()
	gs.Version = Version3
	gs.MsgFlags = AuthPriv
	gs.SecurityModel = UserSecurityModel
	gs.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(t, SHA, AES),
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: getAuthKey(t, SHA, AES),
		PrivacyProtocol:          AES,
		PrivacyPassphrase:        ""}

	err := gs.Connect()
	if err == nil {
		t.Fatalf("Expected validation error for empty PrivacyPassphrase")
	}
}

func TestSnmpV3AuthNoPrivEmptyPrivatePassword(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	gs := newTestGoSNMP()
	gs.Version = Version3
	gs.MsgFlags = AuthNoPriv
	gs.SecurityModel = UserSecurityModel
	gs.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(t, SHA, NoPriv),
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: getAuthKey(t, SHA, NoPriv),
		PrivacyProtocol:          AES,
		PrivacyPassphrase:        getPrivKey(t, SHA, NoPriv)}

	err := gs.Connect()
	if err == nil {
		t.Fatalf("Expected validation error for empty PrivacyPassphrase")
	}
}
