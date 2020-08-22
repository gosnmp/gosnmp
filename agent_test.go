// Copyright 2012-2020 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// The purpose of these tests is to validate gosnmp's public APIs.
//
// IMPORTANT: If you're modifying _any_ existing code in this file, you
// should be asking yourself about API compatibility!

package gosnmp

import (
	"log"
	"os"
	"testing"
	"time"
)

var startTime time.Time

func TestSnmpAgent(t *testing.T) {
	startTime = time.Now()
	g := &GoSNMP{}
	g.Target = "127.0.0.1"
	g.Port = 161
	g.Community = "public"
	g.Version = Version2c
	g.Timeout = time.Duration(time.Second * 3)
	g.Retries = 0
	g.Logger = log.New(os.Stdout, "", 0)
	a := &GoSNMPAgent{
		Port:   161,
		IPAddr: "0.0.0.0",
		Logger: log.New(os.Stdout, "", 0),
		Snmp:   g,
	}
	initMib(a)
	if a.mibList[6].strOid != ".1.3.6.1.2.1.1.7.0" {
		t.Error("AddMibList sort error")
	}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second * 2)

	err := g.Connect()
	if err != nil {
		t.Fatalf("Connect() err: %v", err)
	}
	defer g.Conn.Close()

	oids := []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}
	result, err2 := g.Get(oids)
	if err2 != nil {
		t.Fatalf("Get() err: %v", err2)
	}
	if result.Error != NoError {
		t.Fatal(result)
	}
	for i, variable := range result.Variables {
		t.Logf("%d: oid: %s ", i, variable.Name)
		switch variable.Type {
		case OctetString:
			t.Logf("string: %s\n", string(variable.Value.(string)))
		default:
			t.Logf("number: %d\n", ToBigInt(variable.Value))
		}
	}
	a.Stop()
}

func getSysDescr(oid string) interface{} {
	return "test"
}

func getSysObjectID(oid string) interface{} {
	return ".1.3.6.1.2.1.1.1.0"
}

func getSysUpTime(oid string) interface{} {
	return uint32((time.Now().UnixNano() - startTime.UnixNano()) / (1000 * 1000 * 10))
}

func getSysContact(oid string) interface{} {
	return "test sysContact"
}

func getSysName(oid string) interface{} {
	return "test sysName"
}

func getSysLocation(oid string) interface{} {
	return "test sysLocation"
}

func getSysServices(oid string) interface{} {
	return 72
}

func initMib(a *GoSNMPAgent) {
	a.AddMibList(".1.3.6.1.2.1.1.1.0", OctetString, getSysDescr)
	a.AddMibList(".1.3.6.1.2.1.1.2.0", ObjectIdentifier, getSysObjectID)
	a.AddMibList(".1.3.6.1.2.1.1.3.0", TimeTicks, getSysUpTime)
	a.AddMibList(".1.3.6.1.2.1.1.7.0", Integer, getSysServices)
	a.AddMibList(".1.3.6.1.2.1.1.4.0", OctetString, getSysContact)
	a.AddMibList(".1.3.6.1.2.1.1.5.0", OctetString, getSysName)
	a.AddMibList(".1.3.6.1.2.1.1.6.0", OctetString, getSysLocation)
}
