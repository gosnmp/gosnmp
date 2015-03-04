// Copyright 2012-2014 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// This program demonstrates BulkWalk.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/soniah/gosnmp"
)

func usage() {
	fmt.Println("Usage:")
	fmt.Printf("   %s host community [oid]\n", filepath.Base(os.Args[0]))
	fmt.Println("     host      - the host to walk/scan")
	fmt.Println("     community - the community string for device")
	fmt.Println("     oid       - the MIB/Oid defining a subtree of values")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 3 {
		usage()
	}
	target := os.Args[1]
	community := os.Args[2]
	var oid string
	if len(os.Args) > 3 {
		oid = os.Args[3]
	}

	gosnmp.Default.Target = target
	gosnmp.Default.Community = community
	gosnmp.Default.Timeout = time.Duration(10 * time.Second) // Timeout better suited to walking
	err := gosnmp.Default.Connect()
	if err != nil {
		fmt.Printf("Connect err: %v\n", err)
		os.Exit(1)
	}
	defer gosnmp.Default.Conn.Close()

	err = gosnmp.Default.BulkWalk(oid, printValue)
	if err != nil {
		fmt.Printf("Walk Error: %v\n", err)
		os.Exit(1)
	}
}

func printValue(pdu gosnmp.SnmpPDU) error {
	fmt.Printf("%s = ", pdu.Name)

	switch pdu.Type {
	case gosnmp.OctetString:
		b := pdu.Value.([]byte)
		fmt.Printf("STRING: %s\n", string(b))
	default:
		fmt.Printf("TYPE %d: %d\n", pdu.Type, gosnmp.ToBigInt(pdu.Value))
	}
	return nil
}
