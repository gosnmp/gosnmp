// Copyright 2014 Chris Dance (codedance). All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in
// the LICENSE file.

// This program demonstrates BulkWalk.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/codedance/gosnmp"
)

func usage() {
	fmt.Println("\nUsage:\n\n")
	fmt.Printf("   %s host [oid]\n", filepath.Base(os.Args[0]))
	fmt.Println("     host - the host to walk/scan")
	fmt.Println("     oid  - the MIB/Oid defining a subtree of values")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	target := os.Args[1]
	var oid string
	if len(os.Args) > 2 {
		oid = os.Args[2]
	}

	gosnmp.Default.Target = target
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
		fmt.Printf("STRING: %s\n", pdu.Value.(string))
	default:
		fmt.Printf("TYPE %d: %d\n", pdu.Type, gosnmp.ToBigInt(pdu.Value))
	}
	return nil
}
