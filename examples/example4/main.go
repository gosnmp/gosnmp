// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package main

import (
	"fmt"
	"log"
	"os"
	"time"
	g "github.com/gosnmp/gosnmp"
)

const (
	On  int = 1
	Off     = 2
)

func main() {
	var Client = &g.GoSNMP{
		Target:    "192.168.91.20",
		Port:      161,
		Community: "private",
		Version:   g.Version2c,
		Timeout:   time.Duration(2) * time.Second,
		Logger:    g.NewLogger(log.New(os.Stdout, "", 0)),
	}
	err := Client.Connect()
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer Client.Conn.Close()
	var mySnmpPDU = []g.SnmpPDU{{
		Name:  "1.3.6.1.4.1.318.1.1.4.4.2.1.3.15",
		Type:  g.Integer,
		Value: On,
	}}
	setResult, setErr := Client.Set(mySnmpPDU)
	if setErr != nil {
		log.Fatalf("SNMP set() fialed due to err: %v", setErr)
	}
	for i, variable := range setResult.Variables {
		fmt.Printf("%d: oid: %s ", i, variable.Name)

		// the Value of each variable returned by Get() implements
		// interface{}. You could do a type switch...
		switch variable.Type {
		case g.OctetString:
			fmt.Printf("string: %s\n", string(variable.Value.([]byte)))
		default:
			// ... or often you're just interested in numeric values.
			// ToBigInt() will return the Value as a BigInt, for plugging
			// into your calculations.
			fmt.Printf("number: %d\n", g.ToBigInt(variable.Value))
		}
	}
}
