// Copyright 2012 Andreas Louca. All rights reserved.
// Use of this source code is goverend by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"github.com/alouca/gosnmp"
)

var (
	cmdCommunity string
	cmdTarget    string
	cmdOid       string
	cmdTimeout   int64
)

func init() {
	flag.StringVar(&cmdTarget, "target", "", "Target SNMP Agent")
	flag.StringVar(&cmdCommunity, "community", "public", "SNNP Community")
	flag.StringVar(&cmdOid, "oid", "", "OID")
	flag.Int64Var(&cmdTimeout, "timeout", 5, "Set the timeout in seconds")
	flag.Parse()
}

func main() {
	if cmdTarget == "" || cmdOid == "" {
		flag.PrintDefaults()
		return
	}

	s, err := gosnmp.NewGoSNMP(cmdTarget, cmdCommunity, gosnmp.Version2c, cmdTimeout)

	if err != nil {
		fmt.Printf("Error creating SNMP instance: %s\n", err.Error())
		return
	}

	s.SetTimeout(cmdTimeout)
	fmt.Printf("Getting %s\n", cmdOid)
	resp, err := s.Get(cmdOid)

	if err != nil {
		fmt.Printf("Error during SNMP GET: %s\n", err.Error())
	} else {
		fmt.Printf("%s -> ", cmdOid)
		switch resp.Type {
		case gosnmp.OctetString:
			if s, ok := resp.Value.(string); ok {
				fmt.Printf("%s\n", s)
			} else {
				fmt.Printf("Response is not a string\n")
			}
		default:
			fmt.Printf("Type: %d - Value: %v\n", resp.Type, resp.Value)
		}
	}

}
