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
)

func init() {
	flag.StringVar(&cmdTarget, "target", "", "Target SNMP Agent")
	flag.StringVar(&cmdCommunity, "community", "", "SNNP Community")
	flag.StringVar(&cmdOid, "oid", "", "OID")
	flag.Parse()
}

func main() {
	s := gosnmp.NewGoSNMP(cmdTarget, cmdCommunity, 1)
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
			fmt.Printf("Type: %d\n", resp.Type)
		}
	}

}
