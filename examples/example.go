// Copyright 2012 Andreas Louca. All rights reserved.
// Use of this source code is goverend by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"./gosnmp"
	"flag"
	"fmt"
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
	resp := s.Get(cmdOid)
	fmt.Printf("%s -> %s\n", cmdOid, resp)
}
