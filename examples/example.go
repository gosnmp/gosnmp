// Copyright 2012 Andreas Louca and Jon Auer, 2013 Sonia Hamilton. All
// rights reserved.  Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/soniah/gosnmp"
)

var (
	cmdCommunity string
	cmdPort      uint
	cmdTarget    string
	cmdOid       string
	cmdDebug     string
	cmdTimeout   int64
)

func init() {
	flag.StringVar(&cmdDebug, "debug", "", "Debug flag expects byte array of raw packet to test decoding")

	flag.StringVar(&cmdTarget, "target", "", "Target SNMP Agent")
	flag.UintVar(&cmdPort, "port", 161, "Target Port")
	flag.StringVar(&cmdCommunity, "community", "public", "SNNP Community")
	flag.StringVar(&cmdOid, "oid", "", "OID")
	flag.Int64Var(&cmdTimeout, "timeout", 5, "Set the timeout in seconds")
	flag.Parse()
}

func main() {
	if cmdDebug != "" {
		fmt.Printf("Running in debug mode\n")
		s, err := gosnmp.NewGoSNMP("", 0, "", gosnmp.Version2c, 5)
		s.SetDebug(true)
		s.SetVerbose(true)
		packet, err := hex.DecodeString(cmdDebug)
		if err != nil {
			fmt.Printf("Unable to decode raw packet: %s\n", err.Error())
			return
		}

		pckt, err := s.Debug(packet)

		if err != nil {
			fmt.Printf("Error while debugging: %s\n", err.Error())
		} else {
			for _, resp := range pckt.Variables {
				fmt.Printf("%s -> %v\n", resp.Name, resp.Value)
			}
		}

		return
	}

	if cmdTarget == "" || cmdOid == "" {
		flag.PrintDefaults()
		return
	}

	s, err := gosnmp.NewGoSNMP(cmdTarget, uint16(cmdPort), cmdCommunity, gosnmp.Version2c, cmdTimeout)
	s.SetDebug(true)
	s.SetVerbose(true)
	if err != nil {
		fmt.Printf("Error creating SNMP instance: %s\n", err.Error())
		return
	}

	s.SetTimeout(cmdTimeout)
	fmt.Printf("Getting %s\n", cmdOid)
	resp, err := s.Get(cmdOid)
	if err != nil {
		fmt.Printf("Error getting response: %s\n", err.Error())
	} else {
		for _, v := range resp.Variables {
			fmt.Printf("%s -> ", v.Name)
			switch v.Type {
			case gosnmp.OctetString:
				if s, ok := v.Value.(string); ok {
					fmt.Printf("%s\n", s)
				} else {
					fmt.Printf("Response is not a string\n")
				}
			default:
				fmt.Printf("Type: %d - Value: %v\n", v.Type, v.Value)
			}
		}

	}

}
