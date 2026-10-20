// Copyright 2023 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

/*
The developer of the trapserver code (https://github.com/jda) says "I'm working
on the best level of abstraction but I'm able to receive traps from a Cisco
switch and Net-SNMP".

Pull requests welcome.
*/

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	g "github.com/gosnmp/gosnmp"
)

func main() {
	secParamsList := []*g.UsmSecurityParameters{
		{
			UserName:                 "myuser",
			AuthenticationProtocol:   g.MD5,
			AuthenticationPassphrase: "mypassword",
			PrivacyProtocol:          g.AES,
			PrivacyPassphrase:        "myprivacy",
		},
		{
			UserName:                 "myuser2",
			AuthenticationProtocol:   g.SHA,
			AuthenticationPassphrase: "mypassword2",
			PrivacyProtocol:          g.DES,
			PrivacyPassphrase:        "myprivacy2",
		},
		{
			UserName:                 "myuser2",
			AuthenticationProtocol:   g.MD5,
			AuthenticationPassphrase: "mypassword2",
			PrivacyProtocol:          g.AES,
			PrivacyPassphrase:        "myprivacy2",
		},
	}

	flag.Usage = func() {
		fmt.Printf("Usage:\n")
		fmt.Printf("   %s\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}

	tl := g.NewTrapListener()
	tl.OnNewTrap = myTrapHandler

	usmTable := g.NewSnmpV3SecurityParametersTable(g.NewLogger(log.New(os.Stdout, "", 0)))
	for _, sp := range secParamsList {
		err := usmTable.Add(sp.UserName, sp)
		if err != nil {
			usmTable.Logger.Print(err)
		}
	}

	gs := &g.GoSNMP{
		Port:                        161,
		Transport:                   "udp",
		Version:                     g.Version3, // Always using version3 for traps, only option that works with all SNMP versions simultaneously
		SecurityModel:               g.UserSecurityModel,
		SecurityParameters:          &g.UsmSecurityParameters{AuthoritativeEngineID: "12345"}, // Use for server's engine ID
		TrapSecurityParametersTable: usmTable,
	}
	tl.Params = gs
	tl.Params.Logger = g.NewLogger(log.New(os.Stdout, "", 0))

	err := tl.Listen("0.0.0.0:9162")
	if err != nil {
		log.Panicf("error in listen: %s", err)
	}
}

func myTrapHandler(packet *g.SnmpPacket, addr *net.UDPAddr) {
	log.Printf("got trapdata from %s\n", addr.IP)
	for _, v := range packet.Variables {
		switch v.Type {
		case g.OctetString:
			b := v.Value.([]byte)
			fmt.Printf("OID: %s, string: %x\n", v.Name, b)

		default:
			log.Printf("trap: %+v\n", v)
		}
	}
}
