// Copyright 2012-2016 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package main

import (
	"flag"
	"fmt"
	g "github.com/soniah/gosnmp"
	"log"
	"net"
	"os"
	"path/filepath"
)

func main() {
	flag.Usage = func() {
		fmt.Printf("Usage:\n")
		fmt.Printf("   %s\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}

	params := g.Default
	params.Logger = log.New(os.Stdout, "", 0)

	tl := g.TrapListener{
		OnNewTrap: myTrapHandler,
		Params:    params,
	}
	err := tl.Listen("0.0.0.0:9162")
	if err != nil {
		log.Panicf("error in listen: %s\n")
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
