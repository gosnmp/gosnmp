// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"io"
	"log"
	"time"
)

func newTestGoSNMP() *GoSNMP {
	return &GoSNMP{
		Port:               161,
		Transport:          udp,
		Community:          "public",
		Version:            Version2c,
		Timeout:            2 * time.Second,
		Retries:            3,
		ExponentialTimeout: true,
		MaxOids:            MaxOids,
		Logger:             NewLogger(log.New(io.Discard, "", 0)),
	}
}

func newTestGoSNMPv3(msgFlags SnmpV3MsgFlags, sp SnmpV3SecurityParameters) *GoSNMP {
	gs := newTestGoSNMP()
	gs.Version = Version3
	gs.MsgFlags = msgFlags
	gs.SecurityModel = UserSecurityModel
	gs.SecurityParameters = sp
	return gs
}
