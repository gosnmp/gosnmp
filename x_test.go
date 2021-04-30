// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// +build x

package gosnmp

import (
	_ "fmt"
	"net"
	"testing"
	"time"
    _"log"
    _"io/ioutil"
)

func counter64Response() []byte {
	return []byte{
		0x30, 0x2f, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
		0x63, 0xa2, 0x22, 0x02, 0x04, 0x0b, 0x58, 0xf1, 0x52, 0x02, 0x01, 0x00,
		0x02, 0x01, 0x00, 0x30, 0x14, 0x30, 0x12, 0x06, 0x0b, 0x2b, 0x06, 0x01,
		0x02, 0x01, 0x1f, 0x01, 0x01, 0x01, 0x0a, 0x01, 0x46, 0x03, 0x17, 0x50,
		0x87,
	}
}

func BenchmarkSendOneRequest(b *testing.B) {
	b.StopTimer()

	srvr, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		b.Fatalf("udp4 error listening: %s", err)
	}
	defer srvr.Close()

	x := &GoSNMP{
		Version:                 Version2c,
		Target:                  srvr.LocalAddr().(*net.UDPAddr).IP.String(),
		Port:                    uint16(srvr.LocalAddr().(*net.UDPAddr).Port),
		Timeout:                 time.Millisecond * 100,
		Retries:                 0,
		UseUnconnectedUDPSocket: true,
//        Logger: NewLogger(log.New(ioutil.Discard, "", 0)),
        Logger: FakeLogger{},
	}
	if err := x.Connect(); err != nil {
		b.Fatalf("error connecting: %s", err)
	}

	go func() {
		buf := make([]byte, 256)
		outBuf := counter64Response()
		for {
			_, addr, err := srvr.ReadFrom(buf)
			if err != nil {
				return
			}

			copy(outBuf[17:21], buf[11:15]) // evil: copy request ID
			srvr.WriteTo(outBuf, addr)
		}
	}()

	pdus := []SnmpPDU{{Name: ".1.3.6.1.2.1.31.1.1.1.10.1", Type: Null}}
	reqPkt := x.mkSnmpPacket(GetRequest, pdus, 0, 0)

	// make sure everything works before starting the test
	_, err = x.sendOneRequest(reqPkt, true)
	if err != nil {
		b.Fatalf("Precheck failed: %s", err)
	}

	b.StartTimer()

	for n := 0; n < b.N; n++ {
		_, err = x.sendOneRequest(reqPkt, true)
		if err != nil {
			b.Fatalf("error: %s", err)
			return
		}
	}
}
