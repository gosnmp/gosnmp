// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package netsnmp

import (
	"encoding/base64"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/gosnmp/gosnmp"
)

var (
	rec  = flag.Bool("rec", false, "record and use net-snmp expected outputs, else use recorded values [if true requires libsnmp/cgo]. ")
	pcap = flag.String("pcap", "", "dir to put exp and got data as pcap files, no pcaps made if blank.")
)

func TestPDU(t *testing.T) {
	flag.Parse()

	if isPlayback() {
		t.Log("playback mode enabled")
	}

	recdir := filepath.Join("testdata", t.Name())
	if *rec && !isPlayback() {
		if err := os.MkdirAll(recdir, 0755); err != nil {
			t.Fatalf("error creating record dir: %s", err)
		}
	} else if *rec {
		t.Fatal("record mode requires `-tags netsnmp` and libsnmpd installed")
	}

	pcapdir := ""
	if *pcap != "" {
		pcapdir = filepath.Join(*pcap, t.Name())
		if err := os.MkdirAll(pcapdir, 0755); err != nil {
			t.Fatalf("error creating pcap dir: %s", err)
		}
	}

	tstpdus := []gosnmp.SnmpPDU{
		{
			Name:  ".1.3.6.1.2.1.1.7.0",
			Type:  gosnmp.Integer,
			Value: 104,
		},
		{
			Name:  ".1.3.6.1.2.1.2.2.1.10.1",
			Type:  gosnmp.Counter32,
			Value: uint32(271070065),
		},
		{
			Name:  ".1.3.6.1.2.1.2.2.1.5.1",
			Type:  gosnmp.Gauge32,
			Value: uint32(math.MaxUint32),
		},
		{
			Name:  ".1.3.6.1.2.1.1.4.0",
			Type:  gosnmp.OctetString,
			Value: []byte("Administrator"),
		},
		{
			Name:  ".1.3.6.1.2.1.4.21.1.1.127.0.0.1",
			Type:  gosnmp.IPAddress,
			Value: "127.0.0.1",
		},
		{
			Name:  ".1.3.6.1.4.1.6574.4.2.12.1.0",
			Type:  gosnmp.OpaqueFloat,
			Value: float32(10.0),
		},
		{
			Name:  ".1.3.6.1.4.1.6574.4.2.12.1.1",
			Type:  gosnmp.OpaqueFloat,
			Value: float32(0.0),
		},
		{
			Name:  ".1.3.6.1.4.1.6574.4.2.12.2.0",
			Type:  gosnmp.OpaqueDouble,
			Value: float64(10.0),
		},
		{
			Name:  ".1.3.6.1.4.1.6574.4.2.12.2.1",
			Type:  gosnmp.OpaqueDouble,
			Value: float64(0.0),
		},
		{
			Name:  ".1.3.6.1.2.1.2.2.1.10.1",
			Type:  gosnmp.Counter32,
			Value: uint32(271070065),
		},
		{
			Name:  ".1.3.6.1.2.1.1.3.0",
			Type:  gosnmp.TimeTicks,
			Value: uint32(318870100),
		},
		{
			Name:  ".1.3.6.1.2.1.1.3.1",
			Type:  gosnmp.Uinteger32,
			Value: uint32(math.MaxInt32),
		},
		{
			Name:  ".1.3.6.1.2.1.1.3.2",
			Type:  gosnmp.Counter64,
			Value: uint64(math.MaxInt64),
		},
	}
	sess := gosnmp.Default
	sess.Version = gosnmp.Version2c

	for i, tstpdu := range tstpdus {
		tname := fmt.Sprintf("test%d_PDU%s", i, tstpdu.Type.String())
		t.Run(tname, func(t *testing.T) {
			fname := filepath.Join(recdir, tname+"_pkt.b64")

			pdus := []gosnmp.SnmpPDU{tstpdu}
			pkt := sess.MkSnmpPacket(gosnmp.SetRequest, pdus, 0, 0)
			pkt.RequestID++

			exp, err := netSnmpPduPkt(fname, pdus[0], sess, pkt.RequestID, testing.Verbose())
			if err != nil {
				t.Fatal(err)
			}

			if *rec {
				pktrec := base64.StdEncoding.EncodeToString(exp)
				if err = os.WriteFile(fname, []byte(pktrec), 0600); err != nil {
					t.Logf("error writing record file: %s", err)
				}
			}

			got, err := pkt.MarshalMsg()
			if err != nil {
				t.Fatal(err)
			}

			if *pcap != "" {
				savePcap(t, filepath.Join(pcapdir, tname), exp, got)
			}

			if diff := cmp.Diff(exp, got); diff != "" {
				t.Fatalf("\ngot(%d): %q\nexp(%d): %q\ndiff:\n%s", len(got), got, len(exp), exp, diff)
			}
		})
	}
}

func writePcap(fn string, payload []byte) error {
	fn += ".pcap"

	f, err := os.OpenFile(fn, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	l3 := &layers.IPv4{
		SrcIP:    net.ParseIP("192.168.2.1"),
		DstIP:    net.ParseIP("192.168.2.2"),
		Protocol: layers.IPProtocolUDP,
		Version:  4,
	}
	l4 := &layers.UDP{
		SrcPort: 161,
		DstPort: 161,
	}
	err = l4.SetNetworkLayerForChecksum(l3)
	if err != nil {
		return err
	}

	buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		},
		l3,
		l4,
		gopacket.Payload(payload),
	)
	if err != nil {
		return err
	}

	pkt := gopacket.NewPacket(buf.Bytes(),
		layers.LinkTypeIPv4,
		gopacket.Default)

	w := pcapgo.NewWriter(f)
	err = w.WriteFileHeader(1600, layers.LinkTypeIPv4)
	if err != nil {
		return err
	}

	err = w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(pkt.Data()),
		Length:        len(pkt.Data()),
	}, pkt.Data())
	if err != nil {
		return err
	}

	return nil
}

func savePcap(t *testing.T, fp string, exp, got []byte) {
	err := writePcap(fp+"_exp", exp)
	if err != nil {
		t.Logf("error saving exp pcap: %s", err.Error())
	}
	err = writePcap(fp+"_got", got)
	if err != nil {
		t.Logf("error saving got pcap: %s", err.Error())
	}
}
