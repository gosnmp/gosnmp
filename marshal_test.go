// Copyright 2013 Sonia Hamilton. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package gosnmp

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

var _ = fmt.Sprintf("dummy") // dummy
var _ = ioutil.Discard       // dummy
var _ = os.DevNull           // dummy

// Tests in alphabetical order of function being tested

// -- Enmarshal ----------------------------------------------------------------

// "Enmarshal" not "Marshal" - easier to select tests via a regex

type testsEnmarshalVarbindPosition struct {
	oid string
	// start and finish position of bytes are calculated with application layer
	// starting at byte 0. The easiest way to calculate these values is to use
	// ghex (or similar) to delete the bytes from the lower layers of the
	// capture. Then open the capture in wireshark, right-click, "decode as..."
	// and choose snmp. Click on each varbind and the "packet bytes" window
	// will highlight the corresponding bytes, then the "eyeball tool" can be
	// used to find the start and finish values...
	start     int
	finish    int
	pdu_type  Asn1BER
	pdu_value interface{}
}

type testsEnmarshal_t struct {
	version      SnmpVersion
	community    string
	request_type PDUType
	requestid    uint32
	// function and function name returning bytes from tcpdump
	good_bytes func() []byte
	func_name  string // could do this via reflection
	// start position of the pdu
	pdu_start int
	// start position of the vbl
	vbl_start int
	// finish position of pdu, vbl and message - all the same
	finish int
	// a slice of positions containing start and finish of each varbind
	vb_positions []testsEnmarshalVarbindPosition
}

var testsEnmarshal = []testsEnmarshal_t{
	{
		Version2c,
		"public",
		GetRequest,
		1871507044,
		kyocera_request_bytes,
		"kyocera_request",
		0x0e, // pdu start
		0x1d, // vbl start
		0xa0, // finish
		[]testsEnmarshalVarbindPosition{
			{"1.3.6.1.2.1.1.7.0", 0x20, 0x2d, Null, nil},
			{"1.3.6.1.2.1.2.2.1.10.1", 0x2e, 0x3d, Null, nil},
			{"1.3.6.1.2.1.2.2.1.5.1", 0x3e, 0x4d, Null, nil},
			{"1.3.6.1.2.1.1.4.0", 0x4e, 0x5b, Null, nil},
			{"1.3.6.1.2.1.43.5.1.1.15.1", 0x5c, 0x6c, Null, nil},
			{"1.3.6.1.2.1.4.21.1.1.127.0.0.1", 0x6d, 0x7f, Null, nil},
			{"1.3.6.1.4.1.23.2.5.1.1.1.4.2", 0x80, 0x92, Null, nil},
			{"1.3.6.1.2.1.1.3.0", 0x93, 0xa0, Null, nil},
		},
	},
	{
		Version1,
		"privatelab",
		SetRequest,
		526895288,
		port_on_outgoing1,
		"port_on_outgoing1",
		0x11, // pdu start
		0x1f, // vbl start
		0x36, // finish
		[]testsEnmarshalVarbindPosition{
			{"1.3.6.1.4.1.318.1.1.4.4.2.1.3.5", 0x21, 0x36, Integer, 1},
		},
	},
	{
		Version1,
		"privatelab",
		SetRequest,
		1826072803,
		port_off_outgoing1,
		"port_off_outgoing1",
		0x11, // pdu start
		0x1f, // vbl start
		0x36, // finish
		[]testsEnmarshalVarbindPosition{
			{"1.3.6.1.4.1.318.1.1.4.4.2.1.3.5", 0x21, 0x36, Integer, 2},
		},
	},
}

// helpers for Enmarshal tests

// vb_pos_pdus returns a slice of oids in the given test
func vb_pos_pdus(test testsEnmarshal_t) (pdus []SnmpPDU) {
	for _, vbp := range test.vb_positions {
		pdu := SnmpPDU{vbp.oid, vbp.pdu_type, vbp.pdu_value}
		pdus = append(pdus, pdu)
	}
	return
}

// check_byte_equality walks the bytes in test_bytes, and compares them to good_bytes
func check_byte_equality(t *testing.T, test testsEnmarshal_t, test_bytes []byte,
	start int, finish int) {

	test_bytes_len := len(test_bytes)

	good_bytes := test.good_bytes()
	good_bytes = good_bytes[start : finish+1]
	for cursor := range good_bytes {
		if test_bytes_len < cursor {
			t.Errorf("%s: test_bytes_len (%d) < cursor (%d)", test.func_name,
				test_bytes_len, cursor)
			break
		}
		if test_bytes[cursor] != good_bytes[cursor] {
			t.Errorf("%s: cursor %d: test_bytes != good_bytes:\n%s\n%s",
				test.func_name,
				cursor,
				dumpBytes2("good", good_bytes, cursor),
				dumpBytes2("test", test_bytes, cursor))
			break
		}
	}
}

// Enmarshal tests in order that should be used for troubleshooting
// ie check each varbind is working, then the varbind list, etc

func TestEnmarshalVarbind(t *testing.T) {

	// slog = log.New(os.Stdout, "", 0) // for verbose debugging
	slog = log.New(ioutil.Discard, "", 0)

	for _, test := range testsEnmarshal {
		for j, test2 := range test.vb_positions {
			snmppdu := &SnmpPDU{test2.oid, test2.pdu_type, test2.pdu_value}
			test_bytes, err := marshalVarbind(snmppdu)
			if err != nil {
				t.Errorf("#%s:%d:%s err returned: %v",
					test.func_name, j, test2.oid, err)
			}

			check_byte_equality(t, test, test_bytes, test2.start, test2.finish)
		}
	}
}

func TestEnmarshalVBL(t *testing.T) {

	// slog = log.New(os.Stdout, "", 0) // for verbose debugging
	slog = log.New(ioutil.Discard, "", 0)

	for _, test := range testsEnmarshal {
		x := &SnmpPacket{
			Community: test.community,
			Version:   test.version,
			RequestID: test.requestid,
		}

		pdus := vb_pos_pdus(test)

		test_bytes, err := x.marshalVBL(pdus)
		if err != nil {
			t.Errorf("#%s: marshalVBL() err returned: %v", test.func_name, err)
		}

		check_byte_equality(t, test, test_bytes, test.vbl_start, test.finish)
	}
}

func TestEnmarshalPDU(t *testing.T) {

	// slog = log.New(os.Stdout, "", 0) // for verbose debugging
	slog = log.New(ioutil.Discard, "", 0)

	for _, test := range testsEnmarshal {
		x := &SnmpPacket{
			Community: test.community,
			Version:   test.version,
			PDUType:   test.request_type,
			RequestID: test.requestid,
		}
		pdus := vb_pos_pdus(test)

		test_bytes, err := x.marshalPDU(pdus, test.requestid)
		if err != nil {
			t.Errorf("#%s: marshalPDU() err returned: %v", test.func_name, err)
		}

		check_byte_equality(t, test, test_bytes, test.pdu_start, test.finish)
	}
}

func TestEnmarshalMsg(t *testing.T) {

	// slog = log.New(os.Stdout, "", 0) // for verbose debugging
	slog = log.New(ioutil.Discard, "", 0)

	for _, test := range testsEnmarshal {
		x := &SnmpPacket{
			Community: test.community,
			Version:   test.version,
			PDUType:   test.request_type,
			RequestID: test.requestid,
		}
		pdus := vb_pos_pdus(test)

		test_bytes, err := x.marshalMsg(pdus,
			test.request_type, test.requestid)
		if err != nil {
			t.Errorf("#%s: marshal() err returned: %v", test.func_name, err)
		}
		check_byte_equality(t, test, test_bytes, 0, test.finish)
	}
}

// -- Unmarshal -----------------------------------------------------------------

var testsUnmarshal = []struct {
	in  func() []byte
	out *SnmpPacket
}{
	{kyocera_response_bytes,
		&SnmpPacket{
			Version:    Version2c,
			Community:  "public",
			PDUType:    GetResponse,
			RequestID:  1066889284,
			Error:      0,
			ErrorIndex: 0,
			Variables: []SnmpPDU{
				{
					Name:  "1.3.6.1.2.1.1.7.0",
					Type:  Integer,
					Value: 104,
				},
				{
					Name:  "1.3.6.1.2.1.2.2.1.10.1",
					Type:  Counter32,
					Value: 271070065,
				},
				{
					Name:  "1.3.6.1.2.1.2.2.1.5.1",
					Type:  Gauge32,
					Value: 100000000,
				},
				{
					Name:  "1.3.6.1.2.1.1.4.0",
					Type:  OctetString,
					Value: "Administrator",
				},
				{
					Name:  "1.3.6.1.2.1.43.5.1.1.15.1",
					Type:  Null,
					Value: nil,
				},
				{
					Name:  "1.3.6.1.2.1.4.21.1.1.127.0.0.1",
					Type:  IpAddress,
					Value: "127.0.0.1",
				},
				{
					Name:  "1.3.6.1.4.1.23.2.5.1.1.1.4.2",
					Type:  OctetString,
					Value: "00 15 99 37 76 2b",
				},
				{
					Name:  "1.3.6.1.2.1.1.3.0",
					Type:  TimeTicks,
					Value: 318870100,
				},
			},
		},
	},
	{cisco_response_bytes,
		&SnmpPacket{
			Version:    Version2c,
			Community:  "public",
			PDUType:    GetResponse,
			RequestID:  4876669,
			Error:      0,
			ErrorIndex: 0,
			Variables: []SnmpPDU{
				{
					Name:  "1.3.6.1.2.1.1.7.0",
					Type:  Integer,
					Value: 78,
				},
				{
					Name:  "1.3.6.1.2.1.2.2.1.2.6",
					Type:  OctetString,
					Value: "GigabitEthernet0",
				},
				{
					Name:  "1.3.6.1.2.1.2.2.1.5.3",
					Type:  Gauge32,
					Value: uint(4294967295),
				},
				{
					Name:  "1.3.6.1.2.1.2.2.1.7.2",
					Type:  NoSuchInstance,
					Value: nil,
				},
				{
					Name:  "1.3.6.1.2.1.2.2.1.9.3",
					Type:  TimeTicks,
					Value: 2970,
				},
				{
					Name:  "1.3.6.1.2.1.3.1.1.2.10.1.10.11.0.17",
					Type:  OctetString,
					Value: "00 07 7d 4d 09 00",
				},
				{
					Name:  "1.3.6.1.2.1.3.1.1.3.10.1.10.11.0.2",
					Type:  IpAddress,
					Value: "10.11.0.2",
				},
				{
					Name:  "1.3.6.1.2.1.4.20.1.1.110.143.197.1",
					Type:  IpAddress,
					Value: "110.143.197.1",
				},
				{
					Name:  "1.3.6.1.66.1",
					Type:  NoSuchObject,
					Value: nil,
				},
				{
					Name:  "1.3.6.1.2.1.1.2.0",
					Type:  ObjectIdentifier,
					Value: "1.3.6.1.4.1.9.1.1166",
				},
			},
		},
	},
	{port_on_incoming1,
		&SnmpPacket{
			Version:     Version1,
			Community:   "privatelab",
			PDUType:     GetResponse,
			RequestID:   526895288,
			Error:       0,
			ErrorIndex:  0,
			Variables: []SnmpPDU{
				{
					Name:  "1.3.6.1.4.1.318.1.1.4.4.2.1.3.5",
					Type:  Integer,
					Value: 1,
				},
			},
		},
	},
	{port_off_incoming1,
		&SnmpPacket{
			Version:     Version1,
			Community:   "privatelab",
			PDUType: GetResponse,
			RequestID:   1826072803,
			Error:       0,
			ErrorIndex:  0,
			Variables: []SnmpPDU{
				{
					Name:  "1.3.6.1.4.1.318.1.1.4.4.2.1.3.5",
					Type:  Integer,
					Value: 2,
				},
			},
		},
	},
}

func TestUnmarshal(t *testing.T) {

	// slog = log.New(os.Stdout, "", 0) // for verbose debugging
	slog = log.New(ioutil.Discard, "", 0)

SANITY:
	for i, test := range testsUnmarshal {
		var err error
		var res *SnmpPacket

		if res, err = unmarshal(test.in()); err != nil {
			t.Errorf("#%d, Unmarshal returned err: %v", i, err)
			continue SANITY
		} else if res == nil {
			t.Errorf("#%d, Unmarshal returned nil", i)
			continue SANITY
		}

		// test "header" fields
		if res.Version != test.out.Version {
			t.Errorf("#%d Version result: %v, test: %v", i, res.Version, test.out.Version)
		}
		if res.Community != test.out.Community {
			t.Errorf("#%d Community result: %v, test: %v", i, res.Community, test.out.Community)
		}
		if res.PDUType != test.out.PDUType {
			t.Errorf("#%d PDUType result: %v, test: %v", i, res.PDUType, test.out.PDUType)
		}
		if res.RequestID != test.out.RequestID {
			t.Errorf("#%d RequestID result: %v, test: %v", i, res.RequestID, test.out.RequestID)
		}
		if res.Error != test.out.Error {
			t.Errorf("#%d Error result: %v, test: %v", i, res.Error, test.out.Error)
		}
		if res.ErrorIndex != test.out.ErrorIndex {
			t.Errorf("#%d ErrorIndex result: %v, test: %v", i, res.ErrorIndex, test.out.ErrorIndex)
		}

		// test varbind values
		for n, vb := range test.out.Variables {
			if len(res.Variables) < n {
				t.Errorf("#%d:%d ran out of varbind results", i, n)
				continue SANITY
			}
			vbr := res.Variables[n]

			if vbr.Name != vb.Name {
				t.Errorf("#%d:%d Name result: %v, test: %v", i, n, vbr.Name, vb.Name)
			}
			if vbr.Type != vb.Type {
				t.Errorf("#%d:%d Type result: %v, test: %v", i, n, vbr.Type, vb.Type)
			}

			switch vb.Type {
			case Integer, Gauge32, Counter32, TimeTicks, Counter64:
				vbval := ToBigInt(vb.Value)
				vbrval := ToBigInt(vbr.Value)
				if vbval.Cmp(vbrval) != 0 {
					t.Errorf("#%d:%d Value result: %v, test: %v", i, n, vbr.Value, vb.Value)
				}
			case OctetString, IpAddress, ObjectIdentifier:
				if vb.Value != vbr.Value {
					t.Errorf("#%d:%d Value result: %v, test: %v", i, n, vbr.Value, vb.Value)
				}
			case Null, NoSuchObject, NoSuchInstance:
				if (vb.Value != nil) || (vbr.Value != nil) {
					t.Errorf("#%d:%d Value result: %v, test: %v", i, n, vbr.Value, vb.Value)
				}
			default:
				t.Errorf("#%d:%d Unhandled case result: %v, test: %v", i, n, vbr.Value, vb.Value)
			}

		}
	}
}

// -----------------------------------------------------------------------------

/*

* byte dumps generated using tcpdump and github.com/jteeuwen/go-bindata eg
  `sudo tcpdump -s 0 -i eth0 -w cisco.pcap host 203.50.251.17 and port 161`

* Frame, Ethernet II, IP and UDP layers removed from generated bytes
*/

/*
kyocera_response_bytes corresponds to the response section of this snmpget

Simple Network Management Protocol
  version: v2c (1)
  community: public
  data: get-response (2)
    get-response
      request-id: 1066889284
      error-status: noError (0)
      error-index: 0
      variable-bindings: 8 items
        1.3.6.1.2.1.1.7.0: 104
        1.3.6.1.2.1.2.2.1.10.1: 271070065
        1.3.6.1.2.1.2.2.1.5.1: 100000000
        1.3.6.1.2.1.1.4.0: 41646d696e6973747261746f72
        1.3.6.1.2.1.43.5.1.1.15.1: Value (Null)
        1.3.6.1.2.1.4.21.1.1.127.0.0.1: 127.0.0.1 (127.0.0.1)
        1.3.6.1.4.1.23.2.5.1.1.1.4.2: 00159937762b
        1.3.6.1.2.1.1.3.0: 318870100
*/

func kyocera_response_bytes() []byte {
	return []byte{
		0x30, 0x81, 0xc2, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c,
		0x69, 0x63, 0xa2, 0x81, 0xb4, 0x02, 0x04, 0x3f, 0x97, 0x70, 0x44, 0x02,
		0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x81, 0xa5, 0x30, 0x0d, 0x06, 0x08,
		0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00, 0x02, 0x01, 0x68, 0x30,
		0x12, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0a,
		0x01, 0x41, 0x04, 0x10, 0x28, 0x33, 0x71, 0x30, 0x12, 0x06, 0x0a, 0x2b,
		0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x05, 0x01, 0x42, 0x04, 0x05,
		0xf5, 0xe1, 0x00, 0x30, 0x19, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01,
		0x01, 0x04, 0x00, 0x04, 0x0d, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x69, 0x73,
		0x74, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x30, 0x0f, 0x06, 0x0b, 0x2b, 0x06,
		0x01, 0x02, 0x01, 0x2b, 0x05, 0x01, 0x01, 0x0f, 0x01, 0x05, 0x00, 0x30,
		0x15, 0x06, 0x0d, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x04, 0x15, 0x01, 0x01,
		0x7f, 0x00, 0x00, 0x01, 0x40, 0x04, 0x7f, 0x00, 0x00, 0x01, 0x30, 0x17,
		0x06, 0x0d, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x17, 0x02, 0x05, 0x01, 0x01,
		0x01, 0x04, 0x02, 0x04, 0x06, 0x00, 0x15, 0x99, 0x37, 0x76, 0x2b, 0x30,
		0x10, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x43,
		0x04, 0x13, 0x01, 0x92, 0x54,
	}
}

/*
cisco_response_bytes corresponds to the response section of this snmpget:

% snmpget -On -v2c -c public 203.50.251.17 1.3.6.1.2.1.1.7.0 1.3.6.1.2.1.2.2.1.2.6 1.3.6.1.2.1.2.2.1.5.3 1.3.6.1.2.1.2.2.1.7.2 1.3.6.1.2.1.2.2.1.9.3 1.3.6.1.2.1.3.1.1.2.10.1.10.11.0.17 1.3.6.1.2.1.3.1.1.3.10.1.10.11.0.2 1.3.6.1.2.1.4.20.1.1.110.143.197.1 1.3.6.1.66.1 1.3.6.1.2.1.1.2.0
.1.3.6.1.2.1.1.7.0 = INTEGER: 78
.1.3.6.1.2.1.2.2.1.2.6 = STRING: GigabitEthernet0
.1.3.6.1.2.1.2.2.1.5.3 = Gauge32: 4294967295
.1.3.6.1.2.1.2.2.1.7.2 = No Such Instance currently exists at this OID
.1.3.6.1.2.1.2.2.1.9.3 = Timeticks: (2970) 0:00:29.70
.1.3.6.1.2.1.3.1.1.2.10.1.10.11.0.17 = Hex-STRING: 00 07 7D 4D 09 00
.1.3.6.1.2.1.3.1.1.3.10.1.10.11.0.2 = Network Address: 0A:0B:00:02
.1.3.6.1.2.1.4.20.1.1.110.143.197.1 = IpAddress: 110.143.197.1
.1.3.6.1.66.1 = No Such Object available on this agent at this OID
.1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.9.1.1166
*/

func cisco_response_bytes() []byte {
	return []byte{
		0x30, 0x81,
		0xf1, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
		0xa2, 0x81, 0xe3, 0x02, 0x03, 0x4a, 0x69, 0x7d, 0x02, 0x01, 0x00, 0x02,
		0x01, 0x00, 0x30, 0x81, 0xd5, 0x30, 0x0d, 0x06, 0x08, 0x2b, 0x06, 0x01,
		0x02, 0x01, 0x01, 0x07, 0x00, 0x02, 0x01, 0x4e, 0x30, 0x1e, 0x06, 0x0a,
		0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02, 0x06, 0x04, 0x10,
		0x47, 0x69, 0x67, 0x61, 0x62, 0x69, 0x74, 0x45, 0x74, 0x68, 0x65, 0x72,
		0x6e, 0x65, 0x74, 0x30, 0x30, 0x13, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02,
		0x01, 0x02, 0x02, 0x01, 0x05, 0x03, 0x42, 0x05, 0x00, 0xff, 0xff, 0xff,
		0xff, 0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02,
		0x01, 0x07, 0x02, 0x81, 0x00, 0x30, 0x10, 0x06, 0x0a, 0x2b, 0x06, 0x01,
		0x02, 0x01, 0x02, 0x02, 0x01, 0x09, 0x03, 0x43, 0x02, 0x0b, 0x9a, 0x30,
		0x19, 0x06, 0x0f, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x03, 0x01, 0x01, 0x02,
		0x0a, 0x01, 0x0a, 0x0b, 0x00, 0x11, 0x04, 0x06, 0x00, 0x07, 0x7d, 0x4d,
		0x09, 0x00, 0x30, 0x17, 0x06, 0x0f, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x03,
		0x01, 0x01, 0x03, 0x0a, 0x01, 0x0a, 0x0b, 0x00, 0x02, 0x40, 0x04, 0x0a,
		0x0b, 0x00, 0x02, 0x30, 0x17, 0x06, 0x0f, 0x2b, 0x06, 0x01, 0x02, 0x01,
		0x04, 0x14, 0x01, 0x01, 0x6e, 0x81, 0x0f, 0x81, 0x45, 0x01, 0x40, 0x04,
		0x6e, 0x8f, 0xc5, 0x01, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x42,
		0x01, 0x80, 0x00, 0x30, 0x15, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01,
		0x01, 0x02, 0x00, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x09, 0x01,
		0x89, 0x0e,
	}
}

/*
kyocera_request_bytes corresponds to the request section of this snmpget:

snmpget -On -v2c -c public 192.168.1.10 1.3.6.1.2.1.1.7.0 1.3.6.1.2.1.2.2.1.10.1 1.3.6.1.2.1.2.2.1.5.1 1.3.6.1.2.1.1.4.0 1.3.6.1.2.1.43.5.1.1.15.1 1.3.6.1.2.1.4.21.1.1.127.0.0.1 1.3.6.1.4.1.23.2.5.1.1.1.4.2 1.3.6.1.2.1.1.3.0
.1.3.6.1.2.1.1.7.0 = INTEGER: 104
.1.3.6.1.2.1.2.2.1.10.1 = Counter32: 144058856
.1.3.6.1.2.1.2.2.1.5.1 = Gauge32: 100000000
.1.3.6.1.2.1.1.4.0 = STRING: "Administrator"
.1.3.6.1.2.1.43.5.1.1.15.1 = NULL
.1.3.6.1.2.1.4.21.1.1.127.0.0.1 = IpAddress: 127.0.0.1
.1.3.6.1.4.1.23.2.5.1.1.1.4.2 = Hex-STRING: 00 15 99 37 76 2B
.1.3.6.1.2.1.1.3.0 = Timeticks: (120394900) 13 days, 22:25:49.00
*/

func kyocera_request_bytes() []byte {
	return []byte{
		0x30, 0x81,
		0x9e, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
		0xa0, 0x81, 0x90, 0x02, 0x04, 0x6f, 0x8c, 0xee, 0x64, 0x02, 0x01, 0x00,
		0x02, 0x01, 0x00, 0x30, 0x81, 0x81, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06,
		0x01, 0x02, 0x01, 0x01, 0x07, 0x00, 0x05, 0x00, 0x30, 0x0e, 0x06, 0x0a,
		0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0a, 0x01, 0x05, 0x00,
		0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01,
		0x05, 0x01, 0x05, 0x00, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02,
		0x01, 0x01, 0x04, 0x00, 0x05, 0x00, 0x30, 0x0f, 0x06, 0x0b, 0x2b, 0x06,
		0x01, 0x02, 0x01, 0x2b, 0x05, 0x01, 0x01, 0x0f, 0x01, 0x05, 0x00, 0x30,
		0x11, 0x06, 0x0d, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x04, 0x15, 0x01, 0x01,
		0x7f, 0x00, 0x00, 0x01, 0x05, 0x00, 0x30, 0x11, 0x06, 0x0d, 0x2b, 0x06,
		0x01, 0x04, 0x01, 0x17, 0x02, 0x05, 0x01, 0x01, 0x01, 0x04, 0x02, 0x05,
		0x00, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03,
		0x00, 0x05, 0x00,
	}
}

// === snmpset dumps ===

/*
port_on_*1() correspond to this snmpset and response:

snmpset -v 1 -c privatelab 192.168.100.124 .1.3.6.1.4.1.318.1.1.4.4.2.1.3.5 i 1

Simple Network Management Protocol
  version: version-1 (0)
  community: privatelab
  data: set-request (3)
    set-request
      request-id: 526895288
      error-status: noError (0)
      error-index: 0
      variable-bindings: 1 item
        1.3.6.1.4.1.318.1.1.4.4.2.1.3.5:
          Object Name: 1.3.6.1.4.1.318.1.1.4.4.2.1.3.5 (iso.3.6.1.4.1.318.1.1.4.4.2.1.3.5)
          Value (Integer32): 1

Simple Network Management Protocol
  version: version-1 (0)
  community: privatelab
  data: get-response (2)
    get-response
      request-id: 526895288
      error-status: noError (0)
      error-index: 0
      variable-bindings: 1 item
        1.3.6.1.4.1.318.1.1.4.4.2.1.3.5:
          Object Name: 1.3.6.1.4.1.318.1.1.4.4.2.1.3.5 (iso.3.6.1.4.1.318.1.1.4.4.2.1.3.5)
          Value (Integer32): 1
*/

func port_on_outgoing1() []byte {
	return []byte{
		0x30, 0x35, 0x02, 0x01, 0x00, 0x04, 0x0a, 0x70, 0x72, 0x69, 0x76, 0x61,
		0x74, 0x65, 0x6c, 0x61, 0x62, 0xa3, 0x24, 0x02, 0x04, 0x1f, 0x67, 0xc8,
		0xb8, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x16, 0x30, 0x14, 0x06,
		0x0f, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x3e, 0x01, 0x01, 0x04, 0x04,
		0x02, 0x01, 0x03, 0x05, 0x02, 0x01, 0x01,
	}
}

func port_on_incoming1() []byte {
	return []byte{
		0x30, 0x82, 0x00, 0x35, 0x02, 0x01, 0x00, 0x04, 0x0a, 0x70, 0x72, 0x69,
		0x76, 0x61, 0x74, 0x65, 0x6c, 0x61, 0x62, 0xa2, 0x24, 0x02, 0x04, 0x1f,
		0x67, 0xc8, 0xb8, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x16, 0x30,
		0x14, 0x06, 0x0f, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x3e, 0x01, 0x01,
		0x04, 0x04, 0x02, 0x01, 0x03, 0x05, 0x02, 0x01, 0x01,
	}
}

/*
port_off_*1() correspond to this snmpset and response:

snmpset -v 1 -c privatelab 192.168.100.124 .1.3.6.1.4.1.318.1.1.4.4.2.1.3.5 i 2

Simple Network Management Protocol
  version: version-1 (0)
  community: privatelab
  data: set-request (3)
    set-request
      request-id: 1826072803
      error-status: noError (0)
      error-index: 0
      variable-bindings: 1 item
        1.3.6.1.4.1.318.1.1.4.4.2.1.3.5:
          Object Name: 1.3.6.1.4.1.318.1.1.4.4.2.1.3.5 (iso.3.6.1.4.1.318.1.1.4.4.2.1.3.5)
          Value (Integer32): 2

Simple Network Management Protocol
  version: version-1 (0)
  community: privatelab
  data: get-response (2)
    get-response
      request-id: 1826072803
      error-status: noError (0)
      error-index: 0
      variable-bindings: 1 item
        1.3.6.1.4.1.318.1.1.4.4.2.1.3.5:
          Object Name: 1.3.6.1.4.1.318.1.1.4.4.2.1.3.5 (iso.3.6.1.4.1.318.1.1.4.4.2.1.3.5)
          Value (Integer32): 2
*/

func port_off_outgoing1() []byte {
	return []byte{
		0x30, 0x35, 0x02, 0x01, 0x00, 0x04, 0x0a, 0x70, 0x72, 0x69, 0x76, 0x61,
		0x74, 0x65, 0x6c, 0x61, 0x62, 0xa3, 0x24, 0x02, 0x04, 0x6c, 0xd7, 0xa8,
		0xe3, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x16, 0x30, 0x14, 0x06,
		0x0f, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x3e, 0x01, 0x01, 0x04, 0x04,
		0x02, 0x01, 0x03, 0x05, 0x02, 0x01, 0x02,
	}
}

func port_off_incoming1() []byte {
	return []byte{
		0x30, 0x82, 0x00, 0x35, 0x02, 0x01, 0x00, 0x04, 0x0a, 0x70, 0x72, 0x69,
		0x76, 0x61, 0x74, 0x65, 0x6c, 0x61, 0x62, 0xa2, 0x24, 0x02, 0x04, 0x6c,
		0xd7, 0xa8, 0xe3, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x16, 0x30,
		0x14, 0x06, 0x0f, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x3e, 0x01, 0x01,
		0x04, 0x04, 0x02, 0x01, 0x03, 0x05, 0x02, 0x01, 0x02,
	}
}
