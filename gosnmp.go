// Copyright 2012 Andreas Louca, 2013 Sonia Hamilton. All rights reserved.  Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"fmt"
	"math/big"
	"net"
	"strconv"
	"time"
)

// MAX_OIDS is the maximum number of oids allowed in a Get()
const MAX_OIDS = 60

type GoSNMP struct {

	// Target is an ipv4 address
	Target string

	// Port is a udp port
	Port uint16

	// Community is an SNMP Community string
	Community string

	// Version is an SNMP Version
	Version SnmpVersion

	// Timeout is the timeout for the SNMP Query
	Timeout time.Duration

	// Conn is net connection to use, typically establised using GoSNMP.Connect()
	Conn net.Conn

	// Logger is the GoSNMP.Logger to use for debugging. If nil, debugging
	// output will be discarded (/dev/null). For verbose logging to stdout:
	// x.Logger = log.New(os.Stdout, "", 0)
	Logger Logger
}

var Default = &GoSNMP{
	Port:      161,
	Community: "public",
	Version:   Version2c,
	Timeout:   time.Duration(2) * time.Second,
}

// SnmpPDU will be used when doing SNMP Set's
type SnmpPDU struct {

	// Name is an oid in string format eg "1.3.6.1.4.9.27"
	Name string

	// The type of the value eg Integer
	Type Asn1BER

	// The value to be set by the SNMP set
	Value interface{}
}

type Asn1BER byte

const (
	EndOfContents     Asn1BER = 0x00
	UnknownType               = 0x00
	Boolean                   = 0x01
	Integer                   = 0x02
	BitString                 = 0x03
	OctetString               = 0x04
	Null                      = 0x05
	ObjectIdentifier          = 0x06
	ObjectDescription         = 0x07
	IpAddress                 = 0x40
	Counter32                 = 0x41
	Gauge32                   = 0x42
	TimeTicks                 = 0x43
	Opaque                    = 0x44
	NsapAddress               = 0x45
	Counter64                 = 0x46
	Uinteger32                = 0x47
	NoSuchObject              = 0x80
	NoSuchInstance            = 0x81
	EndOfMibView              = 0x82
)

//
// Public Functions (main interface)
//

func (x *GoSNMP) Connect() error {
	Conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", x.Target, x.Port), x.Timeout)
	if err == nil {
		x.Conn = Conn
	} else {
		return fmt.Errorf("Error establishing connection to host: %s\n", err.Error())
	}
	return nil
}

// Send an SNMP GET request
func (x *GoSNMP) Get(oids []string) (result *SnmpPacket, err error) {
	oid_count := len(oids)
	if oid_count > MAX_OIDS {
		return nil, fmt.Errorf("oid count (%d) is greater than MAX_OIDS (%d)",
			oid_count, MAX_OIDS)
	}
	// convert oids slice to pdu slice
	var pdus []SnmpPDU
	for _, oid := range oids {
		pdus = append(pdus, SnmpPDU{oid, Null, nil})
	}
	// build up SnmpPacket
	packet_out := &SnmpPacket{
		Community:  x.Community,
		Error:      0,
		ErrorIndex: 0,
		PDUType:    GetRequest,
		Version:    x.Version,
	}
	return x.send(pdus, packet_out)
}

// Send an SNMP SET request
func (x *GoSNMP) Set(pdus []SnmpPDU) (result *SnmpPacket, err error) {
	if len(pdus) != 1 {
		return nil, fmt.Errorf("gosnmp currently only supports SNMP SETs for one oid")
	}
	if pdus[0].Type != Integer {
		return nil, fmt.Errorf("gosnmp currently only supports SNMP SETs for Integers")
	}
	// build up SnmpPacket
	packet_out := &SnmpPacket{
		Community:  x.Community,
		Error:      0,
		ErrorIndex: 0,
		PDUType:    SetRequest,
		Version:    x.Version,
	}
	return x.send(pdus, packet_out)
}

// Send an SNMP GETNEXT request
func (x *GoSNMP) GetNext(oids []string) (result *SnmpPacket, err error) {
	oid_count := len(oids)
	if oid_count > MAX_OIDS {
		return nil, fmt.Errorf("oid count (%d) is greater than MAX_OIDS (%d)",
			oid_count, MAX_OIDS)
	}

	// convert oids slice to pdu slice
	var pdus []SnmpPDU
	for _, oid := range oids {
		pdus = append(pdus, SnmpPDU{oid, Null, nil})
	}

	// Marshal and send the packet
	packet_out := &SnmpPacket{
		Community:  x.Community,
		Error:      0,
		ErrorIndex: 0,
		PDUType:    GetNextRequest,
		Version:    x.Version,
	}

	return x.send(pdus, packet_out)
}

// send an SNMP GETBULK request
func (x *GoSNMP) GetBulk(oids []string, non_repeaters uint8, max_repetitions uint8) (result *SnmpPacket, err error) {
	oid_count := len(oids)
	if oid_count > MAX_OIDS {
		return nil, fmt.Errorf("oid count (%d) is greater than MAX_OIDS (%d)",
			oid_count, MAX_OIDS)
	}

	// convert oids slice to pdu slice
	var pdus []SnmpPDU
	for _, oid := range oids {
		pdus = append(pdus, SnmpPDU{oid, Null, nil})
	}

	// Marshal and send the packet
	packet_out := &SnmpPacket{
		Community:      x.Community,
		PDUType:        GetBulkRequest,
		Version:        x.Version,
		NonRepeaters:   non_repeaters,
		MaxRepetitions: max_repetitions,
	}
	return x.send(pdus, packet_out)
}

//
// Public Functions (helpers) - in alphabetical order
//

// Partition - returns true when dividing a slice into
// partition_size lengths, including last partition which may be smaller
// than partition_size. This is useful when you have a large array of OIDs
// to run Get() on. See the tests for example usage.
//
// For example for a slice of 8 items to be broken into partitions of
// length 3, Partition returns true for the current_position having
// the following values:
//
// 0  1  2  3  4  5  6  7
//       T        T     T
//
func Partition(current_position, partition_size, slice_length int) bool {
	if current_position < 0 || current_position >= slice_length {
		return false
	}
	if partition_size == 1 { // redundant, but an obvious optimisation
		return true
	}
	if current_position%partition_size == partition_size-1 {
		return true
	}
	if current_position == slice_length-1 {
		return true
	}
	return false
}

// ToBigInt converts SnmpPDU.Value to big.Int, or returns a zero big.Int for
// non int-like types (eg strings).
//
// This is a convenience function to make working with SnmpPDU's easier - it
// reduces the need for type assertions. A big.Int is convenient, as SNMP can
// return int32, uint32, and uint64.
func ToBigInt(value interface{}) *big.Int {
	var val int64
	switch value := value.(type) { // shadow
	case int:
		val = int64(value)
	case int8:
		val = int64(value)
	case int16:
		val = int64(value)
	case int32:
		val = int64(value)
	case int64:
		val = int64(value)
	case uint:
		val = int64(value)
	case uint8:
		val = int64(value)
	case uint16:
		val = int64(value)
	case uint32:
		val = int64(value)
	case uint64:
		return (uint64ToBigInt(value))
	case string:
		// for testing and other apps - numbers may appear as strings
		var err error
		if val, err = strconv.ParseInt(value, 10, 64); err != nil {
			return new(big.Int)
		}
	default:
		return new(big.Int)
	}
	return big.NewInt(val)
}
