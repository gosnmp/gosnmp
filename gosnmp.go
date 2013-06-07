// Copyright 2012 Andreas Louca, 2013 Sonia Hamilton. All rights reserved.  Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"fmt"
	"io/ioutil"
	"log"
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

var DefaultGoSNMP = &GoSNMP{
	Port:      161,
	Community: "public",
	Version:   Version2c,
	Timeout:   time.Duration(2) * time.Second,
}

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
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("recover: %v", e)
		}
	}()

	oid_count := len(oids)
	if oid_count > MAX_OIDS {
		return nil, fmt.Errorf("oid count (%d) is greater than MAX_OIDS (%d)",
			oid_count, MAX_OIDS)
	}

	if x.Conn == nil {
		return nil, fmt.Errorf("&GoSNMP.Conn is missing. Provide a connection or use Connect()")
	}
	x.Conn.SetDeadline(time.Now().Add(x.Timeout))

	if x.Logger == nil {
		x.Logger = log.New(ioutil.Discard, "", 0)
	}
	slog = x.Logger // global variable for debug logging

	// Marshal and send the packet
	packet_out := &SnmpPacket{
		Community:   x.Community,
		Error:       0,
		ErrorIndex:  0,
		RequestType: GetRequest,
		Version:     x.Version,
	}
	// RequestID is only used during tests, therefore use an arbitrary uint32 ie 1
	fBuf, err := packet_out.marshalMsg(oids, 1)
	if err != nil {
		return nil, fmt.Errorf("marshal: %v", err)
	}
	_, err = x.Conn.Write(fBuf)
	if err != nil {
		return nil, fmt.Errorf("Error writing to socket: %s", err.Error())
	}

	// Read and unmarshal the response
	resp := make([]byte, 4096, 4096)
	n, err := x.Conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("Error reading from UDP: %s", err.Error())
	}

	packet_in, err := unmarshal(resp[:n])
	if err != nil {
		return nil, fmt.Errorf("Unable to decode packet: %s", err.Error())
	}
	if packet_in == nil {
		return nil, fmt.Errorf("Unable to decode packet: nil")
	}
	if len(packet_in.Variables) < 1 {
		return nil, fmt.Errorf("No response received.")
	}

	return packet_in, nil
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
