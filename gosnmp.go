// Copyright 2012 Andreas Louca and Jon Auer, 2013 Sonia Hamilton. All
// rights reserved.  Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"fmt"
	l "github.com/alouca/gologger"
	"net"
	"time"
)

type GoSNMP struct {
	Target    string
	Port      uint16
	Community string
	Version   SnmpVersion
	Timeout   time.Duration
	Conn      net.Conn
	Log       *l.Logger
}

func NewGoSNMP(target string, port uint16, community string, version SnmpVersion, timeout int64) (*GoSNMP, error) {
	// Open a UDP connection to the target
	Conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", target, port), time.Duration(timeout)*time.Second)

	if err != nil {
		return nil, fmt.Errorf("Error establishing connection to host: %s\n", err.Error())
	}
	s := &GoSNMP{target, port, community, version, time.Duration(timeout) * time.Second, Conn, l.CreateLogger(false, false)}

	return s, nil
}

// Enables verbose logging
func (x *GoSNMP) SetVerbose(v bool) {
	x.Log.VerboseFlag = v
}

// Enables debugging
func (x *GoSNMP) SetDebug(d bool) {
	x.Log.DebugFlag = d
}

// Sets the timeout for network read/write functions. Defaults to 5 seconds.
func (x *GoSNMP) SetTimeout(seconds int64) {
	if seconds <= 0 {
		seconds = 5
	}
	x.Timeout = time.Duration(seconds) * time.Second
}

// StreamWalk will start walking a specified OID, and push through a channel the results
// as it receives them, without waiting for the whole process to finish to return the 
// results
func (x *GoSNMP) StreamWalk(oid string, c chan *Variable) error {

	return nil
}

// Walk will SNMP walk the target, blocking until the process is complete
func (x *GoSNMP) Walk(oid string) ([]*Variable, error) {

	return nil, nil
}

// Debug function
func (x *GoSNMP) Debug(data []byte) (*SnmpPacket, error) {
	packet, err := Unmarshal(data)

	if err != nil {
		return nil, fmt.Errorf("Unable to decode packet: %s\n", err.Error())
	}
	return packet, nil
}

// Sends an SNMP GET request to the target. Returns a Variable with the response or an error
func (x *GoSNMP) Get(oid string) (result *SnmpPacket, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("recover: %v", e)
		}
	}()

	x.Conn.SetDeadline(time.Now().Add(x.Timeout)) // Set timeout on the connection
	packet := &SnmpPacket{
		Community:   x.Community,
		Error:       0,
		ErrorIndex:  0,
		RequestType: GetRequest,
		Version:     x.Version,
		Variables:   []SnmpPDU{SnmpPDU{Name: oid, Type: Null}},
	}

	// Marshal and send the packet
	fBuf, err := packet.marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal: %v", err)
	}

	_, err = x.Conn.Write(fBuf)
	if err != nil {
		return nil, fmt.Errorf("Error writing to socket: %s", err.Error())
	}

	// Read and unmarshal the response
	resp := make([]byte, 2048, 2048)
	n, err := x.Conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("Error reading from UDP: %s", err.Error())
	}

	pdu, err := Unmarshal(resp[:n])
	if err != nil {
		return nil, fmt.Errorf("Unable to decode packet: %s", err.Error())
	}
	if pdu == nil {
		return nil, fmt.Errorf("Unable to decode packet: nil")
	}
	if len(pdu.Variables) < 1 {
		return nil, fmt.Errorf("No response received.")
	}

	return pdu, nil
}
