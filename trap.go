// Copyright 2012-2016 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

//
// Sending Traps ie GoSNMP acting as an Agent
//

// SendTrap sends a SNMP Trap (v2c/v3 only)
//
// pdus[0] can a pdu of Type TimeTicks (with the desired uint32 epoch
// time).  Otherwise a TimeTicks pdu will be prepended, with time set to
// now. This mirrors the behaviour of the Net-SNMP command-line tools.
//
// SendTrap doesn't wait for a return packet from the NMS (Network
// Management Station).
//
// See also Listen() and examples for creating an NMS.
func (x *GoSNMP) SendTrap(trap SnmpTrap) (result *SnmpPacket, err error) {
	var pdutype PDUType

	if len(trap.Variables) == 0 {
		return nil, fmt.Errorf("Sendtrap requires at least 1 pdu")
	}

	if trap.Variables[0].Type == TimeTicks {
		// check is uint32
		if _, ok := trap.Variables[0].Value.(uint32); !ok {
			return nil, fmt.Errorf("Sendtrap TimeTick must be uint32")
		}
	}

	switch x.Version {
	case Version2c, Version3:
		// do nothing
		pdutype = SNMPv2Trap

		if trap.Variables[0].Type != TimeTicks {
			now := uint32(time.Now().Unix())
			timetickPDU := SnmpPDU{"1.3.6.1.2.1.1.3.0", TimeTicks, now, x.Logger}
			// prepend timetickPDU
			trap.Variables = append([]SnmpPDU{timetickPDU}, trap.Variables...)
		}

	case Version1:
		pdutype = Trap
		if len(trap.Enterprise) == 0 {
			return nil, fmt.Errorf("Sendtrap for SNMPV1 requires an Enterprise OID")
		}
		if len(trap.AgentAddress) == 0 {
			return nil, fmt.Errorf("Sendtrap for SNMPV1 requires an Agent Address")
		}

	default:
		err = fmt.Errorf("SendTrap doesn't support %s", x.Version)
		return nil, err
	}

	packetOut := x.mkSnmpPacket(pdutype, trap.Variables, 0, 0)
	if x.Version == Version1 {
		packetOut.Enterprise = trap.Enterprise
		packetOut.AgentAddress = trap.AgentAddress
		packetOut.GenericTrap = trap.GenericTrap
		packetOut.SpecificTrap = trap.SpecificTrap
		packetOut.Timestamp = trap.Timestamp
	}

	// all sends wait for the return packet, except for SNMPv2Trap
	// -> wait is false
	return x.send(packetOut, false)
}

//
// Receiving Traps ie GoSNMP acting as an NMS (Network Management
// Station).
//
// GoSNMP.unmarshal() currently only handles SNMPv2Trap (ie v2c, v3)
//

// A TrapListener defineds parameters for running a SNMP Trap receiver.
// nil values will be replaced by default values.
type TrapListener struct {
	OnNewTrap func(s *SnmpPacket, u *net.UDPAddr)
	Params    *GoSNMP

	// these unexported fields are for letting test cases
	// know we are ready
	listening bool
	c         *sync.Cond
	m         sync.Mutex
	conn      *net.UDPConn
	finish    chan bool
	done      chan bool
}

// optional constructor for TrapListener
func NewTrapListener() *TrapListener {
	tl := &TrapListener{}
	tl.c = sync.NewCond(&sync.Mutex{})
	tl.finish = make(chan bool)
	tl.done = make(chan bool)
	return tl
}

// safely check if TrapListener is ready and listening
func (t *TrapListener) ready() bool {
	t.m.Lock()
	defer t.m.Unlock()
	return t.listening
}

// Close terminates the listening on TrapListener socket
func (t *TrapListener) Close() {
	t.conn.Close()
	t.finish <- true
	<-t.done
}

// Listen listens on the UDP address addr and calls the OnNewTrap
// function specified in *TrapListener for every trap recieved.
func (t *TrapListener) Listen(addr string) (err error) {
	if t.Params == nil {
		t.Params = Default
	}
	t.Params.validateParameters()

	if t.OnNewTrap == nil {
		t.OnNewTrap = debugTrapHandler
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	t.conn = conn
	defer conn.Close()

	// mark that we are listening now
	func() {
		t.m.Lock()
		defer t.m.Unlock()
		t.listening = true
		t.c.Broadcast()
	}()

	// don't forget to mark that we are no longer listening later on
	defer func() {
		t.m.Lock()
		defer t.m.Unlock()
		t.listening = false
		t.c.Broadcast()
	}()

	for {
		select {
		case <-t.finish:
			t.done <- true
			return

		default:
			var buf [4096]byte
			rlen, remote, err := conn.ReadFromUDP(buf[:])
			if err != nil {
				t.Params.logPrintf("TrapListener: error in read %s\n", err)
			}

			msg := buf[:rlen]
			traps := t.Params.UnmarshalTrap(msg)
			if traps != nil {
				t.OnNewTrap(traps, remote)
			}
		}

	}
}

// Default trap handler
func debugTrapHandler(s *SnmpPacket, u *net.UDPAddr) {
	log.Printf("got trapdata from %+v: %+v\n", u, s)
}

// Unmarshal SNMP Trap
func (x *GoSNMP) UnmarshalTrap(trap []byte) (result *SnmpPacket) {
	result = new(SnmpPacket)

	if x.SecurityParameters != nil {
		result.SecurityParameters = x.SecurityParameters.Copy()
	}

	cursor, err := x.unmarshalHeader(trap, result)
	if err != nil {
		x.logPrintf("UnmarshalTrap: %s\n", err)
		return nil
	}

	if result.Version == Version3 {
		if result.SecurityModel == UserSecurityModel {
			err = x.testAuthentication(trap, result)
			if err != nil {
				x.logPrintf("UnmarshalTrap v3 auth: %s\n", err)
				return nil
			}
		}
		trap, cursor, err = x.decryptPacket(trap, cursor, result)
	}
	err = x.unmarshalPayload(trap, cursor, result)
	if err != nil {
		x.logPrintf("UnmarshalTrap: %s\n", err)
		return nil
	}
	return result
}
