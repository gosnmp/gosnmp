// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//
// Sending Traps ie GoSNMP acting as an Agent
//

// SendTrap sends a SNMP Trap
//
// pdus[0] can a pdu of Type TimeTicks (with the desired uint32 epoch
// time).  Otherwise a TimeTicks pdu will be prepended, with time set to
// now. This mirrors the behaviour of the Net-SNMP command-line tools.
//
// SendTrap doesn't wait for a return packet from the NMS (Network
// Management Station).
//
// See also Listen() and examples for creating an NMS.
//
// NOTE: the trap code is currently unreliable when working with snmpv3 - pull requests welcome
func (x *GoSNMP) SendTrap(trap SnmpTrap) (result *SnmpPacket, err error) {
	var pdutype PDUType

	switch x.Version {
	case Version2c, Version3:
		// Default to a v2 trap.
		pdutype = SNMPv2Trap

		if len(trap.Variables) == 0 {
			return nil, fmt.Errorf("function SendTrap requires at least 1 PDU")
		}

		if trap.Variables[0].Type == TimeTicks {
			// check is uint32
			if _, ok := trap.Variables[0].Value.(uint32); !ok {
				return nil, fmt.Errorf("function SendTrap TimeTick must be uint32")
			}
		}

		switch x.MsgFlags {
		// as per https://www.rfc-editor.org/rfc/rfc3412.html#section-6.4
		// The reportableFlag MUST always be zero when the message contains
		// a PDU from the Unconfirmed Class such as an SNMPv2-trap PDU
		case 0x4, 0x5, 0x7:
			// .. therefor bitclear the Reportable flag from the MsgFlags
			// that we inherited from validateParameters()
			x.MsgFlags = (x.MsgFlags &^ Reportable)
		}

		// If it's an inform, do that instead.
		if trap.IsInform {
			pdutype = InformRequest
		}

		if trap.Variables[0].Type != TimeTicks {
			now := uint32(time.Now().Unix())
			timetickPDU := SnmpPDU{Name: "1.3.6.1.2.1.1.3.0", Type: TimeTicks, Value: now}
			// prepend timetickPDU
			trap.Variables = append([]SnmpPDU{timetickPDU}, trap.Variables...)
		}

	case Version1:
		pdutype = Trap
		if len(trap.Enterprise) == 0 {
			return nil, fmt.Errorf("function SendTrap for SNMPV1 requires an Enterprise OID")
		}
		if len(trap.AgentAddress) == 0 {
			return nil, fmt.Errorf("function SendTrap for SNMPV1 requires an Agent Address")
		}

	default:
		err = fmt.Errorf("function SendTrap doesn't support %s", x.Version)
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
	// -> wait is only for informs
	return x.send(packetOut, trap.IsInform)
}

//
// Receiving Traps ie GoSNMP acting as an NMS (Network Management
// Station).
//
// GoSNMP.unmarshal() currently only handles SNMPv2Trap
//

// A TrapListener defines parameters for running a SNMP Trap receiver.
// nil values will be replaced by default values.
type TrapListener struct {
	done      chan bool
	listening chan bool
	sync.Mutex

	// Params is a reference to the TrapListener's "parent" GoSNMP instance.
	Params *GoSNMP

	// OnNewTrap handles incoming Trap and Inform PDUs.
	OnNewTrap TrapHandlerFunc

	// CloseTimeout is the max wait time for the socket to gracefully signal its closure.
	CloseTimeout time.Duration

	// These unexported fields are for letting test cases
	// know we are ready.
	conn  *net.UDPConn
	proto string

	// Total number of packets received referencing an unknown snmpEngineID
	usmStatsUnknownEngineIDsCount uint32

	finish int32 // Atomic flag; set to 1 when closing connection
}

// Default timeout value for CloseTimeout of 3 seconds
const defaultCloseTimeout = 3 * time.Second

// TrapHandlerFunc is a callback function type which receives SNMP Trap and
// Inform packets when they are received.  If this callback is null, Trap and
// Inform PDUs will not be received (Inform responses will still be sent,
// however).  This callback should not modify the contents of the SnmpPacket
// nor the UDPAddr passed to it, and it should copy out any values it wishes to
// use instead of retaining references in order to avoid memory fragmentation.
//
// The general effect of received Trap and Inform packets do not differ for the
// receiver, and the response is handled by the caller of the handler, so there
// is no need for the application to handle Informs any different than Traps.
// Nonetheless, the packet's Type field can be examined to determine what type
// of event this is for e.g. statistics gathering functions, etc.
type TrapHandlerFunc func(s *SnmpPacket, u *net.UDPAddr)

// NewTrapListener returns an initialized TrapListener.
//
// NOTE: the trap code is currently unreliable when working with snmpv3 - pull requests welcome
func NewTrapListener() *TrapListener {
	tl := &TrapListener{
		finish:       0,
		done:         make(chan bool),
		listening:    make(chan bool, 1), // Buffered because one doesn't have to block on it.
		CloseTimeout: defaultCloseTimeout,
	}

	return tl
}

// Listening returns a sentinel channel on which one can block
// until the listener is ready to receive requests.
//
// NOTE: the trap code is currently unreliable when working with snmpv3 - pull requests welcome
func (t *TrapListener) Listening() <-chan bool {
	t.Lock()
	defer t.Unlock()
	return t.listening
}

// Close terminates the listening on TrapListener socket
func (t *TrapListener) Close() {
	if atomic.CompareAndSwapInt32(&t.finish, 0, 1) {
		t.Lock()
		defer t.Unlock()

		if t.conn == nil {
			return
		}

		if err := t.conn.Close(); err != nil {
			t.Params.Logger.Printf("failed to Close() the TrapListener socket: %s", err)
		}

		select {
		case <-t.done:
		case <-time.After(t.CloseTimeout): // A timeout can prevent blocking forever
			t.Params.Logger.Printf("timeout while awaiting done signal on TrapListener Close()")
		}
	}
}

// SendUDP sends a given SnmpPacket to the provided address using the currently opened connection.
func (t *TrapListener) SendUDP(packet *SnmpPacket, addr *net.UDPAddr) error {
	ob, err := packet.marshalMsg()
	if err != nil {
		return fmt.Errorf("error marshaling SnmpPacket: %w", err)
	}

	// Send the return packet back.
	count, err := t.conn.WriteTo(ob, addr)
	if err != nil {
		return fmt.Errorf("error sending SnmpPacket: %w", err)
	}

	// This isn't fatal, but should be logged.
	if count != len(ob) {
		t.Params.Logger.Printf("Failed to send all bytes of SnmpPacket!\n")
	}
	return nil
}

func (t *TrapListener) listenUDP(addr string) error {
	// udp

	udpAddr, err := net.ResolveUDPAddr(t.proto, addr)
	if err != nil {
		return err
	}
	t.conn, err = net.ListenUDP(udp, udpAddr)
	if err != nil {
		return err
	}

	defer t.conn.Close()

	// Mark that we are listening now.
	t.listening <- true

	for {
		switch {
		case atomic.LoadInt32(&t.finish) == 1:
			t.done <- true
			return nil

		default:
			var buf [4096]byte
			rlen, remote, err := t.conn.ReadFromUDP(buf[:])
			if err != nil {
				if atomic.LoadInt32(&t.finish) == 1 {
					// err most likely comes from reading from a closed connection
					continue
				}
				t.Params.Logger.Printf("TrapListener: error in read %s\n", err)
				continue
			}

			msg := buf[:rlen]
			trap, err := t.Params.UnmarshalTrap(msg, false)
			if err != nil {
				t.Params.Logger.Printf("TrapListener: error in UnmarshalTrap %s\n", err)
				continue
			}
			if trap.Version == Version3 && trap.SecurityModel == UserSecurityModel && t.Params.SecurityModel == UserSecurityModel {
				securityParams, ok := t.Params.SecurityParameters.(*UsmSecurityParameters)
				if !ok {
					t.Params.Logger.Printf("TrapListener: Invalid SecurityParameters types")
				}
				packetSecurityParams, ok := trap.SecurityParameters.(*UsmSecurityParameters)
				if !ok {
					t.Params.Logger.Printf("TrapListener: Invalid SecurityParameters types")
				}
				snmpEngineID := securityParams.AuthoritativeEngineID
				msgAuthoritativeEngineID := packetSecurityParams.AuthoritativeEngineID
				if msgAuthoritativeEngineID != snmpEngineID {
					if len(msgAuthoritativeEngineID) < 5 || len(msgAuthoritativeEngineID) > 32 {
						// RFC3411 section 5. – SnmpEngineID definition.
						// SnmpEngineID is an OCTET STRING which size should be between 5 and 32
						// According to RFC3414 3.2.3b: stop processing and report
						// the listener authoritative engine ID
						atomic.AddUint32(&t.usmStatsUnknownEngineIDsCount, 1)
						err := t.reportAuthoritativeEngineID(trap, snmpEngineID, remote)
						if err != nil {
							t.Params.Logger.Printf("TrapListener: %s\n", err)
						}
						continue
					}
					// RFC3414 3.2.3a: Continue processing
				}
			}
			// Here we assume that t.OnNewTrap will not alter the contents
			// of the PDU (per documentation, because Go does not have
			// compile-time const checking).  We don't pass a copy because
			// the SnmpPacket type is somewhat large, but we could without
			// violating any implicit or explicit spec.
			t.OnNewTrap(trap, remote)

			// If it was an Inform request, we need to send a response.
			if trap.PDUType == InformRequest { //nolint:whitespace

				// Reuse the packet, since we're supposed to send it back
				// with the exact same variables unless there's an error.
				// Change the PDUType to the response, though.
				trap.PDUType = GetResponse

				// If the response can be sent, the error-status is
				// supposed to be set to noError and the error-index set to
				// zero.
				trap.Error = NoError
				trap.ErrorIndex = 0

				// TODO: Check that the message marshalled is not too large
				// for the originator to accept and if so, send a tooBig
				// error PDU per RFC3416 section 4.2.7.  This maximum size,
				// however, does not have a well-defined mechanism in the
				// RFC other than using the path MTU (which is difficult to
				// determine), so it's left to future implementations.
				err := t.SendUDP(trap, remote)
				if err != nil {
					t.Params.Logger.Printf("TrapListener: %s\n", err)
				}
			}
		}
	}
}

func (t *TrapListener) reportAuthoritativeEngineID(trap *SnmpPacket, snmpEngineID string, addr *net.UDPAddr) error {
	newSecurityParams, ok := trap.SecurityParameters.Copy().(*UsmSecurityParameters)
	if !ok {
		return errors.New("unable to cast SecurityParams to UsmSecurityParameters")
	}
	newSecurityParams.AuthoritativeEngineID = snmpEngineID
	reportPacket := trap
	reportPacket.PDUType = Report
	reportPacket.MsgFlags &= AuthPriv
	reportPacket.SecurityParameters = newSecurityParams
	reportPacket.Variables = []SnmpPDU{
		{
			Name:  usmStatsUnknownEngineIDs,
			Value: int(atomic.LoadUint32(&t.usmStatsUnknownEngineIDsCount)),
			Type:  Integer,
		},
	}
	return t.SendUDP(reportPacket, addr)
}

func (t *TrapListener) handleTCPRequest(conn net.Conn) {
	// Make a buffer to hold incoming data.
	buf := make([]byte, 4096)
	// Read the incoming connection into the buffer.
	reqLen, err := conn.Read(buf)
	if err != nil {
		t.Params.Logger.Printf("TrapListener: error in read %s\n", err)
		return
	}

	msg := buf[:reqLen]
	traps, err := t.Params.UnmarshalTrap(msg, false)
	if err != nil {
		t.Params.Logger.Printf("TrapListener: error in read %s\n", err)
		return
	}
	// TODO: lying for backward compatibility reason - create UDP Address ... not nice
	r, _ := net.ResolveUDPAddr("", conn.RemoteAddr().String())
	t.OnNewTrap(traps, r)
	// Close the connection when you're done with it.
	conn.Close()
}

func (t *TrapListener) listenTCP(addr string) error {
	tcpAddr, err := net.ResolveTCPAddr(t.proto, addr)
	if err != nil {
		return err
	}

	l, err := net.ListenTCP(tcp, tcpAddr)
	if err != nil {
		return err
	}

	defer l.Close()

	// Mark that we are listening now.
	t.listening <- true

	for {
		switch {
		case atomic.LoadInt32(&t.finish) == 1:
			t.done <- true
			return nil
		default:

			// Listen for an incoming connection.
			conn, err := l.Accept()
			fmt.Printf("ACCEPT: %s", conn)
			if err != nil {
				fmt.Println("error accepting: ", err.Error())
				return err
			}
			// Handle connections in a new goroutine.
			go t.handleTCPRequest(conn)
		}
	}
}

// Listen listens on the UDP address addr and calls the OnNewTrap
// function specified in *TrapListener for every trap received.
//
// NOTE: the trap code is currently unreliable when working with snmpv3 - pull requests welcome
func (t *TrapListener) Listen(addr string) error {
	if t.Params == nil {
		t.Params = Default
	}

	// TODO TODO returning an error cause the following to hang/break
	// TestSendTrapBasic
	// TestSendTrapWithoutWaitingOnListen
	// TestSendV1Trap
	_ = t.Params.validateParameters()

	if t.OnNewTrap == nil {
		t.OnNewTrap = t.debugTrapHandler
	}

	splitted := strings.SplitN(addr, "://", 2)
	t.proto = udp
	if len(splitted) > 1 {
		t.proto = splitted[0]
		addr = splitted[1]
	}

	switch t.proto {
	case tcp:
		return t.listenTCP(addr)
	case udp:
		return t.listenUDP(addr)
	default:
		return fmt.Errorf("not implemented network protocol: %s [use: tcp/udp]", t.proto)
	}
}

// Default trap handler
func (t *TrapListener) debugTrapHandler(s *SnmpPacket, u *net.UDPAddr) {
	t.Params.Logger.Printf("got trapdata from %+v: %+v\n", u, s)
}

// UnmarshalTrap unpacks the SNMP Trap.
//
// NOTE: the trap code is currently unreliable when working with snmpv3 - pull requests welcome
func (x *GoSNMP) UnmarshalTrap(trap []byte, useResponseSecurityParameters bool) (*SnmpPacket, error) {
	result := new(SnmpPacket)
	// Get only the version from the header of the trap
	_, err := x.unmarshalVersionFromHeader(trap, result)
	if err != nil {
		x.Logger.Printf("UnmarshalTrap version unmarshal: %s\n", err)
		return nil, err
	}
	// If there are multiple users configured and the SNMP trap is v3, see which user has valid credentials
	// by iterating through the list and seeing which credentials are authentic / can be used to decrypt
	if len(x.SecurityParametersMap) > 0 && result.Version == Version3 {
		secParamsList, err := x.getSecParamsList(trap)
		for _, secParams := range secParamsList {
			// Copy the trap and re-initialize the packet with new security parameters to unmarshal with
			cpTrap := make([]byte, len(trap))
			copy(cpTrap, trap)
			result = new(SnmpPacket)
			e := secParams.InitSecurityKeys()
			if e != nil {
				return nil, err
			}
			result.SecurityParameters = secParams.Copy()
			result, e = x.UnmarshalTrapBase(cpTrap, result, true)
			if result != nil {
				return result, e
			}
		}
		return nil, fmt.Errorf("No credentials successfully unmarshaled trap")
	}
	return x.UnmarshalTrapBase(trap, result, useResponseSecurityParameters)
}

func (x *GoSNMP) getSecParamsList(trap []byte) ([]SnmpV3SecurityParameters, error) {
	// Initialize a packet with no auth/priv to retrieve ID/key for security parameters to use
	cpResult := new(SnmpPacket)
	cpResult.MsgFlags = NoAuthNoPriv
	_, _ = x.unmarshalHeader(trap, cpResult)
	return x.SecurityParametersMap.getEntry(cpResult.SecurityParameters.getIdentifier())
}

func (x *GoSNMP) UnmarshalTrapBase(trap []byte, result *SnmpPacket, useResponseSecurityParameters bool) (*SnmpPacket, error) {
	if x.SecurityParameters != nil && result.SecurityParameters == nil {
		err := x.SecurityParameters.InitSecurityKeys()
		if err != nil {
			return nil, err
		}
		result.SecurityParameters = x.SecurityParameters.Copy()
	}

	cursor, err := x.unmarshalHeader(trap, result)
	if err != nil {
		x.Logger.Printf("UnmarshalTrap: %s\n", err)
		return nil, err
	}

	if result.Version == Version3 {
		if result.SecurityModel == UserSecurityModel {
			err = x.testAuthentication(trap, result, useResponseSecurityParameters)
			if err != nil {
				x.Logger.Printf("UnmarshalTrap v3 auth: %s\n", err)
				return nil, err
			}
		}

		trap, cursor, err = x.decryptPacket(trap, cursor, result)
		if err != nil {
			x.Logger.Printf("UnmarshalTrap v3 decrypt: %s\n", err)
			return nil, err
		}
	}
	err = x.unmarshalPayload(trap, cursor, result)
	if err != nil {
		x.Logger.Printf("UnmarshalTrap: %s\n", err)
		return nil, err
	}
	return result, nil
}
