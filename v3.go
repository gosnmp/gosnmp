// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
)

// SnmpV3MsgFlags contains various message flags to describe Authentication, Privacy, and whether a report PDU must be sent.
type SnmpV3MsgFlags uint8

// Possible values of SnmpV3MsgFlags
const (
	NoAuthNoPriv SnmpV3MsgFlags = 0x0 // No authentication, and no privacy
	AuthNoPriv   SnmpV3MsgFlags = 0x1 // Authentication and no privacy
	AuthPriv     SnmpV3MsgFlags = 0x3 // Authentication and privacy
	Reportable   SnmpV3MsgFlags = 0x4 // Report PDU must be sent.
)

//go:generate stringer -type=SnmpV3MsgFlags

// SnmpV3SecurityModel describes the security model used by a SnmpV3 connection
type SnmpV3SecurityModel uint8

// UserSecurityModel is the only SnmpV3SecurityModel currently implemented.
const (
	UserSecurityModel SnmpV3SecurityModel = 3
)

//go:generate stringer -type=SnmpV3SecurityModel

// SnmpV3SecurityParameters is a generic interface type to contain various implementations of SnmpV3SecurityParameters
type SnmpV3SecurityParameters interface {
	Log()
	Copy() SnmpV3SecurityParameters
	Description() string
	SafeString() string
	InitPacket(packet *SnmpPacket) error
	InitSecurityKeys() error
	validate(flags SnmpV3MsgFlags) error
	init(log Logger) error
	discoveryRequired() *SnmpPacket
	getDefaultContextEngineID() string
	setSecurityParameters(in SnmpV3SecurityParameters) error
	marshal(flags SnmpV3MsgFlags) ([]byte, error)
	unmarshal(flags SnmpV3MsgFlags, packet []byte, cursor int) (int, error)
	authenticate(packet []byte) error
	isAuthentic(packetBytes []byte, packet *SnmpPacket) (bool, error)
	encryptPacket(scopedPdu []byte) ([]byte, error)
	decryptPacket(packet []byte, cursor int) ([]byte, error)
	getIdentifier() string
	getLogger() Logger
	setLogger(log Logger)
}

func (x *GoSNMP) validateParametersV3() error {
	// update following code if you implement a new security model
	if x.SecurityModel != UserSecurityModel {
		return errors.New("the SNMPV3 User Security Model is the only SNMPV3 security model currently implemented")
	}
	if x.SecurityParameters == nil {
		return errors.New("SNMPV3 SecurityParameters must be set")
	}

	return x.SecurityParameters.validate(x.MsgFlags)
}

// authenticate the marshalled result of a snmp version 3 packet
func (packet *SnmpPacket) authenticate(msg []byte) ([]byte, error) {
	defer func() {
		if e := recover(); e != nil {
			var buf = make([]byte, 8192)
			runtime.Stack(buf, true)
			fmt.Printf("[v3::authenticate]recover: %v. Stack=%v\n", e, string(buf))
		}
	}()
	if packet.Version != Version3 {
		return msg, nil
	}
	if packet.MsgFlags&AuthNoPriv > 0 {
		err := packet.SecurityParameters.authenticate(msg)
		if err != nil {
			return nil, err
		}
	}

	return msg, nil
}

func (x *GoSNMP) testAuthentication(packet []byte, result *SnmpPacket, useResponseSecurityParameters bool) error {
	if x.Version != Version3 {
		return fmt.Errorf("testAuthentication called with non Version3 connection")
	}
	msgFlags := x.MsgFlags
	if useResponseSecurityParameters {
		msgFlags = result.MsgFlags
	}

	// Special case for Engine Discovery (RFC3414 section 4) where we should
	// skip authentication for the discovery packet with the special settings
	// described in the RFC. The discovery package requires
	msgSecParams := result.SecurityParameters.(*UsmSecurityParameters)
	if msgFlags&NoAuthNoPriv == 0 && // NoAuthNoPriv method
		msgSecParams.UserName == "" && // empty username
		msgSecParams.AuthoritativeEngineID == "" && // empty authoritative engine ID
		len(result.Variables) == 0 { // empty variable binding list
		return nil
	}

	if msgFlags&AuthNoPriv > 0 {
		var authentic bool
		var err error
		if useResponseSecurityParameters {
			authentic, err = result.SecurityParameters.isAuthentic(packet, result)
		} else {
			authentic, err = x.SecurityParameters.isAuthentic(packet, result)
		}
		if err != nil {
			return err
		}
		if !authentic {
			return fmt.Errorf("incoming packet is not authentic, discarding")
		}
	}

	return nil
}

func (x *GoSNMP) initPacket(packetOut *SnmpPacket) error {
	if x.MsgFlags&AuthPriv > AuthNoPriv {
		return x.SecurityParameters.InitPacket(packetOut)
	}

	return nil
}

// http://tools.ietf.org/html/rfc2574#section-2.2.3 This code does not
// check if the last message received was more than 150 seconds ago The
// snmpds that this code was tested on emit an 'out of time window'
// error with the new time and this code will retransmit when that is
// received.
func (x *GoSNMP) negotiateInitialSecurityParameters(packetOut *SnmpPacket) error {
	if x.Version != Version3 || packetOut.Version != Version3 {
		return fmt.Errorf("negotiateInitialSecurityParameters called with non Version3 connection or packet")
	}

	if x.SecurityModel != packetOut.SecurityModel {
		return fmt.Errorf("connection security model does not match security model defined in packet")
	}

	if discoveryPacket := packetOut.SecurityParameters.discoveryRequired(); discoveryPacket != nil {
		discoveryPacket.ContextName = x.ContextName
		result, err := x.sendOneRequest(discoveryPacket, true)

		if err != nil {
			return err
		}

		err = x.storeSecurityParameters(result)
		if err != nil {
			return err
		}

		err = x.updatePktSecurityParameters(packetOut)
		if err != nil {
			return err
		}
	} else {
		err := packetOut.SecurityParameters.InitSecurityKeys()
		if err == nil {
			return err
		}
	}

	return nil
}

// save the connection security parameters after a request/response
func (x *GoSNMP) storeSecurityParameters(result *SnmpPacket) error {
	if x.Version != Version3 || result.Version != Version3 {
		return fmt.Errorf("storeParameters called with non Version3 connection or packet")
	}

	if x.SecurityModel != result.SecurityModel {
		return fmt.Errorf("connection security model does not match security model extracted from packet")
	}

	if x.ContextEngineID == "" {
		x.ContextEngineID = result.SecurityParameters.getDefaultContextEngineID()
	}

	return x.SecurityParameters.setSecurityParameters(result.SecurityParameters)
}

// update packet security parameters to match connection security parameters
func (x *GoSNMP) updatePktSecurityParameters(packetOut *SnmpPacket) error {
	if x.Version != Version3 || packetOut.Version != Version3 {
		return fmt.Errorf("updatePktSecurityParameters called with non Version3 connection or packet")
	}

	if x.SecurityModel != packetOut.SecurityModel {
		return fmt.Errorf("connection security model does not match security model extracted from packet")
	}

	err := packetOut.SecurityParameters.setSecurityParameters(x.SecurityParameters)
	if err != nil {
		return err
	}

	if packetOut.ContextEngineID == "" {
		packetOut.ContextEngineID = x.ContextEngineID
	}

	return nil
}

func (packet *SnmpPacket) marshalV3(buf *bytes.Buffer) (*bytes.Buffer, error) {
	emptyBuffer := new(bytes.Buffer) // used when returning errors

	header, err := packet.marshalV3Header()
	if err != nil {
		return emptyBuffer, err
	}
	buf.Write([]byte{byte(Sequence), byte(len(header))})
	packet.Logger.Printf("Marshal V3 Header len=%d. Eaten Last 4 Bytes=%v", len(header), header[len(header)-4:])
	buf.Write(header)

	var securityParameters []byte
	securityParameters, err = packet.SecurityParameters.marshal(packet.MsgFlags)
	if err != nil {
		return emptyBuffer, err
	}
	packet.Logger.Printf("Marshal V3 SecurityParameters len=%d. Eaten Last 4 Bytes=%v",
		len(securityParameters), securityParameters[len(securityParameters)-4:])

	buf.Write([]byte{byte(OctetString)})
	secParamLen, err := marshalLength(len(securityParameters))
	if err != nil {
		return emptyBuffer, err
	}
	buf.Write(secParamLen)
	buf.Write(securityParameters)

	scopedPdu, err := packet.marshalV3ScopedPDU()
	if err != nil {
		return emptyBuffer, err
	}
	buf.Write(scopedPdu)
	return buf, nil
}

// marshal a snmp version 3 packet header
func (packet *SnmpPacket) marshalV3Header() ([]byte, error) {
	buf := new(bytes.Buffer)

	// msg id
	buf.Write([]byte{byte(Integer), 4})
	err := binary.Write(buf, binary.BigEndian, packet.MsgID)
	if err != nil {
		return nil, err
	}
	oldLen := 0
	packet.Logger.Printf("MarshalV3Header msgID len=%v", buf.Len()-oldLen)
	oldLen = buf.Len()
	// maximum response msg size
	var maxBufSize uint32 = rxBufSize
	if packet.MsgMaxSize != 0 {
		maxBufSize = packet.MsgMaxSize
	}
	maxmsgsize, err := marshalUint32(maxBufSize)
	if err != nil {
		return nil, err
	}
	buf.Write([]byte{byte(Integer), byte(len(maxmsgsize))})
	buf.Write(maxmsgsize)
	packet.Logger.Printf("MarshalV3Header maxmsgsize len=%v", buf.Len()-oldLen)
	oldLen = buf.Len()

	// msg flags
	buf.Write([]byte{byte(OctetString), 1, byte(packet.MsgFlags)})

	packet.Logger.Printf("MarshalV3Header msg flags len=%v", buf.Len()-oldLen)
	oldLen = buf.Len()

	// msg security model
	buf.Write([]byte{byte(Integer), 1, byte(packet.SecurityModel)})

	packet.Logger.Printf("MarshalV3Header msg security model len=%v", buf.Len()-oldLen)

	return buf.Bytes(), nil
}

// marshal and encrypt (if necessary) a snmp version 3 Scoped PDU
func (packet *SnmpPacket) marshalV3ScopedPDU() ([]byte, error) {
	var b []byte

	scopedPdu, err := packet.prepareV3ScopedPDU()
	if err != nil {
		return nil, err
	}
	pduLen, err := marshalLength(len(scopedPdu))
	if err != nil {
		return nil, err
	}
	b = append([]byte{byte(Sequence)}, pduLen...)
	scopedPdu = append(b, scopedPdu...)
	if packet.MsgFlags&AuthPriv > AuthNoPriv {
		scopedPdu, err = packet.SecurityParameters.encryptPacket(scopedPdu)
		if err != nil {
			return nil, err
		}
	}

	return scopedPdu, nil
}

// prepare the plain text of a snmp version 3 Scoped PDU
func (packet *SnmpPacket) prepareV3ScopedPDU() ([]byte, error) {
	var buf bytes.Buffer

	// ContextEngineID
	idlen, err := marshalLength(len(packet.ContextEngineID))
	if err != nil {
		return nil, err
	}
	buf.Write(append([]byte{byte(OctetString)}, idlen...))
	buf.WriteString(packet.ContextEngineID)

	// ContextName
	namelen, err := marshalLength(len(packet.ContextName))
	if err != nil {
		return nil, err
	}
	buf.Write(append([]byte{byte(OctetString)}, namelen...))
	buf.WriteString(packet.ContextName)

	data, err := packet.marshalPDU()
	if err != nil {
		return nil, err
	}
	buf.Write(data)
	return buf.Bytes(), nil
}

func (x *GoSNMP) unmarshalV3Header(packet []byte,
	cursor int,
	response *SnmpPacket) (int, error) {
	if PDUType(packet[cursor]) != Sequence {
		return 0, fmt.Errorf("invalid SNMPV3 Header")
	}

	_, cursorTmp, err := parseLength(packet[cursor:])
	if err != nil {
		return 0, err
	}
	cursor += cursorTmp
	if cursor > len(packet) {
		return 0, errors.New("error parsing SNMPV3 message ID: truncted packet")
	}

	rawMsgID, count, err := parseRawField(x.Logger, packet[cursor:], "msgID")
	if err != nil {
		return 0, fmt.Errorf("error parsing SNMPV3 message ID: %w", err)
	}
	cursor += count
	if cursor > len(packet) {
		return 0, errors.New("error parsing SNMPV3 message ID: truncted packet")
	}

	if MsgID, ok := rawMsgID.(int); ok {
		response.MsgID = uint32(MsgID) //nolint:gosec
		x.Logger.Printf("Parsed message ID %d", MsgID)
	}

	rawMsgMaxSize, count, err := parseRawField(x.Logger, packet[cursor:], "msgMaxSize")
	if err != nil {
		return 0, fmt.Errorf("error parsing SNMPV3 msgMaxSize: %w", err)
	}
	cursor += count
	if cursor > len(packet) {
		return 0, errors.New("error parsing SNMPV3 message ID: truncted packet")
	}

	if MsgMaxSize, ok := rawMsgMaxSize.(int); ok {
		response.MsgMaxSize = uint32(MsgMaxSize) //nolint:gosec
		x.Logger.Printf("Parsed message max size %d", MsgMaxSize)
	}

	rawMsgFlags, count, err := parseRawField(x.Logger, packet[cursor:], "msgFlags")
	if err != nil {
		return 0, fmt.Errorf("error parsing SNMPV3 msgFlags: %w", err)
	}
	cursor += count
	if cursor > len(packet) {
		return 0, errors.New("error parsing SNMPV3 message ID: truncted packet")
	}

	if MsgFlags, ok := rawMsgFlags.(string); ok && len(MsgFlags) > 0 {
		response.MsgFlags = SnmpV3MsgFlags(MsgFlags[0])
		x.Logger.Printf("parsed msg flags %s", MsgFlags)
	}

	rawSecModel, count, err := parseRawField(x.Logger, packet[cursor:], "msgSecurityModel")
	if err != nil {
		return 0, fmt.Errorf("error parsing SNMPV3 msgSecModel: %w", err)
	}
	cursor += count
	if cursor >= len(packet) {
		return 0, errors.New("error parsing SNMPV3 message ID: truncted packet")
	}

	if SecModel, ok := rawSecModel.(int); ok {
		response.SecurityModel = SnmpV3SecurityModel(SecModel) //nolint:gosec
		x.Logger.Printf("Parsed security model %d", SecModel)
	}

	if PDUType(packet[cursor]) != PDUType(OctetString) {
		return 0, errors.New("invalid SNMPV3 Security Parameters")
	}
	_, cursorTmp, err = parseLength(packet[cursor:])
	if err != nil {
		return 0, err
	}
	cursor += cursorTmp
	if cursor > len(packet) {
		return 0, errors.New("error parsing SNMPV3 message ID: truncted packet")
	}
	if response.SecurityParameters == nil {
		response.SecurityParameters = &UsmSecurityParameters{Logger: x.Logger}
	}

	cursor, err = response.SecurityParameters.unmarshal(response.MsgFlags, packet, cursor)
	if err != nil {
		return 0, err
	}
	x.Logger.Printf("Parsed Security Parameters. now offset=%v,", cursor)

	return cursor, nil
}

func (x *GoSNMP) decryptPacket(packet []byte, cursor int, response *SnmpPacket) ([]byte, int, error) {
	var err error
	var decrypted = false

	if cursor >= len(packet) {
		return nil, 0, errors.New("error parsing SNMPV3: truncated packet")
	}

	switch PDUType(packet[cursor]) {
	case PDUType(OctetString):
		// pdu is encrypted
		packet, err = response.SecurityParameters.decryptPacket(packet, cursor)
		if err != nil {
			return nil, 0, err
		}
		decrypted = true
		fallthrough
	case Sequence:
		// pdu is plaintext or has been decrypted
		tlength, cursorTmp, err := parseLength(packet[cursor:])
		if err != nil {
			return nil, 0, err
		}
		if decrypted {
			// truncate padding that might have been included with
			// the encrypted PDU
			if cursor+tlength > len(packet) {
				return nil, 0, errors.New("error parsing SNMPV3: truncated packet")
			}
			packet = packet[:cursor+tlength]
		}
		cursor += cursorTmp
		if cursor > len(packet) {
			return nil, 0, errors.New("error parsing SNMPV3: truncated packet")
		}

		rawContextEngineID, count, err := parseRawField(x.Logger, packet[cursor:], "contextEngineID")
		if err != nil {
			return nil, 0, fmt.Errorf("error parsing SNMPV3 contextEngineID: %w", err)
		}
		cursor += count
		if cursor > len(packet) {
			return nil, 0, errors.New("error parsing SNMPV3: truncated packet")
		}

		if contextEngineID, ok := rawContextEngineID.(string); ok {
			response.ContextEngineID = contextEngineID
			x.Logger.Printf("Parsed contextEngineID %s", contextEngineID)
		}
		rawContextName, count, err := parseRawField(x.Logger, packet[cursor:], "contextName")
		if err != nil {
			return nil, 0, fmt.Errorf("error parsing SNMPV3 contextName: %w", err)
		}
		cursor += count
		if cursor > len(packet) {
			return nil, 0, errors.New("error parsing SNMPV3: truncated packet")
		}

		if contextName, ok := rawContextName.(string); ok {
			response.ContextName = contextName
			x.Logger.Printf("Parsed contextName %s", contextName)
		}

	default:
		return nil, 0, errors.New("error parsing SNMPV3 scoped PDU")
	}
	return packet, cursor, nil
}
