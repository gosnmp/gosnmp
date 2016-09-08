package gosnmp

// Copyright 2012-2016 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"
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

// SnmpV3SecurityModel describes the security model used by a SnmpV3 connection
type SnmpV3SecurityModel uint8

// UserSecurityModel is the only SnmpV3SecurityModel currently implemented.
const (
	UserSecurityModel SnmpV3SecurityModel = 3
)

// SnmpV3SecurityParameters is a generic interface type to contain various implementations of SnmpV3SecurityParameters
type SnmpV3SecurityParameters interface {
	Copy() SnmpV3SecurityParameters
	validate(flags SnmpV3MsgFlags) error
	init(log Logger) error
	initPacket(packet *SnmpPacket) error
	marshal(flags SnmpV3MsgFlags) ([]byte, uint32, error)
	unmarshal(flags SnmpV3MsgFlags, packet []byte, cursor int) (int, error)
	encryptPacket(scopedPdu []byte) ([]byte, error)
	decryptPacket(packet []byte, cursor int) ([]byte, error)
}

func (x *GoSNMP) validateParametersV3() error {
	// update following code if you implement a new security model
	if x.SecurityModel != UserSecurityModel {
		return fmt.Errorf("The SNMPV3 User Security Model is the only SNMPV3 security model currently implemented")
	}

	return x.SecurityParameters.validate(x.MsgFlags)
}

// authenticate the marshalled result of a snmp version 3 packet
func (packet *SnmpPacket) authenticate(msg []byte, authParamStart uint32) ([]byte, error) {
	defer func() {
		if e := recover(); e != nil {
			fmt.Printf("recover: %v\n", e)
		}
	}()
	if packet.Version != Version3 {
		return msg, nil
	}
	if packet.MsgFlags&AuthNoPriv == 0 {
		return msg, nil
	}
	if packet.SecurityModel != UserSecurityModel {
		return nil, fmt.Errorf("Error authenticating message: Unknown security model.")
	}

	var secParams *UsmSecurityParameters
	var err error

	if secParams, err = castUsmSecParams(packet.SecurityParameters); err != nil {
		return nil, err
	}
	var secretKey = genlocalkey(secParams.AuthenticationProtocol,
		secParams.AuthenticationPassphrase,
		secParams.AuthoritativeEngineID)

	var extkey [64]byte

	copy(extkey[:], secretKey)

	var k1, k2 [64]byte

	for i := 0; i < 64; i++ {
		k1[i] = extkey[i] ^ 0x36
		k2[i] = extkey[i] ^ 0x5c
	}

	var h, h2 hash.Hash

	switch secParams.AuthenticationProtocol {
	default:
		h = md5.New()
		h2 = md5.New()
	case SHA:
		h = sha1.New()
		h2 = sha1.New()
	}

	h.Write(k1[:])
	h.Write(msg)
	d1 := h.Sum(nil)
	h2.Write(k2[:])
	h2.Write(d1)
	copy(msg[authParamStart:authParamStart+12], h2.Sum(nil)[:12])
	return msg, nil
}

func (x *GoSNMP) testUsmAuthentication(packet []byte, result *SnmpPacket) error {
	if x.Version != Version3 {
		return fmt.Errorf("testUsmAuthentication called with non Version3 connection")
	}

	if x.SecurityModel != UserSecurityModel {
		return fmt.Errorf("testUsmAuthentication called with connection that is not using the User Security Model")
	}

	var secParameters *UsmSecurityParameters
	var err error

	if secParameters, err = castUsmSecParams(x.SecurityParameters); err != nil {
		return err
	}

	var resultSecParams *UsmSecurityParameters

	if resultSecParams, err = castUsmSecParams(result.SecurityParameters); err != nil {
		return err
	}

	if x.MsgFlags&AuthNoPriv > 0 {
		if !isAuthentic(packet, resultSecParams.AuthenticationParameters,
			secParameters.AuthenticationProtocol,
			secParameters.AuthenticationPassphrase,
			secParameters.AuthoritativeEngineID) {
			return fmt.Errorf("Incoming packet is not authentic, discarding")
		}
	}

	return nil
}

// determine whether a message is authentic
func isAuthentic(msg []byte, authParams string, authProtocol SnmpV3AuthProtocol, authPassphrase string, authEngineID string) bool {
	var secretKey = genlocalkey(authProtocol,
		authPassphrase,
		authEngineID)

	var extkey [64]byte

	copy(extkey[:], secretKey)

	var k1, k2 [64]byte

	for i := 0; i < 64; i++ {
		k1[i] = extkey[i] ^ 0x36
		k2[i] = extkey[i] ^ 0x5c
	}

	var h, h2 hash.Hash

	switch authProtocol {
	default:
		h = md5.New()
		h2 = md5.New()
	case SHA:
		h = sha1.New()
		h2 = sha1.New()
	}

	h.Write(k1[:])
	h.Write(msg)
	d1 := h.Sum(nil)
	h2.Write(k2[:])
	h2.Write(d1)

	result := h2.Sum(nil)[:12]
	for k, v := range []byte(authParams) {
		if result[k] != v {
			return false
		}
	}
	return true
}

func (x *GoSNMP) initPacket(packetOut *SnmpPacket) error {

	if x.MsgFlags&AuthPriv > AuthNoPriv {
		return x.SecurityParameters.initPacket(packetOut)
	}

	return nil
}

// http://tools.ietf.org/html/rfc2574#section-2.2.3 This code does not
// check if the last message received was more than 150 seconds ago The
// snmpds that this code was tested on emit an 'out of time window'
// error with the new time and this code will retransmit when that is
// received.
func (x *GoSNMP) negotiateInitialSecurityParameters(packetOut *SnmpPacket, wait bool) error {
	if x.Version != Version3 || packetOut.Version != Version3 {
		return fmt.Errorf("negotiateInitialSecurityParameters called with non Version3 connection or packet")
	}

	if x.SecurityModel != packetOut.SecurityModel {
		return fmt.Errorf("connection security model does not match security model defined in packet")
	}

	if packetOut.SecurityModel == UserSecurityModel {
		var secParams *UsmSecurityParameters
		var err error

		if secParams, err = castUsmSecParams(packetOut.SecurityParameters); err != nil {
			return err
		}

		if secParams.AuthoritativeEngineID == "" {
			var emptyPdus []SnmpPDU

			// send blank packet to discover authoriative engine ID/boots/time
			blankPacket := &SnmpPacket{
				Version:            Version3,
				MsgFlags:           Reportable | NoAuthNoPriv,
				SecurityModel:      UserSecurityModel,
				SecurityParameters: &UsmSecurityParameters{Logger: x.Logger},
				PDUType:            GetRequest,
				Logger:             x.Logger,
				Variables:          emptyPdus,
			}
			result, err := x.sendOneRequest(blankPacket, wait)

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

	if result.SecurityModel == UserSecurityModel {
		var newSecParams *UsmSecurityParameters
		var err error

		if newSecParams, err = castUsmSecParams(result.SecurityParameters); err != nil {
			return err
		}
		connSecParams, _ := x.SecurityParameters.(*UsmSecurityParameters)
		if connSecParams != nil {
			connSecParams.AuthoritativeEngineID = newSecParams.AuthoritativeEngineID
			connSecParams.AuthoritativeEngineBoots = newSecParams.AuthoritativeEngineBoots
			connSecParams.AuthoritativeEngineTime = newSecParams.AuthoritativeEngineTime
		}
		if x.ContextEngineID == "" {
			x.ContextEngineID = newSecParams.AuthoritativeEngineID
		}
	}

	return nil

}

// update packet security parameters to match connection security parameters
func (x *GoSNMP) updatePktSecurityParameters(packetOut *SnmpPacket) error {
	if x.Version != Version3 || packetOut.Version != Version3 {
		return fmt.Errorf("updatePktSecurityParameters called with non Version3 connection or packet")
	}

	if x.SecurityModel != packetOut.SecurityModel {
		return fmt.Errorf("connection security model does not match security model extracted from packet")
	}

	if x.SecurityModel == UserSecurityModel {
		var c *UsmSecurityParameters
		var err error
		if c, err = castUsmSecParams(x.SecurityParameters); err != nil {
			return err
		}

		var s *UsmSecurityParameters
		if s, err = castUsmSecParams(packetOut.SecurityParameters); err != nil {
			return err
		}

		s.AuthoritativeEngineID = c.AuthoritativeEngineID
		s.AuthoritativeEngineBoots = c.AuthoritativeEngineBoots
		s.AuthoritativeEngineTime = c.AuthoritativeEngineTime

	}

	if packetOut.ContextEngineID == "" {
		packetOut.ContextEngineID = x.ContextEngineID
	}

	return nil
}

func (packet *SnmpPacket) marshalV3(buf *bytes.Buffer) (*bytes.Buffer, uint32, error) {

	emptyBuffer := new(bytes.Buffer) // used when returning errors
	var authParamStart uint32

	header, err := packet.marshalV3Header()
	if err != nil {
		return emptyBuffer, 0, err
	}
	buf.Write([]byte{byte(Sequence), byte(len(header))})
	buf.Write(header)

	var securityParameters []byte
	securityParameters, authParamStart, err = packet.SecurityParameters.marshal(packet.MsgFlags)
	if err != nil {
		return emptyBuffer, 0, err
	}

	buf.Write([]byte{byte(OctetString)})
	secParamLen, err := marshalLength(len(securityParameters))
	if err != nil {
		return emptyBuffer, 0, err
	}
	buf.Write(secParamLen)
	authParamStart += uint32(buf.Len())
	buf.Write(securityParameters)

	scopedPdu, err := packet.marshalV3ScopedPDU()
	if err != nil {
		return emptyBuffer, 0, err
	}
	buf.Write(scopedPdu)
	return buf, authParamStart, nil
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

	// maximum response msg size
	maxmsgsize := marshalUvarInt(rxBufSize)
	buf.Write([]byte{byte(Integer), byte(len(maxmsgsize))})
	buf.Write(maxmsgsize)

	// msg flags
	buf.Write([]byte{byte(OctetString), 1, byte(packet.MsgFlags)})

	// msg security model
	buf.Write([]byte{byte(Integer), 1, byte(packet.SecurityModel)})

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

	//ContextEngineID
	idlen, err := marshalLength(len(packet.ContextEngineID))
	if err != nil {
		return nil, err
	}
	buf.Write(append([]byte{byte(OctetString)}, idlen...))
	buf.WriteString(packet.ContextEngineID)

	//ContextName
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
		return 0, fmt.Errorf("Invalid SNMPV3 Header\n")
	}

	_, cursorTmp := parseLength(packet[cursor:])
	cursor += cursorTmp

	rawMsgID, count, err := parseRawField(packet[cursor:], "msgID")
	if err != nil {
		return 0, fmt.Errorf("Error parsing SNMPV3 message ID: %s", err.Error())
	}
	cursor += count
	if MsgID, ok := rawMsgID.(int); ok {
		response.MsgID = uint32(MsgID)
		x.logPrintf("Parsed message ID %d", MsgID)
	}
	// discard msg max size
	_, count, err = parseRawField(packet[cursor:], "maxMsgSize")
	if err != nil {
		return 0, fmt.Errorf("Error parsing SNMPV3 maxMsgSize: %s", err.Error())
	}
	cursor += count
	// discard msg max size

	rawMsgFlags, count, err := parseRawField(packet[cursor:], "msgFlags")
	if err != nil {
		return 0, fmt.Errorf("Error parsing SNMPV3 msgFlags: %s", err.Error())
	}
	cursor += count
	if MsgFlags, ok := rawMsgFlags.(string); ok {
		response.MsgFlags = SnmpV3MsgFlags(MsgFlags[0])
		x.logPrintf("parsed msg flags %s", MsgFlags)
	}

	rawSecModel, count, err := parseRawField(packet[cursor:], "msgSecurityModel")
	if err != nil {
		return 0, fmt.Errorf("Error parsing SNMPV3 msgSecModel: %s", err.Error())
	}
	cursor += count
	if SecModel, ok := rawSecModel.(int); ok {
		response.SecurityModel = SnmpV3SecurityModel(SecModel)
		x.logPrintf("Parsed security model %d", SecModel)
	}

	if PDUType(packet[cursor]) != OctetString {
		return 0, fmt.Errorf("Invalid SNMPV3 Security Parameters\n")
	}
	_, cursorTmp = parseLength(packet[cursor:])
	cursor += cursorTmp

	cursor, err = response.SecurityParameters.unmarshal(response.MsgFlags, packet, cursor)
	if err != nil {
		return 0, err
	}
	return cursor, nil
}

func (x *GoSNMP) decryptPacket(packet []byte, cursor int, response *SnmpPacket) ([]byte, int, error) {
	var err error
	switch PDUType(packet[cursor]) {
	case OctetString:
		// pdu is encrypted
		packet, err = response.SecurityParameters.decryptPacket(packet, cursor)
		if err != nil {
			return nil, 0, err
		}
		fallthrough
	case Sequence:
		// pdu is plaintext
		tlength, cursorTmp := parseLength(packet[cursor:])
		// truncate padding that may have been included with
		// the encrypted PDU
		packet = packet[:cursor+tlength]
		cursor += cursorTmp
		rawContextEngineID, count, err := parseRawField(packet[cursor:], "contextEngineID")
		if err != nil {
			return nil, 0, fmt.Errorf("Error parsing SNMPV3 contextEngineID: %s", err.Error())
		}
		cursor += count
		if contextEngineID, ok := rawContextEngineID.(string); ok {
			response.ContextEngineID = contextEngineID
			x.logPrintf("Parsed contextEngineID %s", contextEngineID)
		}
		rawContextName, count, err := parseRawField(packet[cursor:], "contextName")
		if err != nil {
			return nil, 0, fmt.Errorf("Error parsing SNMPV3 contextName: %s", err.Error())
		}
		cursor += count
		if contextName, ok := rawContextName.(string); ok {
			response.ContextName = contextName
			x.logPrintf("Parsed contextName %s", contextName)
		}

	default:
		return nil, 0, fmt.Errorf("Error parsing SNMPV3 scoped PDU\n")
	}
	return packet, cursor, nil
}
