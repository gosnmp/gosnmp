// Copyright 2012 Andreas Louca and Jon Auer, 2013 Sonia Hamilton. All
// rights reserved.  Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"bytes"
	"fmt"
	l "github.com/alouca/gologger"
	"math"
	"math/big"
	"strconv"
	"strings"
)

type MessageType byte

const (
	Sequence       MessageType = 0x30
	GetRequest     MessageType = 0xa0
	GetNextRequest             = 0xa1
	GetResponse                = 0xa2
	SetRequest                 = 0xa3
	Trap                       = 0xa4
	GetBulkRequest             = 0xa5
)

type SnmpVersion uint8

const (
	Version1  SnmpVersion = 0x0
	Version2c SnmpVersion = 0x1
)

func (s SnmpVersion) String() string {
	if s == Version1 {
		return "1"
	} else if s == Version2c {
		return "2c"
	}
	return "U"
}

type SnmpPacket struct {
	Version     SnmpVersion
	Community   string
	RequestType MessageType
	RequestID   uint8
	Error       uint8
	ErrorIndex  uint8
	Variables   []SnmpPDU
}

type SnmpPDU struct {
	Name  string
	Type  Asn1BER
	Value interface{}
}

func Unmarshal(packet []byte) (*SnmpPacket, error) {
	log := l.GetDefaultLogger()
	//var err error
	response := new(SnmpPacket)
	response.Variables = make([]SnmpPDU, 0, 5)

	// Start parsing the packet
	cursor := 0

	// First bytes should be 0x30
	if MessageType(packet[0]) != Sequence {
		return nil, fmt.Errorf("Invalid packet header\n")
	}

	length, cursor := calc_length(packet)
	if len(packet) != length {
		return nil, fmt.Errorf("Error verifying packet sanity: Got %d Expected: %d\n", len(packet), length)
	}
	log.Debug("Packet sanity verified, we got all the bytes (%d)", length)

	// Parse SNMP Version
	rawVersion, count, err := parseRawField(packet[cursor:], log, "version")
	if err != nil {
		return nil, fmt.Errorf("Error parsing SNMP packet version: %s", err.Error())
	}

	cursor += count
	if version, ok := rawVersion.(int); ok {
		response.Version = SnmpVersion(version)
		log.Debug("Parsed version %d", version)
	}

	// Parse community
	rawCommunity, count, err := parseRawField(packet[cursor:], log, "community")
	cursor += count
	if community, ok := rawCommunity.(string); ok {
		response.Community = community
		log.Debug("Parsed community %s", community)
	}

	// Parse SNMP packet type
	switch MessageType(packet[cursor]) {
	case GetResponse:
		response, err = unmarshalGetResponse(packet[cursor:], response, log, length)
	default:
		return nil, fmt.Errorf("Unknown MessageType %#x")
	}

	return response, nil
}

func unmarshalGetResponse(packet []byte, response *SnmpPacket, log *l.Logger, length int) (*SnmpPacket, error) {
	cursor := 0
	log.Debug("SNMP Packet is GET RESPONSE, bytes are: % #x...", packet[:10])
	response.RequestType = GetResponse

	getresponse_length, cursor := calc_length(packet)
	if len(packet) != getresponse_length {
		return nil, fmt.Errorf("Error verifying GetResponse sanity: Got %d Expected: %d\n", len(packet), getresponse_length)
	}
	log.Debug("getresponse_length: %d", getresponse_length)

	// Parse Request-ID
	rawRequestId, count, err := parseRawField(packet[cursor:], log, "request id")
	if err != nil {
		return nil, fmt.Errorf("Error parsing SNMP packet request ID: %s", err.Error())
	}
	cursor += count
	if requestid, ok := rawRequestId.(int); ok {
		response.RequestID = uint8(requestid)
		log.Debug("request-id: %d", uint8(requestid))
	}

	// Parse Error-Status
	rawError, count, err := parseRawField(packet[cursor:], log, "error-status")
	if err != nil {
		return nil, fmt.Errorf("Error parsing SNMP packet error: %s", err.Error())
	}
	cursor += count
	if error_status, ok := rawError.(int); ok {
		response.Error = uint8(error_status)
		log.Debug("error-status: %d", uint8(error_status))
	}

	// Parse Error-Index
	rawErrorIndex, count, err := parseRawField(packet[cursor:], log, "error index")
	if err != nil {
		return nil, fmt.Errorf("Error parsing SNMP packet error index: %s", err.Error())
	}
	cursor += count
	if errorindex, ok := rawErrorIndex.(int); ok {
		response.ErrorIndex = uint8(errorindex)
		log.Debug("error-index: %d", uint8(errorindex))
	}

	return unmarshalVBL(packet[cursor:], response, log, length)
}

// unmarshal a Varbind list
func unmarshalVBL(packet []byte, response *SnmpPacket, log *l.Logger, length int) (*SnmpPacket, error) {
	cursor := 0
	log.Debug("unmarshalVBL(), bytes are: % #x...", packet[:10])
	if packet[cursor] != 0x30 {
		return nil, fmt.Errorf("Expected a sequence when unmarshalling a VBL, got %x", packet[cursor])
	}

	vbl_length, cursor := calc_length(packet)
	if len(packet) != vbl_length {
		return nil, fmt.Errorf("Error verifying GetResponse sanity: Got %d Expected: %d\n", len(packet), vbl_length)
	}
	log.Debug("vbl_length: %d", vbl_length)

	// Loop & parse Varbinds
	// for cursor < vbl_length { // TODO hack - range error "packet[cursor] != 0x30"
	if packet[cursor] != 0x30 {
		return nil, fmt.Errorf("Expected a sequence when unmarshalling a VB, got %x", packet[cursor])
	}
	packet = packet[cursor:]
	_, cursor = calc_length(packet)

	// Parse OID
	rawOid, oid_length, err := parseRawField(packet[cursor:], log, "OID")
	if err != nil {
		return nil, fmt.Errorf("Error parsing OID Value: %s", err.Error())
	}
	log.Debug("OID (%v) Field was %d bytes", rawOid, oid_length)
	cursor += oid_length

	var oid []int
	var ok bool
	if oid, ok = rawOid.([]int); !ok {
		return nil, fmt.Errorf("unable to type assert rawOid |%v| to []int", rawOid)
	}

	// Parse Value
	v, err := decodeValue(packet[cursor:], log, "value")
	response.Variables = append(response.Variables, SnmpPDU{oidToString(oid), v.Type, v.Value})
	return response, nil
}

func parseRawField(data []byte, log *l.Logger, msg string) (interface{}, int, error) {
	log.Debug("%s: parseRawField got bytes: % #x...", msg, data[:10])
	switch Asn1BER(data[0]) {
	case Integer:
		length := int(data[1])
		if length == 1 {
			return int(data[2]), 3, nil
		} else {
			resp, err := parseInt(data[2:(1 + length)])
			return resp, 2 + length, err
		}
	case OctetString:
		//length := int(data[1])
		length, cursor := calc_length(data)
		return string(data[cursor:length]), length, nil
	case ObjectIdentifier:
		length := int(data[1])
		oid, err := parseObjectIdentifier(data[2 : 2+length])
		return oid, length + 2, err
	default:
		return nil, 0, fmt.Errorf("Unknown field type: %x\n", data[0])
	}

	return nil, 0, nil
}

func (packet *SnmpPacket) marshal() ([]byte, error) {
	// Prepare the buffer to send
	buffer := make([]byte, 0, 1024)
	buf := bytes.NewBuffer(buffer)

	// Write the packet header (Message type 0x30) & Version = 2
	buf.Write([]byte{byte(Sequence), 0, 2, 1, byte(packet.Version)})

	// Write Community
	buf.Write([]byte{4, uint8(len(packet.Community))})
	buf.WriteString(packet.Community)

	// Marshal the SNMP PDU
	snmpPduBuffer := make([]byte, 0, 1024)
	snmpPduBuf := bytes.NewBuffer(snmpPduBuffer)

	snmpPduBuf.Write([]byte{byte(packet.RequestType), 0, 2, 1, packet.RequestID, 2, 1, packet.Error, 2, 1, packet.ErrorIndex, byte(Sequence), 0})

	pduLength := 0
	for _, varlist := range packet.Variables {
		pdu, err := marshalPDU(&varlist)

		if err != nil {
			return nil, err
		}
		pduLength += len(pdu)
		snmpPduBuf.Write(pdu)
	}

	pduBytes := snmpPduBuf.Bytes()
	// Varbind list length
	pduBytes[12] = byte(pduLength)
	// SNMP PDU length (PDU header + varbind list length)
	pduBytes[1] = byte(pduLength + 11)

	buf.Write(pduBytes)

	// Write the 
	//buf.Write([]byte{packet.RequestType, uint8(17 + len(mOid)), 2, 1, 1, 2, 1, 0, 2, 1, 0, 0x30, uint8(6 + len(mOid)), 0x30, uint8(4 + len(mOid)), 6, uint8(len(mOid))})
	//buf.Write(mOid)
	//buf.Write([]byte{5, 0})

	ret := buf.Bytes()

	// Set the packet size
	ret[1] = uint8(len(ret) - 2)

	return ret, nil
}

func marshalPDU(pdu *SnmpPDU) ([]byte, error) {
	oid, err := marshalOID(pdu.Name)
	if err != nil {
		return nil, err
	}

	pduBuffer := make([]byte, 0, 1024)
	pduBuf := bytes.NewBuffer(pduBuffer)

	// Mashal the PDU type into the appropriate BER
	switch pdu.Type {
	case Null:
		pduBuf.Write([]byte{byte(Sequence), byte(len(oid) + 4)})
		pduBuf.Write([]byte{byte(ObjectIdentifier), byte(len(oid))})
		pduBuf.Write(oid)
		pduBuf.Write([]byte{Null, 0x00})
	default:
		return nil, fmt.Errorf("Unable to marshal PDU: uknown BER type %d", pdu.Type)
	}

	return pduBuf.Bytes(), nil
}

func oidToString(oid []int) (ret string) {
	for _, i := range oid {
		ret = ret + fmt.Sprintf(".%d", i)
	}
	return
}

func marshalOID(oid string) ([]byte, error) {
	var err error

	// Encode the oid
	oid = strings.Trim(oid, ".")
	oidParts := strings.Split(oid, ".")
	oidBytes := make([]int, len(oidParts))

	// Convert the string OID to an array of integers
	for i := 0; i < len(oidParts); i++ {
		oidBytes[i], err = strconv.Atoi(oidParts[i])
		if err != nil {
			return nil, fmt.Errorf("Unable to parse OID: %s\n", err.Error())
		}
	}

	mOid, err := marshalObjectIdentifier(oidBytes)

	if err != nil {
		return nil, fmt.Errorf("Unable to marshal OID: %s\n", err.Error())
	}

	return mOid, err
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

// Issue 4389: math/big: add SetUint64 and Uint64 functions to *Int
//
// uint64ToBigInt copied from: http://github.com/cznic/mathutil/blob/master/mathutil.go#L341
//
// replace with Uint64ToBigInt or equivalent when using Go 1.1

var uint64ToBigIntDelta big.Int

func init() {
	uint64ToBigIntDelta.SetBit(&uint64ToBigIntDelta, 63, 1)
}

func uint64ToBigInt(n uint64) *big.Int {
	if n <= math.MaxInt64 {
		return big.NewInt(int64(n))
	}

	y := big.NewInt(int64(n - uint64(math.MaxInt64) - 1))
	return y.Add(y, &uint64ToBigIntDelta)
}

// calc_length parses and calculates an snmp packet length
//
// http://luca.ntop.org/Teaching/Appunti/asn1.html
//
// Length octets. There are two forms: short (for lengths between 0 and 127),
// and long definite (for lengths between 0 and 2^1008 -1).
//
// * Short form. One octet. Bit 8 has value "0" and bits 7-1 give the length.
// * Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits
//   7-1 give the number of additional length octets. Second and following
//   octets give the length, base 256, most significant digit first.
func calc_length(bytes []byte) (length int, cursor int) {
	// TODO some error checking would be nice....
	if int(bytes[1]) <= 127 {
		length = int(bytes[1])
		length += 2
		cursor += 2
	} else {
		num_octets := int(bytes[1]) & 127
		for i := 0; i < num_octets; i++ {
			length <<= 8
			length += int(bytes[2+i])
		}
		length += 2 + num_octets
		cursor += 2 + num_octets
	}
	return length, cursor
}
