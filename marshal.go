// Copyright 2012 Andreas Louca, 2013 Sonia Hamilton. All rights reserved.  Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package gosnmp

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
)

//
// Remaining globals and definitions located here.
//

type SnmpVersion uint8

const (
	Version1  SnmpVersion = 0x0
	Version2c SnmpVersion = 0x1
)

type SnmpPacket struct {
	Version     SnmpVersion
	Community   string
	RequestType MessageType
	RequestID   uint32
	Error       uint8
	ErrorIndex  uint8
	Variables   []SnmpPDU
}

type SnmpPDU struct {
	Name  string
	Type  Asn1BER
	Value interface{}
}

type Asn1BER byte

const (
	EndOfContents    Asn1BER = 0x00
	Boolean                  = 0x01
	Integer                  = 0x02
	BitString                = 0x03
	OctetString              = 0x04
	Null                     = 0x05
	ObjectIdentifier         = 0x06
	ObjectDescription        = 0x07
	IpAddress                = 0x40
	Counter32                = 0x41
	Gauge32                  = 0x42
	TimeTicks                = 0x43
	Opaque                   = 0x44
	NsapAddress              = 0x45
	Counter64                = 0x46
	Uinteger32               = 0x47
	NoSuchObject             = 0x80
	NoSuchInstance           = 0x81
)

type Variable struct {
	Name  []int
	Type  Asn1BER
	Value interface{}
}

type VarBind struct {
	Name  asn1.ObjectIdentifier
	Value asn1.RawValue
}

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

// Logger is an interface used for debugging. Both Print and
// Printf have the same interfaces as Package Log in the std library. The
// Logger interface is small to give you flexibility in how you do
// your debugging.
//
// For verbose logging to stdout:
//
//     gosnmp_logger = log.New(os.Stdout, "", 0)

type Logger interface {
	Print(v ...interface{})
	Printf(format string, v ...interface{})
}

// slog is a global variable that is used for debug logging
var slog Logger

// -- Marshalling Logic --------------------------------------------------------

// marshal an SNMP message
func (packet *SnmpPacket) marshalMsg(oids []string, requestid uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	// version
	buf.Write([]byte{2, 1, byte(packet.Version)})

	// community
	buf.Write([]byte{4, uint8(len(packet.Community))})
	buf.WriteString(packet.Community)

	// pdu
	pdu, err := packet.marshalPDU(oids, requestid)
	if err != nil {
		return nil, err
	}
	buf.Write(pdu)

	// build up resulting msg - sequence, length then the tail (buf)
	msg := new(bytes.Buffer)
	msg.WriteByte(byte(Sequence))

	buf_length_bytes, err2 := marshalLength(buf.Len())
	if err2 != nil {
		return nil, err2
	}
	msg.Write(buf_length_bytes)

	buf.WriteTo(msg) // reverse logic - want to do msg.Write(buf)
	return msg.Bytes(), nil
}

// marshal a PDU
func (packet *SnmpPacket) marshalPDU(oids []string, requestid uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	// requestid
	buf.Write([]byte{2, 4})
	err := binary.Write(buf, binary.BigEndian, requestid)
	if err != nil {
		return nil, err
	}

	// error
	buf.Write([]byte{2, 1, 0})

	// error index
	buf.Write([]byte{2, 1, 0})

	// varbind list
	vbl, err := packet.marshalVBL(oids)
	if err != nil {
		return nil, err
	}
	buf.Write(vbl)

	// build up resulting pdu - GetRequest, length, then the tail (buf)
	pdu := new(bytes.Buffer)
	pdu.WriteByte(byte(GetRequest))

	buf_length_bytes, err2 := marshalLength(buf.Len())
	if err2 != nil {
		return nil, err2
	}
	pdu.Write(buf_length_bytes)

	buf.WriteTo(pdu) // reverse logic - want to do pdu.Write(buf)
	return pdu.Bytes(), nil
}

// marshal a varbind list
func (packet *SnmpPacket) marshalVBL(oids []string) ([]byte, error) {

	vbl_buf := new(bytes.Buffer)
	for _, oid := range oids {
		sp := &SnmpPDU{Name: oid, Type: Null}
		vb, err := marshalVarbind(sp)
		if err != nil {
			return nil, err
		}
		vbl_buf.Write(vb)
	}

	vbl_bytes := vbl_buf.Bytes()
	vbl_length_bytes, err := marshalLength(len(vbl_bytes))
	if err != nil {
		return nil, err
	}

	// FIX does bytes.Buffer give better performance than byte slices?
	result := []byte{byte(Sequence)}
	result = append(result, vbl_length_bytes...)
	result = append(result, vbl_bytes...)
	return result, nil
}

// marshal a varbind
func marshalVarbind(pdu *SnmpPDU) ([]byte, error) {
	oid, err := marshalOID(pdu.Name)
	if err != nil {
		return nil, err
	}
	pduBuf := new(bytes.Buffer)

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

// -- Unmarshalling Logic ------------------------------------------------------

func unmarshal(packet []byte) (*SnmpPacket, error) {
	response := new(SnmpPacket)
	response.Variables = make([]SnmpPDU, 0, 5)

	// Start parsing the packet
	cursor := 0

	// First bytes should be 0x30
	if MessageType(packet[0]) != Sequence {
		return nil, fmt.Errorf("Invalid packet header\n")
	}

	length, cursor := parseLength(packet)
	if len(packet) != length {
		return nil, fmt.Errorf("Error verifying packet sanity: Got %d Expected: %d\n", len(packet), length)
	}
	slog.Printf("Packet sanity verified, we got all the bytes (%d)", length)

	// Parse SNMP Version
	rawVersion, count, err := parseRawField(packet[cursor:], "version")
	if err != nil {
		return nil, fmt.Errorf("Error parsing SNMP packet version: %s", err.Error())
	}

	cursor += count
	if version, ok := rawVersion.(int); ok {
		response.Version = SnmpVersion(version)
		slog.Printf("Parsed version %d", version)
	}

	// Parse community
	rawCommunity, count, err := parseRawField(packet[cursor:], "community")
	cursor += count
	if community, ok := rawCommunity.(string); ok {
		response.Community = community
		slog.Printf("Parsed community %s", community)
	}

	// Parse SNMP packet type
	switch MessageType(packet[cursor]) {
	case GetResponse:
		response, err = unmarshalGetResponse(packet[cursor:], response, length)
	default:
		return nil, fmt.Errorf("Unknown MessageType %#x")
	}

	return response, nil
}

func unmarshalGetResponse(packet []byte, response *SnmpPacket, length int) (*SnmpPacket, error) {
	cursor := 0
	dumpBytes1(packet, "SNMP Packet is GET RESPONSE", 16)
	response.RequestType = GetResponse

	getresponse_length, cursor := parseLength(packet)
	if len(packet) != getresponse_length {
		return nil, fmt.Errorf("Error verifying GetResponse sanity: Got %d Expected: %d\n", len(packet), getresponse_length)
	}
	slog.Printf("getresponse_length: %d", getresponse_length)

	// Parse Request-ID
	rawRequestId, count, err := parseRawField(packet[cursor:], "request id")
	if err != nil {
		return nil, fmt.Errorf("Error parsing SNMP packet request ID: %s", err.Error())
	}
	cursor += count
	if requestid, ok := rawRequestId.(uint); ok {
		response.RequestID = uint32(requestid)
		slog.Printf("request-id: %d", response.RequestID)
	}

	// Parse Error-Status
	rawError, count, err := parseRawField(packet[cursor:], "error-status")
	if err != nil {
		return nil, fmt.Errorf("Error parsing SNMP packet error: %s", err.Error())
	}
	cursor += count
	if error_status, ok := rawError.(int); ok {
		response.Error = uint8(error_status)
		slog.Printf("error-status: %d", uint8(error_status))
	}

	// Parse Error-Index
	rawErrorIndex, count, err := parseRawField(packet[cursor:], "error index")
	if err != nil {
		return nil, fmt.Errorf("Error parsing SNMP packet error index: %s", err.Error())
	}
	cursor += count
	if errorindex, ok := rawErrorIndex.(int); ok {
		response.ErrorIndex = uint8(errorindex)
		slog.Printf("error-index: %d", uint8(errorindex))
	}

	return unmarshalVBL(packet[cursor:], response, length)
}

// unmarshal a Varbind list
func unmarshalVBL(packet []byte, response *SnmpPacket,
	length int) (*SnmpPacket, error) {

	dumpBytes1(packet, "\n=== unmarshalVBL()", 32)
	var cursor, cursor_inc int
	var vbl_length int
	if packet[cursor] != 0x30 {
		return nil, fmt.Errorf("Expected a sequence when unmarshalling a VBL, got %x",
			packet[cursor])
	}

	vbl_length, cursor = parseLength(packet)
	if len(packet) != vbl_length {
		return nil, fmt.Errorf("Error verifying: packet length %d vbl length %d\n",
			len(packet), vbl_length)
	}
	slog.Printf("vbl_length: %d", vbl_length)

	// Loop & parse Varbinds
	for cursor < vbl_length {
		dumpBytes1(packet[cursor:], fmt.Sprintf("\nSTARTING a varbind. Cursor %d", cursor), 32)
		if packet[cursor] != 0x30 {
			return nil, fmt.Errorf("Expected a sequence when unmarshalling a VB, got %x", packet[cursor])
		}

		_, cursor_inc = parseLength(packet[cursor:])
		cursor += cursor_inc

		// Parse OID
		rawOid, oid_length, err := parseRawField(packet[cursor:], "OID")
		if err != nil {
			return nil, fmt.Errorf("Error parsing OID Value: %s", err.Error())
		}
		cursor += oid_length

		var oid []int
		var ok bool
		if oid, ok = rawOid.([]int); !ok {
			return nil, fmt.Errorf("unable to type assert rawOid |%v| to []int", rawOid)
		}
		slog.Printf("OID: %s", oidToString(oid))

		// Parse Value
		v, err := decodeValue(packet[cursor:], "value")
		value_length, _ := parseLength(packet[cursor:])
		cursor += value_length
		response.Variables = append(response.Variables, SnmpPDU{oidToString(oid), v.Type, v.Value})
	}
	return response, nil
}
