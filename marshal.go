// Copyright 2012-2014 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"sync/atomic"
	"time"
)

//
// Remaining globals and definitions located here.
// See http://www.rane.com/note161.html for a succint description of the SNMP
// protocol.
//

// SnmpVersion 1 and 2c implemented, 3 planned
type SnmpVersion uint8

// SnmpVersion 1 and 2c implemented, 3 planned
const (
	Version1  SnmpVersion = 0x0
	Version2c SnmpVersion = 0x1
)

// SnmpPacket struct represents the entire SNMP Message or Sequence at the
// application layer.
type SnmpPacket struct {
	Version        SnmpVersion
	Community      string
	PDUType        PDUType
	RequestID      uint32
	Error          uint8
	ErrorIndex     uint8
	NonRepeaters   uint8
	MaxRepetitions uint8
	Variables      []SnmpPDU
}

// VarBind struct represents an SNMP Varbind.
type VarBind struct {
	Name  asn1.ObjectIdentifier
	Value asn1.RawValue
}

// PDUType describes which SNMP Protocol Data Unit is being sent.
type PDUType byte

// The currently supported PDUType's
const (
	Sequence       PDUType = 0x30
	GetRequest     PDUType = 0xa0
	GetNextRequest PDUType = 0xa1
	GetResponse    PDUType = 0xa2
	SetRequest     PDUType = 0xa3
	Trap           PDUType = 0xa4
	GetBulkRequest PDUType = 0xa5
)

const (
	rxBufSize = 65536
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

// generic "sender"
func (x *GoSNMP) send(pdus []SnmpPDU, packetOut *SnmpPacket) (result *SnmpPacket, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("recover: %v", e)
		}
	}()

	if x.Conn == nil {
		return nil, fmt.Errorf("&GoSNMP.Conn is missing. Provide a connection or use Connect()")
	}

	if x.Logger == nil {
		x.Logger = log.New(ioutil.Discard, "", 0)
	}
	slog = x.Logger // global variable for debug logging

	finalDeadline := time.Now().Add(x.Timeout)

	if x.Retries < 0 {
		x.Retries = 0
	}
	allReqIDs := make([]uint32, 0, x.Retries+1)
	for retries := 0; ; retries++ {
		if retries > 0 {
			if LoggingDisabled != true {
				slog.Printf("Retry number %d. Last error was: %v", retries, err)
			}
			if time.Now().After(finalDeadline) {
				err = fmt.Errorf("Request timeout (after %d retries)", retries-1)
				break
			}
			if retries > x.Retries {
				// Report last error
				break
			}
		}
		err = nil

		reqDeadline := time.Now().Add(x.Timeout / time.Duration(x.Retries+1))
		x.Conn.SetDeadline(reqDeadline)

		// Request ID is an atomic counter (started at a random value)
		reqID := atomic.AddUint32(&(x.requestID), 1)
		allReqIDs = append(allReqIDs, reqID)

		var outBuf []byte
		outBuf, err = packetOut.marshalMsg(pdus, packetOut.PDUType, reqID)
		if err != nil {
			// Don't retry - not going to get any better!
			err = fmt.Errorf("marshal: %v", err)
			break
		}
		_, err = x.Conn.Write(outBuf)
		if err != nil {
			err = fmt.Errorf("Error writing to socket: %s", err.Error())
			continue
		}

		// FIXME: If our packet exceeds our buf size we'll get a partial read
		// and this request, and the next will fail. The correct logic would be
		// to realloc and read more if pack len > buff size.
		resp := make([]byte, rxBufSize, rxBufSize)
		var n int
		n, err = x.Conn.Read(resp)
		if err != nil {
			err = fmt.Errorf("Error reading from UDP: %s", err.Error())
			continue
		}

		result, err = unmarshal(resp[:n])
		if err != nil {
			err = fmt.Errorf("Unable to decode packet: %s", err.Error())
			continue
		}
		if result == nil || len(result.Variables) < 1 {
			err = fmt.Errorf("Unable to decode packet: nil")
			continue
		}

		validID := false
		for _, id := range allReqIDs {
			if id == result.RequestID {
				validID = true
			}
		}
		if !validID {
			err = fmt.Errorf("Out of order response")
			continue
		}

		// Success!
		return result, nil
	}

	// Return last error
	return nil, err
}

// -- Marshalling Logic --------------------------------------------------------

// marshal an SNMP message
func (packet *SnmpPacket) marshalMsg(pdus []SnmpPDU,
	pdutype PDUType, requestid uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	// version
	buf.Write([]byte{2, 1, byte(packet.Version)})

	// community
	buf.Write([]byte{4, uint8(len(packet.Community))})
	buf.WriteString(packet.Community)

	// pdu
	pdu, err := packet.marshalPDU(pdus, requestid)
	if err != nil {
		return nil, err
	}
	buf.Write(pdu)

	// build up resulting msg - sequence, length then the tail (buf)
	msg := new(bytes.Buffer)
	msg.WriteByte(byte(Sequence))

	bufLengthBytes, err2 := marshalLength(buf.Len())
	if err2 != nil {
		return nil, err2
	}
	msg.Write(bufLengthBytes)

	buf.WriteTo(msg) // reverse logic - want to do msg.Write(buf)
	return msg.Bytes(), nil
}

// marshal a PDU
func (packet *SnmpPacket) marshalPDU(pdus []SnmpPDU, requestid uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	// requestid
	buf.Write([]byte{2, 4})
	err := binary.Write(buf, binary.BigEndian, requestid)
	if err != nil {
		return nil, err
	}

	if packet.PDUType == GetBulkRequest {
		// non repeaters
		buf.Write([]byte{2, 1, packet.NonRepeaters})

		// max repetitions
		buf.Write([]byte{2, 1, packet.MaxRepetitions})
	} else { // get and getnext have same packet format

		// error
		buf.Write([]byte{2, 1, 0})

		// error index
		buf.Write([]byte{2, 1, 0})
	}

	// varbind list
	vbl, err := packet.marshalVBL(pdus)
	if err != nil {
		return nil, err
	}
	buf.Write(vbl)

	// build up resulting pdu - request type, length, then the tail (buf)
	pdu := new(bytes.Buffer)
	pdu.WriteByte(byte(packet.PDUType))

	bufLengthBytes, err2 := marshalLength(buf.Len())
	if err2 != nil {
		return nil, err2
	}
	pdu.Write(bufLengthBytes)

	buf.WriteTo(pdu) // reverse logic - want to do pdu.Write(buf)
	return pdu.Bytes(), nil
}

// marshal a varbind list
func (packet *SnmpPacket) marshalVBL(pdus []SnmpPDU) ([]byte, error) {

	vblBuf := new(bytes.Buffer)
	for _, pdu := range pdus {
		vb, err := marshalVarbind(&pdu)
		if err != nil {
			return nil, err
		}
		vblBuf.Write(vb)
	}

	vblBytes := vblBuf.Bytes()
	vblLengthBytes, err := marshalLength(len(vblBytes))
	if err != nil {
		return nil, err
	}

	// FIX does bytes.Buffer give better performance than byte slices?
	result := []byte{byte(Sequence)}
	result = append(result, vblLengthBytes...)
	result = append(result, vblBytes...)
	return result, nil
}

// marshal a varbind
func marshalVarbind(pdu *SnmpPDU) ([]byte, error) {
	oid, err := marshalOID(pdu.Name)
	if err != nil {
		return nil, err
	}
	pduBuf := new(bytes.Buffer)
	tmpBuf := new(bytes.Buffer)

	// Marshal the PDU type into the appropriate BER
	switch pdu.Type {
	case Null:
		pduBuf.Write([]byte{byte(Sequence), byte(len(oid) + 4)})
		pduBuf.Write([]byte{byte(ObjectIdentifier), byte(len(oid))})
		pduBuf.Write(oid)
		pduBuf.Write([]byte{Null, 0x00})
	case Integer:
		// Oid
		tmpBuf.Write([]byte{byte(ObjectIdentifier), byte(len(oid))})
		tmpBuf.Write(oid)
		// Integer
		intBytes := []byte{byte(pdu.Value.(int))}
		tmpBuf.Write([]byte{byte(Integer), byte(len(intBytes))})
		tmpBuf.Write(intBytes)
		// Sequence, length of oid + integer, then oid/integer data
		pduBuf.WriteByte(byte(Sequence))
		pduBuf.WriteByte(byte(len(oid) + len(intBytes) + 4))
		pduBuf.Write(tmpBuf.Bytes())
	default:
		return nil, fmt.Errorf("Unable to marshal PDU: unknown BER type %d", pdu.Type)
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
	if PDUType(packet[0]) != Sequence {
		return nil, fmt.Errorf("Invalid packet header\n")
	}

	length, cursor := parseLength(packet)
	if len(packet) != length {
		return nil, fmt.Errorf("Error verifying packet sanity: Got %d Expected: %d\n", len(packet), length)
	}
	if LoggingDisabled != true {
		slog.Printf("Packet sanity verified, we got all the bytes (%d)", length)
	}

	// Parse SNMP Version
	rawVersion, count, err := parseRawField(packet[cursor:], "version")
	if err != nil {
		return nil, fmt.Errorf("Error parsing SNMP packet version: %s", err.Error())
	}

	cursor += count
	if version, ok := rawVersion.(int); ok {
		response.Version = SnmpVersion(version)
		if LoggingDisabled != true {
			slog.Printf("Parsed version %d", version)
		}
	}

	// Parse community
	rawCommunity, count, err := parseRawField(packet[cursor:], "community")
	cursor += count
	if community, ok := rawCommunity.(string); ok {
		response.Community = community
		if LoggingDisabled != true {
			slog.Printf("Parsed community %s", community)
		}
	}

	// Parse SNMP packet type
	requestType := PDUType(packet[cursor])
	switch requestType {
	// known, supported types
	case GetResponse, GetNextRequest, GetBulkRequest:
		response, err = unmarshalResponse(packet[cursor:], response, length, requestType)
		if err != nil {
			return nil, fmt.Errorf("Error in unmarshalResponse: %s", err.Error())
		}
	default:
		return nil, fmt.Errorf("Unknown PDUType %#x", requestType)
	}
	return response, nil
}

func unmarshalResponse(packet []byte, response *SnmpPacket, length int, requestType PDUType) (*SnmpPacket, error) {
	cursor := 0
	dumpBytes1(packet, "SNMP Packet is GET RESPONSE", 16)
	response.PDUType = requestType

	getResponseLength, cursor := parseLength(packet)
	if len(packet) != getResponseLength {
		return nil, fmt.Errorf("Error verifying Response sanity: Got %d Expected: %d\n", len(packet), getResponseLength)
	}
	if LoggingDisabled != true {
		slog.Printf("getResponseLength: %d", getResponseLength)
	}

	// Parse Request-ID
	rawRequestID, count, err := parseRawField(packet[cursor:], "request id")
	if err != nil {
		return nil, fmt.Errorf("Error parsing SNMP packet request ID: %s", err.Error())
	}
	cursor += count
	if requestid, ok := rawRequestID.(int); ok {
		response.RequestID = uint32(requestid)
		if LoggingDisabled != true {
			slog.Printf("requestID: %d", response.RequestID)
		}
	}

	if response.PDUType == GetBulkRequest {
		// Parse Non Repeaters
		rawNonRepeaters, count, err := parseRawField(packet[cursor:], "non repeaters")
		if err != nil {
			return nil, fmt.Errorf("Error parsing SNMP packet non repeaters: %s", err.Error())
		}
		cursor += count
		if nonRepeaters, ok := rawNonRepeaters.(int); ok {
			response.NonRepeaters = uint8(nonRepeaters)
		}

		// Parse Max Repetitions
		rawMaxRepetitions, count, err := parseRawField(packet[cursor:], "max repetitions")
		if err != nil {
			return nil, fmt.Errorf("Error parsing SNMP packet max repetitions: %s", err.Error())
		}
		cursor += count
		if maxRepetitions, ok := rawMaxRepetitions.(int); ok {
			response.MaxRepetitions = uint8(maxRepetitions)
		}
	} else {
		// Parse Error-Status
		rawError, count, err := parseRawField(packet[cursor:], "error-status")
		if err != nil {
			return nil, fmt.Errorf("Error parsing SNMP packet error: %s", err.Error())
		}
		cursor += count
		if errorStatus, ok := rawError.(int); ok {
			response.Error = uint8(errorStatus)
			if LoggingDisabled != true {
				slog.Printf("errorStatus: %d", uint8(errorStatus))
			}
		}

		// Parse Error-Index
		rawErrorIndex, count, err := parseRawField(packet[cursor:], "error index")
		if err != nil {
			return nil, fmt.Errorf("Error parsing SNMP packet error index: %s", err.Error())
		}
		cursor += count
		if errorindex, ok := rawErrorIndex.(int); ok {
			response.ErrorIndex = uint8(errorindex)
			if LoggingDisabled != true {
				slog.Printf("error-index: %d", uint8(errorindex))
			}
		}
	}

	return unmarshalVBL(packet[cursor:], response, length)
}

// unmarshal a Varbind list
func unmarshalVBL(packet []byte, response *SnmpPacket,
	length int) (*SnmpPacket, error) {

	dumpBytes1(packet, "\n=== unmarshalVBL()", 32)
	var cursor, cursorInc int
	var vblLength int
	if packet[cursor] != 0x30 {
		return nil, fmt.Errorf("Expected a sequence when unmarshalling a VBL, got %x",
			packet[cursor])
	}

	vblLength, cursor = parseLength(packet)
	if len(packet) != vblLength {
		return nil, fmt.Errorf("Error verifying: packet length %d vbl length %d\n",
			len(packet), vblLength)
	}
	if LoggingDisabled != true {
		slog.Printf("vblLength: %d", vblLength)
	}

	// Loop & parse Varbinds
	for cursor < vblLength {
		dumpBytes1(packet[cursor:], fmt.Sprintf("\nSTARTING a varbind. Cursor %d", cursor), 32)
		if packet[cursor] != 0x30 {
			return nil, fmt.Errorf("Expected a sequence when unmarshalling a VB, got %x", packet[cursor])
		}

		_, cursorInc = parseLength(packet[cursor:])
		cursor += cursorInc

		// Parse OID
		rawOid, oidLength, err := parseRawField(packet[cursor:], "OID")
		if err != nil {
			return nil, fmt.Errorf("Error parsing OID Value: %s", err.Error())
		}
		cursor += oidLength

		var oid []int
		var ok bool
		if oid, ok = rawOid.([]int); !ok {
			return nil, fmt.Errorf("unable to type assert rawOid |%v| to []int", rawOid)
		}
		oidStr := oidToString(oid)
		if LoggingDisabled != true {
			slog.Printf("OID: %s", oidStr)
		}

		// Parse Value
		v, err := decodeValue(packet[cursor:], "value")
		if err != nil {
			return nil, fmt.Errorf("Error decoding value: %v", err)
		}
		valueLength, _ := parseLength(packet[cursor:])
		cursor += valueLength
		response.Variables = append(response.Variables, SnmpPDU{oidStr, v.Type, v.Value})
	}
	return response, nil
}
