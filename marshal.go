// Copyright 2012-2014 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

//
// Remaining globals and definitions located here.
// See http://www.rane.com/note161.html for a succint description of the SNMP
// protocol.
//

// SnmpVersion 1, 2c and 3 implemented
type SnmpVersion uint8

// SnmpVersion 1, 2c and 3 implemented
const (
	Version1  SnmpVersion = 0x0
	Version2c SnmpVersion = 0x1
	Version3  SnmpVersion = 0x3
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

// SnmpV3AuthProtocol describes the authentication protocol in use by an authenticated SnmpV3 connection.
type SnmpV3AuthProtocol uint8

// NoAuth, MD5, and SHA are implemented
const (
	NoAuth SnmpV3AuthProtocol = 1
	MD5    SnmpV3AuthProtocol = 2
	SHA    SnmpV3AuthProtocol = 3
)

// SnmpV3PrivProtocol is the privacy protocol in use by an private SnmpV3 connection.
type SnmpV3PrivProtocol uint8

// NoPriv, DES implemented, AES planned
const (
	NoPriv SnmpV3PrivProtocol = 1
	DES    SnmpV3PrivProtocol = 2
	AES    SnmpV3PrivProtocol = 3
)

// SnmpV3SecurityParameters is a generic interface type to contain various implementations of SnmpV3SecurityParameters
type SnmpV3SecurityParameters interface {
	Copy() SnmpV3SecurityParameters
}

// UsmSecurityParameters is an implementation of SnmpV3SecurityParameters for the UserSecurityModel
type UsmSecurityParameters struct {
	AuthoritativeEngineID    string
	AuthoritativeEngineBoots uint32
	AuthoritativeEngineTime  uint32
	UserName                 string
	AuthenticationParameters string
	PrivacyParameters        []byte

	AuthenticationProtocol SnmpV3AuthProtocol
	PrivacyProtocol        SnmpV3PrivProtocol

	AuthenticationPassphrase string
	PrivacyPassphrase        string

	localDESSalt uint32
	localAESSalt uint64
}

// Copy method for UsmSecurityParameters used to copy a SnmpV3SecurityParameters without knowing it's implementation
func (sp *UsmSecurityParameters) Copy() SnmpV3SecurityParameters {
	return &UsmSecurityParameters{AuthoritativeEngineID: sp.AuthoritativeEngineID,
		AuthoritativeEngineBoots: sp.AuthoritativeEngineBoots,
		AuthoritativeEngineTime:  sp.AuthoritativeEngineTime,
		UserName:                 sp.UserName,
		AuthenticationParameters: sp.AuthenticationParameters,
		PrivacyParameters:        sp.PrivacyParameters,
		AuthenticationProtocol:   sp.AuthenticationProtocol,
		PrivacyProtocol:          sp.PrivacyProtocol,
		AuthenticationPassphrase: sp.AuthenticationPassphrase,
		PrivacyPassphrase:        sp.PrivacyPassphrase,
		localDESSalt:             sp.localDESSalt,
		localAESSalt:             sp.localAESSalt,
	}
}

// SnmpPacket struct represents the entire SNMP Message or Sequence at the
// application layer.
type SnmpPacket struct {
	Version            SnmpVersion
	MsgFlags           SnmpV3MsgFlags
	SecurityModel      SnmpV3SecurityModel
	SecurityParameters interface{}
	ContextEngineID    string
	ContextName        string
	Community          string
	PDUType            PDUType
	MsgID              uint32
	RequestID          uint32
	Error              uint8
	ErrorIndex         uint8
	NonRepeaters       uint8
	MaxRepetitions     uint8
	Variables          []SnmpPDU
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
	InformRequest  PDUType = 0xa6
	SNMPV2Trap     PDUType = 0xa7
	Report         PDUType = 0xa8
)

const (
	rxBufSizeMin = 1024   // Minimal buffer size to handle 1 OID (see dispatch())
	rxBufSizeMax = 131072 // 2 x max MTU size (65507)
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

func (x *GoSNMP) sendOneRequest(pdus []SnmpPDU, packetOut *SnmpPacket) (result *SnmpPacket, err error) {
	finalDeadline := time.Now().Add(x.Timeout)

	allReqIDs := make([]uint32, 0, x.Retries+1)
	allMsgIDs := make([]uint32, 0, x.Retries+1)
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
		reqID := atomic.AddUint32(&(x.requestID), 1) // TODO: fix overflows
		allReqIDs = append(allReqIDs, reqID)

		var msgID uint32
		if x.Version == Version3 {
			msgID = atomic.AddUint32(&(x.msgID), 1) // TODO: fix overflows
			allMsgIDs = append(allMsgIDs, msgID)

			// http://tools.ietf.org/html/rfc2574#section-8.1.1.1
			// localDESSalt needs to be incremented on every packet.
			if x.MsgFlags&AuthPriv > AuthNoPriv && x.SecurityModel == UserSecurityModel {
				baseSecParams, ok := x.SecurityParameters.(*UsmSecurityParameters)
				if !ok || baseSecParams == nil {
					err = fmt.Errorf("&GoSNMP.SecurityModel indicates the User Security Model, but &GoSNMP.SecurityParameters is not of type &UsmSecurityParameters")
					break
				}
				var newPktLocalAESSalt uint64
				var newPktLocalDESSalt uint32
				switch baseSecParams.PrivacyProtocol {
				case AES:
					newPktLocalAESSalt = atomic.AddUint64(&(baseSecParams.localAESSalt), 1)
				case DES:
					newPktLocalDESSalt = atomic.AddUint32(&(baseSecParams.localDESSalt), 1)
				}

				if packetOut.Version == Version3 && packetOut.SecurityModel == UserSecurityModel && packetOut.MsgFlags&AuthPriv > AuthNoPriv {

					pktSecParams, ok := packetOut.SecurityParameters.(*UsmSecurityParameters)
					if !ok || baseSecParams == nil {
						err = fmt.Errorf("packetOut.SecurityModel indicates the User Security Model, but packetOut.SecurityParameters is not of type &UsmSecurityParameters")
						break
					}

					switch pktSecParams.PrivacyProtocol {
					case AES:
						var salt = make([]byte, 8)
						binary.BigEndian.PutUint64(salt, newPktLocalAESSalt)
						pktSecParams.PrivacyParameters = salt
					default:
						var salt = make([]byte, 8)
						binary.BigEndian.PutUint32(salt, pktSecParams.AuthoritativeEngineBoots)
						binary.BigEndian.PutUint32(salt[4:], newPktLocalDESSalt)
						pktSecParams.PrivacyParameters = salt
					}
				}
			}
		}

		var outBuf []byte
		outBuf, err = packetOut.marshalMsg(pdus, packetOut.PDUType, msgID, reqID)
		if err != nil {
			// Don't retry - not going to get any better!
			err = fmt.Errorf("marshal: %v", err)
			break
		}

		var expected int
		if packetOut.PDUType == GetBulkRequest {
			expected = int(packetOut.MaxRepetitions)
		} else {
			expected = len(pdus)
		}

		var resp []byte
		resp, err = dispatch(x.Conn, outBuf, expected)
		if err != nil {
			continue
		}

		result, err = x.unmarshal(resp)
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
		if result.RequestID == 0 {
			validID = true
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

	if x.Retries < 0 {
		x.Retries = 0
	}

	// http://tools.ietf.org/html/rfc2574#section-2.2.3
	// This code does not check if the last message received was more than 150 seconds ago
	// The snmpds that this code was tested on emit an 'out of time window' error with the new
	// time and this code will retransmit when that is received.
	if packetOut.Version == Version3 {
		if packetOut.SecurityModel == UserSecurityModel {
			secParams, ok := packetOut.SecurityParameters.(*UsmSecurityParameters)
			if !ok || secParams == nil {
				return nil, fmt.Errorf("packetOut.SecurityModel indicates the User Security Model, but packetOut.SecurityParameters is not of type &UsmSecurityParameters")
			}
			if secParams.AuthoritativeEngineID == "" {
				// send blank packet to discover authoriative engine ID/boots/time
				blankPacket := &SnmpPacket{
					Version:            Version3,
					MsgFlags:           Reportable | NoAuthNoPriv,
					SecurityModel:      UserSecurityModel,
					SecurityParameters: &UsmSecurityParameters{},
					PDUType:            GetRequest,
				}
				var emptyPdus []SnmpPDU
				result, err := x.sendOneRequest(emptyPdus, blankPacket)

				if err != nil {
					return nil, err
				}
				// store the authoritative engine parameters
				newSecParams, ok := result.SecurityParameters.(*UsmSecurityParameters)
				if ok && newSecParams != nil {
					secParams.AuthoritativeEngineID = newSecParams.AuthoritativeEngineID
					secParams.AuthoritativeEngineBoots = newSecParams.AuthoritativeEngineBoots
					secParams.AuthoritativeEngineTime = newSecParams.AuthoritativeEngineTime

					// it seems common to use the authoritative engine id as the default
					// context engine id when it is not specified
					if packetOut.ContextEngineID == "" {
						packetOut.ContextEngineID = newSecParams.AuthoritativeEngineID
					}
					// store for base connection as well
					if x.ContextEngineID == "" {
						x.ContextEngineID = newSecParams.AuthoritativeEngineID
					}
				}

			}
		}
	}
	// perform request
	result, err = x.sendOneRequest(pdus, packetOut)
	if err != nil {
		return result, err
	}

	if result.Version == Version3 && result.SecurityModel == UserSecurityModel {
		secParams, ok := result.SecurityParameters.(*UsmSecurityParameters)
		if !ok || secParams == nil {
			return nil, fmt.Errorf("result.SecurityModel indicates the User Security Model, but result.SecurityParameters is not of type &UsmSecurityParameters")
		}
		if x.Version == Version3 && x.SecurityModel == UserSecurityModel {
			connSecParams, ok := x.SecurityParameters.(*UsmSecurityParameters)
			if !ok || connSecParams != nil {
				connSecParams.AuthoritativeEngineID = secParams.AuthoritativeEngineID
				connSecParams.AuthoritativeEngineBoots = secParams.AuthoritativeEngineBoots
				connSecParams.AuthoritativeEngineTime = secParams.AuthoritativeEngineTime
			}
			if x.ContextEngineID == "" {
				x.ContextEngineID = secParams.AuthoritativeEngineID
			}
		}

		if len(result.Variables) == 1 && result.Variables[0].Name == ".1.3.6.1.6.3.15.1.1.2.0" {

			// out of time window -- but since we just renegotiated the authoritative engine parameters,
			// just resubmit the packet with updated parameters
			pktSecParams, ok := packetOut.SecurityParameters.(*UsmSecurityParameters)
			if !ok || pktSecParams == nil {
				return nil, fmt.Errorf("packetOut.SecurityModel indicates the User Security Model, but packetOut.SecurityParameters is not of type &UsmSecurityParameters")
			}
			pktSecParams.AuthoritativeEngineID = secParams.AuthoritativeEngineID
			pktSecParams.AuthoritativeEngineBoots = secParams.AuthoritativeEngineBoots
			pktSecParams.AuthoritativeEngineTime = secParams.AuthoritativeEngineTime

			if packetOut.ContextEngineID == "" {
				packetOut.ContextEngineID = secParams.AuthoritativeEngineID
			}

			return x.sendOneRequest(pdus, packetOut)
		}
	}
	return result, err
}

// -- Marshalling Logic --------------------------------------------------------

// marshal an SNMP message
func (packet *SnmpPacket) marshalMsg(pdus []SnmpPDU,
	pdutype PDUType, msgid uint32, requestid uint32) ([]byte, error) {
	var authParamStart uint32
	buf := new(bytes.Buffer)

	// version
	buf.Write([]byte{2, 1, byte(packet.Version)})

	if packet.Version != Version3 {
		// community
		buf.Write([]byte{4, uint8(len(packet.Community))})
		buf.WriteString(packet.Community)
		// pdu
		pdu, err := packet.marshalPDU(pdus, requestid)
		if err != nil {
			return nil, err
		}
		buf.Write(pdu)
	} else {
		header, err := packet.marshalSnmpV3Header(msgid)
		if err != nil {
			return nil, err
		}
		buf.Write([]byte{byte(Sequence), byte(len(header))})
		buf.Write(header)

		var securityParameters []byte
		if packet.SecurityModel == UserSecurityModel {
			securityParameters, authParamStart, err = packet.marshalSnmpV3UsmSecurityParameters()
			if err != nil {
				return nil, err
			}
		}

		buf.Write([]byte{byte(OctetString)})
		secParamLen, err := marshalLength(len(securityParameters))
		if err != nil {
			return nil, err
		}
		buf.Write(secParamLen)
		authParamStart += uint32(buf.Len())
		buf.Write(securityParameters)

		scopedPdu, err := packet.marshalSnmpV3ScopedPDU(pdus, requestid)
		if err != nil {
			return nil, err
		}
		buf.Write(scopedPdu)
	}

	// build up resulting msg - sequence, length then the tail (buf)
	msg := new(bytes.Buffer)
	msg.WriteByte(byte(Sequence))

	bufLengthBytes, err2 := marshalLength(buf.Len())
	if err2 != nil {
		return nil, err2
	}
	msg.Write(bufLengthBytes)
	authParamStart += uint32(msg.Len())
	buf.WriteTo(msg) // reverse logic - want to do msg.Write(buf)

	authenticatedMessage, err := packet.authenticate(msg.Bytes(), authParamStart)
	if err != nil {
		return nil, err
	}

	return authenticatedMessage, nil
}

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
	secParams, ok := packet.SecurityParameters.(*UsmSecurityParameters)
	if !ok || secParams == nil {
		return nil, fmt.Errorf("Error authenticating message: Unable to extract UsmSecurityParameters")
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

func marshalUvarInt(x uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, x)
	i := 0
	for ; i < 4; i++ {
		if buf[i] != 0 {
			break
		}
	}
	buf = buf[i:]
	// if the highest bit in buf is set and x is not negative - prepend a byte to make it positive
	if len(buf) > 0 && buf[0]&0x80 > 0 {
		buf = append([]byte{0}, buf...)
	}
	return buf
}

func (packet *SnmpPacket) marshalSnmpV3Header(msgid uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	// msg id
	buf.Write([]byte{byte(Integer), 4})
	err := binary.Write(buf, binary.BigEndian, msgid)
	if err != nil {
		return nil, err
	}

	// maximum response msg size
	maxmsgsize := marshalUvarInt(rxBufSizeMax)
	buf.Write([]byte{byte(Integer), byte(len(maxmsgsize))})
	buf.Write(maxmsgsize)

	// msg flags
	buf.Write([]byte{byte(OctetString), 1, byte(packet.MsgFlags)})

	// msg security model
	buf.Write([]byte{byte(Integer), 1, byte(packet.SecurityModel)})

	return buf.Bytes(), nil
}

func (packet *SnmpPacket) marshalSnmpV3UsmSecurityParameters() ([]byte, uint32, error) {
	var buf bytes.Buffer
	var authParamStart uint32

	secParams, ok := packet.SecurityParameters.(*UsmSecurityParameters)
	if !ok || secParams == nil {
		return nil, 0, fmt.Errorf("packet.SecurityParameters is not of type &UsmSecurityParameters")
	}

	// msgAuthoritativeEngineID
	buf.Write([]byte{byte(OctetString), byte(len(secParams.AuthoritativeEngineID))})
	buf.WriteString(secParams.AuthoritativeEngineID)

	// msgAuthoritativeEngineBoots
	msgAuthoritativeEngineBoots := marshalUvarInt(secParams.AuthoritativeEngineBoots)
	buf.Write([]byte{byte(Integer), byte(len(msgAuthoritativeEngineBoots))})
	buf.Write(msgAuthoritativeEngineBoots)

	// msgAuthoritativeEngineTime
	msgAuthoritativeEngineTime := marshalUvarInt(secParams.AuthoritativeEngineTime)
	buf.Write([]byte{byte(Integer), byte(len(msgAuthoritativeEngineTime))})
	buf.Write(msgAuthoritativeEngineTime)

	// msgUserName
	buf.Write([]byte{byte(OctetString), byte(len(secParams.UserName))})
	buf.WriteString(secParams.UserName)

	authParamStart = uint32(buf.Len() + 2) // +2 indicates PDUType + Length
	// msgAuthenticationParameters
	if packet.MsgFlags&AuthNoPriv > 0 {
		buf.Write([]byte{byte(OctetString), 12,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0})
	} else {
		buf.Write([]byte{byte(OctetString), 0})
	}
	// msgPrivacyParameters
	if packet.MsgFlags&AuthPriv > AuthNoPriv {
		privlen, err := marshalLength(len(secParams.PrivacyParameters))
		if err != nil {
			return nil, 0, err
		}
		buf.Write([]byte{byte(OctetString)})
		buf.Write(privlen)
		buf.Write(secParams.PrivacyParameters)
	} else {
		buf.Write([]byte{byte(OctetString), 0})
	}

	// wrap security parameters in a sequence
	paramLen, err := marshalLength(buf.Len())
	if err != nil {
		return nil, 0, err
	}
	tmpseq := append([]byte{byte(Sequence)}, paramLen...)
	authParamStart += uint32(len(tmpseq))
	tmpseq = append(tmpseq, buf.Bytes()...)

	return tmpseq, authParamStart, nil
}

func (packet *SnmpPacket) marshalSnmpV3ScopedPDU(pdus []SnmpPDU, requestid uint32) ([]byte, error) {
	var b []byte

	scopedPdu, err := packet.prepareSnmpV3ScopedPDU(pdus, requestid)
	if err != nil {
		return nil, err
	}
	pduLen, err := marshalLength(len(scopedPdu))
	if err != nil {
		return nil, err
	}
	b = append([]byte{byte(Sequence)}, pduLen...)
	scopedPdu = append(b, scopedPdu...)
	if packet.MsgFlags&AuthPriv > AuthNoPriv && packet.SecurityModel == UserSecurityModel {
		secParams, ok := packet.SecurityParameters.(*UsmSecurityParameters)
		if !ok || secParams == nil {
			return nil, fmt.Errorf("packet.SecurityModel indicates the User Security Model, but packet.SecurityParameters is not of type &UsmSecurityParameters")
		}
		var privkey = genlocalkey(secParams.AuthenticationProtocol,
			secParams.PrivacyPassphrase,
			secParams.AuthoritativeEngineID)
		switch secParams.PrivacyProtocol {
		case AES:
			var iv [16]byte
			binary.BigEndian.PutUint32(iv[:], secParams.AuthoritativeEngineBoots)
			binary.BigEndian.PutUint32(iv[4:], secParams.AuthoritativeEngineTime)
			copy(iv[8:], secParams.PrivacyParameters)

			block, err := aes.NewCipher(privkey[:16])
			if err != nil {
				return nil, err
			}
			stream := cipher.NewCFBEncrypter(block, iv[:])
			ciphertext := make([]byte, len(scopedPdu))
			stream.XORKeyStream(ciphertext, scopedPdu)
			pduLen, err := marshalLength(len(ciphertext))
			if err != nil {
				return nil, err
			}
			b = append([]byte{byte(OctetString)}, pduLen...)
			scopedPdu = append(b, ciphertext...)
		default:
			preiv := privkey[8:]
			var iv [8]byte
			for i := 0; i < len(iv); i++ {
				iv[i] = preiv[i] ^ secParams.PrivacyParameters[i]
			}
			block, err := des.NewCipher(privkey[:8])
			if err != nil {
				return nil, err
			}
			mode := cipher.NewCBCEncrypter(block, iv[:])

			pad := make([]byte, des.BlockSize-len(scopedPdu)%des.BlockSize)
			scopedPdu = append(scopedPdu, pad...)

			ciphertext := make([]byte, len(scopedPdu))
			mode.CryptBlocks(ciphertext, scopedPdu)
			pduLen, err := marshalLength(len(ciphertext))
			if err != nil {
				return nil, err
			}
			b = append([]byte{byte(OctetString)}, pduLen...)
			scopedPdu = append(b, ciphertext...)
		}

	}

	return scopedPdu, nil
}

func (packet *SnmpPacket) prepareSnmpV3ScopedPDU(pdus []SnmpPDU, requestid uint32) ([]byte, error) {
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

	data, err := packet.marshalPDU(pdus, requestid)
	if err != nil {
		return nil, err
	}
	buf.Write(data)
	return buf.Bytes(), nil
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
		// TODO tests currently only cover positive integers
		// Oid
		tmpBuf.Write([]byte{byte(ObjectIdentifier), byte(len(oid))})
		tmpBuf.Write(oid)
		// Integer
		var intBytes []byte
		switch value := pdu.Value.(type) {
		case byte:
			intBytes = []byte{byte(pdu.Value.(int))}
		case int:
			intBytes = marshalInt16(value)
		default:
			return nil, fmt.Errorf("Unable to marshal PDU Integer; not byte or int.")
		}
		tmpBuf.Write([]byte{byte(Integer), byte(len(intBytes))})
		tmpBuf.Write(intBytes)
		// Sequence, length of oid + integer, then oid/integer data
		pduBuf.WriteByte(byte(Sequence))
		pduBuf.WriteByte(byte(len(oid) + len(intBytes) + 4))
		pduBuf.Write(tmpBuf.Bytes())

	case OctetString:
		//Oid
		tmpBuf.Write([]byte{byte(ObjectIdentifier), byte(len(oid))})
		tmpBuf.Write(oid)
		//OctetString
		var octetStringBytes []byte
		switch value := pdu.Value.(type) {
		case []byte:
			octetStringBytes = value
		case string:
			octetStringBytes = []byte(value)
		default:
			return nil, fmt.Errorf("Unable to marshal PDU OctetString; not []byte or String.")
		}
		tmpBuf.Write([]byte{byte(OctetString), byte(len(octetStringBytes))})
		tmpBuf.Write(octetStringBytes)
		// Sequence, length of oid + octetstring, then oid/octetstring data
		pduBuf.WriteByte(byte(Sequence))
		pduBuf.WriteByte(byte(len(oid) + len(octetStringBytes) + 4))
		pduBuf.Write(tmpBuf.Bytes())

	default:
		return nil, fmt.Errorf("Unable to marshal PDU: unknown BER type %d", pdu.Type)
	}

	return pduBuf.Bytes(), nil
}

// -- Unmarshalling Logic ------------------------------------------------------

func (x *GoSNMP) unmarshal(packet []byte) (*SnmpPacket, error) {
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
	if response.Version != Version3 {
		// Parse community
		rawCommunity, count, err := parseRawField(packet[cursor:], "community")
		if err != nil {
			return nil, fmt.Errorf("Error parsing community string: %s", err.Error())
		}
		cursor += count
		if community, ok := rawCommunity.(string); ok {
			response.Community = community
			if LoggingDisabled != true {
				slog.Printf("Parsed community %s", community)
			}
		}
	} else {
		if PDUType(packet[cursor]) != Sequence {
			return nil, fmt.Errorf("Invalid SNMPV3 Header\n")
		}

		_, cursorTmp := parseLength(packet[cursor:])
		cursor += cursorTmp

		rawMsgID, count, err := parseRawField(packet[cursor:], "msgID")
		if err != nil {
			return nil, fmt.Errorf("Error parsing SNMPV3 message ID: %s", err.Error())
		}
		cursor += count
		if MsgID, ok := rawMsgID.(int); ok {
			response.MsgID = uint32(MsgID)
			if LoggingDisabled != true {
				slog.Printf("Parsed message ID %d", MsgID)

			}
		}
		// discard msg max size
		_, count, err = parseRawField(packet[cursor:], "maxMsgSize")
		if err != nil {
			return nil, fmt.Errorf("Error parsing SNMPV3 maxMsgSize: %s", err.Error())
		}
		cursor += count
		// discard msg max size

		rawMsgFlags, count, err := parseRawField(packet[cursor:], "msgFlags")
		if err != nil {
			return nil, fmt.Errorf("Error parsing SNMPV3 msgFlags: %s", err.Error())
		}
		cursor += count
		if MsgFlags, ok := rawMsgFlags.(string); ok {
			response.MsgFlags = SnmpV3MsgFlags(MsgFlags[0])
			if LoggingDisabled != true {
				slog.Printf("parsed msg flags %s", MsgFlags)
			}
		}

		rawSecModel, count, err := parseRawField(packet[cursor:], "msgSecurityModel")
		if err != nil {
			return nil, fmt.Errorf("Error parsing SNMPV3 msgSecModel: %s", err.Error())
		}
		cursor += count
		if SecModel, ok := rawSecModel.(int); ok {
			response.SecurityModel = SnmpV3SecurityModel(SecModel)
			if LoggingDisabled != true {
				slog.Printf("Parsed security model %d", SecModel)
			}
		}

		if PDUType(packet[cursor]) != OctetString {
			return nil, fmt.Errorf("Invalid SNMPV3 Security Parameters\n")
		}
		_, cursorTmp = parseLength(packet[cursor:])
		cursor += cursorTmp

		if response.SecurityModel == UserSecurityModel {
			var secParameters UsmSecurityParameters
			if x.SecurityModel == UserSecurityModel {
				baseSecParams, ok := x.SecurityParameters.(*UsmSecurityParameters)
				if !ok || baseSecParams == nil {
					return nil, fmt.Errorf("&GoSNMP.SecurityModel indicates the User Security Model, but &GoSNMP.SecurityParameters is not of type &UsmSecurityParameters")
				}
				secParameters.AuthenticationProtocol = baseSecParams.AuthenticationProtocol
				secParameters.PrivacyProtocol = baseSecParams.PrivacyProtocol
				secParameters.PrivacyPassphrase = baseSecParams.PrivacyPassphrase
			}
			if PDUType(packet[cursor]) != Sequence {
				return nil, fmt.Errorf("Error parsing SNMPV3 User Security Model parameters\n")
			}
			_, cursorTmp = parseLength(packet[cursor:])
			cursor += cursorTmp

			rawMsgAuthoritativeEngineID, count, err := parseRawField(packet[cursor:], "msgAuthoritativeEngineID")
			if err != nil {
				return nil, fmt.Errorf("Error parsing SNMPV3 User Security Model msgAuthoritativeEngineID: %s", err.Error())
			}
			cursor += count
			if AuthoritativeEngineID, ok := rawMsgAuthoritativeEngineID.(string); ok {
				secParameters.AuthoritativeEngineID = AuthoritativeEngineID
				if LoggingDisabled != true {
					slog.Printf("Parsed authoritativeEngineID %s", AuthoritativeEngineID)
				}
			}

			rawMsgAuthoritativeEngineBoots, count, err := parseRawField(packet[cursor:], "msgAuthoritativeEngineBoots")
			if err != nil {
				return nil, fmt.Errorf("Error parsing SNMPV3 User Security Model msgAuthoritativeEngineBoots: %s", err.Error())
			}
			cursor += count
			if AuthoritativeEngineBoots, ok := rawMsgAuthoritativeEngineBoots.(int); ok {
				secParameters.AuthoritativeEngineBoots = uint32(AuthoritativeEngineBoots)
				if LoggingDisabled != true {
					slog.Printf("Parsed authoritativeEngineBoots %d", AuthoritativeEngineBoots)
				}
			}

			rawMsgAuthoritativeEngineTime, count, err := parseRawField(packet[cursor:], "msgAuthoritativeEngineTime")
			if err != nil {
				return nil, fmt.Errorf("Error parsing SNMPV3 User Security Model msgAuthoritativeEngineTime: %s", err.Error())
			}
			cursor += count
			if AuthoritativeEngineTime, ok := rawMsgAuthoritativeEngineTime.(int); ok {
				secParameters.AuthoritativeEngineTime = uint32(AuthoritativeEngineTime)
				if LoggingDisabled != true {
					slog.Printf("Parsed authoritativeEngineTime %d", AuthoritativeEngineTime)
				}
			}

			rawMsgUserName, count, err := parseRawField(packet[cursor:], "msgUserName")
			if err != nil {
				return nil, fmt.Errorf("Error parsing SNMPV3 User Security Model msgUserName: %s", err.Error())
			}
			cursor += count
			if msgUserName, ok := rawMsgUserName.(string); ok {
				secParameters.UserName = msgUserName
				if LoggingDisabled != true {
					slog.Printf("Parsed userName %s", msgUserName)
				}
			}

			rawMsgAuthParameters, count, err := parseRawField(packet[cursor:], "msgAuthenticationParameters")
			if err != nil {
				return nil, fmt.Errorf("Error parsing SNMPV3 User Security Model msgAuthenticationParameters: %s", err.Error())
			}
			cursor += count
			if msgAuthenticationParameters, ok := rawMsgAuthParameters.(string); ok {
				secParameters.AuthenticationParameters = msgAuthenticationParameters
				if LoggingDisabled != true {
					slog.Printf("Parsed authenticationParameters %s", msgAuthenticationParameters)
				}
			}

			rawMsgPrivacyParameters, count, err := parseRawField(packet[cursor:], "msgPrivacyParameters")
			if err != nil {
				return nil, fmt.Errorf("Error parsing SNMPV3 User Security Model msgPrivacyParameters: %s", err.Error())
			}
			cursor += count
			if msgPrivacyParameters, ok := rawMsgPrivacyParameters.(string); ok {
				secParameters.PrivacyParameters = []byte(msgPrivacyParameters)
				if LoggingDisabled != true {
					slog.Printf("Parsed privacyParameters %s", msgPrivacyParameters)
				}
			}

			response.SecurityParameters = &secParameters
		}
		switch PDUType(packet[cursor]) {
		case OctetString:
			// pdu is encrypted
			_, cursorTmp := parseLength(packet[cursor:])
			cursorTmp += cursor

			if response.SecurityModel == UserSecurityModel {
				var secParams *UsmSecurityParameters
				secParams, ok := response.SecurityParameters.(*UsmSecurityParameters)
				if !ok || secParams == nil {
					return nil, fmt.Errorf("response.SecurityModel indicates the User Security Model, but response.SecurityParameters is not of type &UsmSecurityParameters")
				}
				var privkey = genlocalkey(secParams.AuthenticationProtocol,
					secParams.PrivacyPassphrase,
					secParams.AuthoritativeEngineID)
				switch secParams.PrivacyProtocol {
				case AES:
					var iv [16]byte
					binary.BigEndian.PutUint32(iv[:], secParams.AuthoritativeEngineBoots)
					binary.BigEndian.PutUint32(iv[4:], secParams.AuthoritativeEngineTime)
					copy(iv[8:], secParams.PrivacyParameters)

					block, err := aes.NewCipher(privkey[:16])
					if err != nil {
						return nil, err
					}
					stream := cipher.NewCFBDecrypter(block, iv[:])
					plaintext := make([]byte, len(packet[cursorTmp:]))
					stream.XORKeyStream(plaintext, packet[cursorTmp:])
					copy(packet[cursor:], plaintext)
					packet = packet[:cursor+len(plaintext)]
				default:
					if len(packet[cursorTmp:])%des.BlockSize != 0 {
						return nil, fmt.Errorf("Error decrypting ScopedPDU: not multiple of des block size.")
					}
					preiv := privkey[8:]
					var iv [8]byte
					for i := 0; i < len(iv); i++ {
						iv[i] = preiv[i] ^ secParams.PrivacyParameters[i]
					}
					block, err := des.NewCipher(privkey[:8])
					if err != nil {
						return nil, err
					}
					mode := cipher.NewCBCDecrypter(block, iv[:])

					plaintext := make([]byte, len(packet[cursorTmp:]))
					mode.CryptBlocks(plaintext, packet[cursorTmp:])
					copy(packet[cursor:], plaintext)
					// truncate packet to remove extra space caused by the
					// octetstring/length header that was just replaced
					packet = packet[:cursor+len(plaintext)]
				}

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
				return nil, fmt.Errorf("Error parsing SNMPV3 contextEngineID: %s", err.Error())
			}
			cursor += count
			if contextEngineID, ok := rawContextEngineID.(string); ok {
				response.ContextEngineID = contextEngineID
				if LoggingDisabled != true {
					slog.Printf("Parsed contextEngineID %s", contextEngineID)
				}
			}
			rawContextName, count, err := parseRawField(packet[cursor:], "contextName")
			if err != nil {
				return nil, fmt.Errorf("Error parsing SNMPV3 contextName: %s", err.Error())
			}
			cursor += count
			if contextName, ok := rawContextName.(string); ok {
				response.ContextName = contextName
				if LoggingDisabled != true {
					slog.Printf("Parsed contextName %s", contextName)
				}
			}

		default:
			return nil, fmt.Errorf("Error parsing SNMPV3 scoped PDU\n")
		}
	}
	// Parse SNMP packet type
	requestType := PDUType(packet[cursor])
	switch requestType {
	// known, supported types
	case GetResponse, GetNextRequest, GetBulkRequest, Report:
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

	// check for an empty response
	if vblLength == 2 && packet[1] == 0x00 {
		return response, nil
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

// dispatch request on network, and read the results into a byte array
//
// Previously, resp was allocated rxBufSize (65536) bytes ie a fixed size for
// all responses. To decrease memory usage, resp is dynamically sized, at the
// cost of possible additional network round trips.
func dispatch(c net.Conn, outBuf []byte, expected int) ([]byte, error) {
	if expected <= 0 {
		expected = 1
	}
	var resp []byte

	for bufSize := rxBufSizeMin * expected; bufSize < rxBufSizeMax; bufSize *= 2 {
		resp = make([]byte, bufSize)
		_, err := c.Write(outBuf)
		if err != nil {
			return resp, fmt.Errorf("Error writing to socket: %s", err.Error())
		}
		n, err := c.Read(resp)
		if err != nil {
			// On Windows we don't get a partial read and truncation. Instead
			// we get an error if buff is too small - WSAEMSGSIZE 10040.
			const WSAEMSGSIZE syscall.Errno = 10040
			if opErr, ok := err.(*net.OpError); ok {
				if opErr.Err == WSAEMSGSIZE {
					continue
				}
			}
			return resp, fmt.Errorf("Error reading from UDP: %s", err.Error())
		}

		if n < bufSize {
			// Memory usage optimization. Help the runtime to release as much memory as
			// possible.
			//
			// See: http://blog.golang.org/go-slices-usage-and-internals,
			//    section: A possible "gotcha"
			// ...As mentioned earlier, re-slicing a slice doesn't make a copy of the
			// underlying array. The full array will be kept in memory until it is no
			// longer referenced. Occasionally this can cause the program to hold all
			// the data in memory when only a small piece of it is needed.
			resp = resp[:n]
			resp2 := make([]byte, len(resp))
			copy(resp2, resp)
			return resp2, nil
		}
		slog.Printf("Retrying. Buffer size was too small. (size %d)", bufSize)
	}
	return resp, fmt.Errorf("Response bufSize exceeded rxBufSizeMax (%d)", rxBufSizeMax)
}
