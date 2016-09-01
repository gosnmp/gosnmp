package gosnmp

// Copyright 2012-2014 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"
	"sync/atomic"
)

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

// MD5 HMAC key calculation algorithm
func md5HMAC(password string, engineID string) []byte {
	comp := md5.New()
	var pi int // password index
	for i := 0; i < 1048576; i += 64 {
		var chunk []byte
		for e := 0; e < 64; e++ {
			chunk = append(chunk, password[pi%len(password)])
			pi++
		}
		comp.Write(chunk)
	}
	compressed := comp.Sum(nil)
	local := md5.New()
	local.Write(compressed)
	local.Write([]byte(engineID))
	local.Write(compressed)
	final := local.Sum(nil)
	return final
}

// SHA HMAC key calculation algorithm
func shaHMAC(password string, engineID string) []byte {
	hash := sha1.New()
	var pi int // password index
	for i := 0; i < 1048576; i += 64 {
		var chunk []byte
		for e := 0; e < 64; e++ {
			chunk = append(chunk, password[pi%len(password)])
			pi++
		}
		hash.Write(chunk)
	}
	hashed := hash.Sum(nil)
	local := sha1.New()
	local.Write(hashed)
	local.Write([]byte(engineID))
	local.Write(hashed)
	final := local.Sum(nil)
	return final
}

func genlocalkey(authProtocol SnmpV3AuthProtocol, passphrase string, engineID string) []byte {
	var secretKey []byte
	switch authProtocol {
	default:
		secretKey = md5HMAC(passphrase, engineID)
	case SHA:
		secretKey = shaHMAC(passphrase, engineID)
	}
	return secretKey
}

/*
Here onwards is a refactoring of Whit's snmpv3 code - the large chunks of code
were affecting the legibility of the main code. Some of the function names may
not reflect their true purpose. Sonia.
*/

func (x *GoSNMP) buildPacket3(msgID uint32, allMsgIDs []uint32,
	packetOut *SnmpPacket) (*SnmpPacket, error) {
	msgID = atomic.AddUint32(&(x.msgID), 1) // TODO: fix overflows
	allMsgIDs = append(allMsgIDs, msgID)

	// http://tools.ietf.org/html/rfc2574#section-8.1.1.1
	// localDESSalt needs to be incremented on every packet.
	if x.MsgFlags&AuthPriv > AuthNoPriv && x.SecurityModel == UserSecurityModel {
		baseSecParams, ok := x.SecurityParameters.(*UsmSecurityParameters)
		if !ok || baseSecParams == nil {
			err := fmt.Errorf("&GoSNMP.SecurityModel indicates the User Security Model, but &GoSNMP.SecurityParameters is not of type &UsmSecurityParameters")
			return nil, err
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
				err := fmt.Errorf("packetOut.SecurityModel indicates the User Security Model, but packetOut.SecurityParameters is not of type &UsmSecurityParameters")
				return nil, err
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
	return packetOut, nil
}

func (x *GoSNMP) setSalt() error {
	var err error
	x.MsgFlags |= Reportable // tell the snmp server that a report PDU MUST be sent
	if x.SecurityModel == UserSecurityModel {
		secParams, ok := x.SecurityParameters.(*UsmSecurityParameters)
		if !ok || secParams == nil {
			return fmt.Errorf("&GoSNMP.SecurityModel indicates the User Security Model, but &GoSNMP.SecurityParameters is not of type &UsmSecurityParameters")
		}
		switch secParams.PrivacyProtocol {
		case AES:
			salt := make([]byte, 8)
			_, err = crand.Read(salt)
			if err != nil {
				return fmt.Errorf("Error creating a cryptographically secure salt: %s\n", err.Error())
			}
			secParams.localAESSalt = binary.BigEndian.Uint64(salt)
		case DES:
			salt := make([]byte, 4)
			_, err = crand.Read(salt)
			if err != nil {
				return fmt.Errorf("Error creating a cryptographically secure salt: %s\n", err.Error())
			}
			secParams.localDESSalt = binary.BigEndian.Uint32(salt)
		}
	}
	return nil
}

// http://tools.ietf.org/html/rfc2574#section-2.2.3 This code does not
// check if the last message received was more than 150 seconds ago The
// snmpds that this code was tested on emit an 'out of time window'
// error with the new time and this code will retransmit when that is
// received.
func (x *GoSNMP) setAuthoritativeEngine(packetOut *SnmpPacket, wait bool) (*SnmpPacket, error) {
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
				Logger:             x.Logger,
			}
			var emptyPdus []SnmpPDU
			result, err := x.sendOneRequest(emptyPdus, blankPacket, wait)

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
	return packetOut, nil
}

// refactor: this probably does something else than
// setAuthoritativeEngine, but the code is *opaque*
func (x *GoSNMP) setAuthoritativeEngine2(packetOut *SnmpPacket, result *SnmpPacket, pdus []SnmpPDU, wait bool) (*SnmpPacket, error) {

	secParams, ok := result.SecurityParameters.(*UsmSecurityParameters)
	if !ok || secParams == nil {
		return &SnmpPacket{}, fmt.Errorf("result.SecurityModel indicates the User Security Model, but result.SecurityParameters is not of type &UsmSecurityParameters")
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
			return &SnmpPacket{}, fmt.Errorf("packetOut.SecurityModel indicates the User Security Model, but packetOut.SecurityParameters is not of type &UsmSecurityParameters")
		}
		pktSecParams.AuthoritativeEngineID = secParams.AuthoritativeEngineID
		pktSecParams.AuthoritativeEngineBoots = secParams.AuthoritativeEngineBoots
		pktSecParams.AuthoritativeEngineTime = secParams.AuthoritativeEngineTime

		if packetOut.ContextEngineID == "" {
			packetOut.ContextEngineID = secParams.AuthoritativeEngineID
		}

		return x.sendOneRequest(pdus, packetOut, wait)
	}
	return x.sendOneRequest(pdus, packetOut, wait)
}

func (packet *SnmpPacket) prepV3pPDU(
	msgid uint32,
	buf *bytes.Buffer,
	pdus []SnmpPDU,
	requestid uint32) (*bytes.Buffer, uint32, error) {

	emptyBuffer := new(bytes.Buffer) // used when returning errors
	var authParamStart uint32

	header, err := packet.marshalSnmpV3Header(msgid)
	if err != nil {
		return emptyBuffer, 0, err
	}
	buf.Write([]byte{byte(Sequence), byte(len(header))})
	buf.Write(header)

	var securityParameters []byte
	if packet.SecurityModel == UserSecurityModel {
		securityParameters, authParamStart, err = packet.marshalSnmpV3UsmSecurityParameters()
		if err != nil {
			return emptyBuffer, 0, err
		}
	}

	buf.Write([]byte{byte(OctetString)})
	secParamLen, err := marshalLength(len(securityParameters))
	if err != nil {
		return emptyBuffer, 0, err
	}
	buf.Write(secParamLen)
	authParamStart += uint32(buf.Len())
	buf.Write(securityParameters)

	scopedPdu, err := packet.marshalSnmpV3ScopedPDU(pdus, requestid)
	if err != nil {
		return emptyBuffer, 0, err
	}
	buf.Write(scopedPdu)
	return buf, authParamStart, nil
}

func (x *GoSNMP) extractV3Packet(packet []byte,
	cursor int,
	response *SnmpPacket,
	OrigAuthEngineID string) ([]byte, int, error) {

	if PDUType(packet[cursor]) != Sequence {
		return nil, 0, fmt.Errorf("Invalid SNMPV3 Header\n")
	}

	_, cursorTmp := parseLength(packet[cursor:])
	cursor += cursorTmp

	rawMsgID, count, err := x.parseRawField(packet[cursor:], "msgID")
	if err != nil {
		return nil, 0, fmt.Errorf("Error parsing SNMPV3 message ID: %s", err.Error())
	}
	cursor += count
	if MsgID, ok := rawMsgID.(int); ok {
		response.MsgID = uint32(MsgID)
		if x.loggingEnabled {
			x.Logger.Printf("Parsed message ID %d", MsgID)

		}
	}
	// discard msg max size
	_, count, err = x.parseRawField(packet[cursor:], "maxMsgSize")
	if err != nil {
		return nil, 0, fmt.Errorf("Error parsing SNMPV3 maxMsgSize: %s", err.Error())
	}
	cursor += count
	// discard msg max size

	rawMsgFlags, count, err := x.parseRawField(packet[cursor:], "msgFlags")
	if err != nil {
		return nil, 0, fmt.Errorf("Error parsing SNMPV3 msgFlags: %s", err.Error())
	}
	cursor += count
	if MsgFlags, ok := rawMsgFlags.(string); ok {
		response.MsgFlags = SnmpV3MsgFlags(MsgFlags[0])
		if x.loggingEnabled {
			x.Logger.Printf("parsed msg flags %s", MsgFlags)
		}
	}

	rawSecModel, count, err := x.parseRawField(packet[cursor:], "msgSecurityModel")
	if err != nil {
		return nil, 0, fmt.Errorf("Error parsing SNMPV3 msgSecModel: %s", err.Error())
	}
	cursor += count
	if SecModel, ok := rawSecModel.(int); ok {
		response.SecurityModel = SnmpV3SecurityModel(SecModel)
		if x.loggingEnabled {
			x.Logger.Printf("Parsed security model %d", SecModel)
		}
	}

	if PDUType(packet[cursor]) != OctetString {
		return nil, 0, fmt.Errorf("Invalid SNMPV3 Security Parameters\n")
	}
	_, cursorTmp = parseLength(packet[cursor:])
	cursor += cursorTmp

	if response.SecurityModel == UserSecurityModel {
		secParameters, ok := response.SecurityParameters.(*UsmSecurityParameters)
		if !ok || secParameters == nil {
			return nil, 0, fmt.Errorf("&GoSNMP.SecurityModel indicates the User Security Model, but &GoSNMP.SecurityParameters is not of type &UsmSecurityParameters")
		}

		if PDUType(packet[cursor]) != Sequence {
			return nil, 0, fmt.Errorf("Error parsing SNMPV3 User Security Model parameters\n")
		}
		_, cursorTmp = parseLength(packet[cursor:])
		cursor += cursorTmp

		rawMsgAuthoritativeEngineID, count, err := x.parseRawField(packet[cursor:], "msgAuthoritativeEngineID")
		if err != nil {
			return nil, 0, fmt.Errorf("Error parsing SNMPV3 User Security Model msgAuthoritativeEngineID: %s", err.Error())
		}
		cursor += count
		if AuthoritativeEngineID, ok := rawMsgAuthoritativeEngineID.(string); ok {
			secParameters.AuthoritativeEngineID = AuthoritativeEngineID
			if x.loggingEnabled {
				x.Logger.Printf("Parsed authoritativeEngineID %s", AuthoritativeEngineID)
			}
		}

		rawMsgAuthoritativeEngineBoots, count, err := x.parseRawField(packet[cursor:], "msgAuthoritativeEngineBoots")
		if err != nil {
			return nil, 0, fmt.Errorf("Error parsing SNMPV3 User Security Model msgAuthoritativeEngineBoots: %s", err.Error())
		}
		cursor += count
		if AuthoritativeEngineBoots, ok := rawMsgAuthoritativeEngineBoots.(int); ok {
			secParameters.AuthoritativeEngineBoots = uint32(AuthoritativeEngineBoots)
			if x.loggingEnabled {
				x.Logger.Printf("Parsed authoritativeEngineBoots %d", AuthoritativeEngineBoots)
			}
		}

		rawMsgAuthoritativeEngineTime, count, err := x.parseRawField(packet[cursor:], "msgAuthoritativeEngineTime")
		if err != nil {
			return nil, 0, fmt.Errorf("Error parsing SNMPV3 User Security Model msgAuthoritativeEngineTime: %s", err.Error())
		}
		cursor += count
		if AuthoritativeEngineTime, ok := rawMsgAuthoritativeEngineTime.(int); ok {
			secParameters.AuthoritativeEngineTime = uint32(AuthoritativeEngineTime)
			if x.loggingEnabled {
				x.Logger.Printf("Parsed authoritativeEngineTime %d", AuthoritativeEngineTime)
			}
		}

		rawMsgUserName, count, err := x.parseRawField(packet[cursor:], "msgUserName")
		if err != nil {
			return nil, 0, fmt.Errorf("Error parsing SNMPV3 User Security Model msgUserName: %s", err.Error())
		}
		cursor += count
		if msgUserName, ok := rawMsgUserName.(string); ok {
			secParameters.UserName = msgUserName
			if x.loggingEnabled {
				x.Logger.Printf("Parsed userName %s", msgUserName)
			}
		}

		rawMsgAuthParameters, count, err := x.parseRawField(packet[cursor:], "msgAuthenticationParameters")
		if err != nil {
			return nil, 0, fmt.Errorf("Error parsing SNMPV3 User Security Model msgAuthenticationParameters: %s", err.Error())
		}

		if msgAuthenticationParameters, ok := rawMsgAuthParameters.(string); ok {
			secParameters.AuthenticationParameters = msgAuthenticationParameters
			if x.loggingEnabled {
				x.Logger.Printf("Parsed authenticationParameters %s", msgAuthenticationParameters)
			}
		}
		// use the authoritative copy of MsgFlags to determine whether this message should be authenticated
		var OrigMsgFlags = response.MsgFlags
		if OrigMsgFlags&AuthNoPriv > 0 {
			if count != 14 {
				return nil, 0, fmt.Errorf("Error authenticating incoming packet: msgAuthenticationParameters is not the correct size")
			}
			blank := make([]byte, 12)
			copy(packet[cursor+2:cursor+14], blank)
			// secParameters.AuthenticationProtocol and secParameters.AuthenticationPassphrase are not written to in this function,
			// so no need to save an 'original' to authenticate against
			if !isAuthentic(packet, secParameters.AuthenticationParameters,
				secParameters.AuthenticationProtocol,
				secParameters.AuthenticationPassphrase,
				OrigAuthEngineID) {
				return nil, 0, fmt.Errorf("Incoming packet is not authentic, discarding")
			}
		}
		cursor += count

		rawMsgPrivacyParameters, count, err := x.parseRawField(packet[cursor:], "msgPrivacyParameters")
		if err != nil {
			return nil, 0, fmt.Errorf("Error parsing SNMPV3 User Security Model msgPrivacyParameters: %s", err.Error())
		}
		cursor += count
		if msgPrivacyParameters, ok := rawMsgPrivacyParameters.(string); ok {
			secParameters.PrivacyParameters = []byte(msgPrivacyParameters)
			if x.loggingEnabled {
				x.Logger.Printf("Parsed privacyParameters %s", msgPrivacyParameters)
			}
		}

		//response.SecurityParameters = &secParameters
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
				return nil, 0, fmt.Errorf("response.SecurityModel indicates the User Security Model, but response.SecurityParameters is not of type &UsmSecurityParameters")
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
					return nil, 0, err
				}
				stream := cipher.NewCFBDecrypter(block, iv[:])
				plaintext := make([]byte, len(packet[cursorTmp:]))
				stream.XORKeyStream(plaintext, packet[cursorTmp:])
				copy(packet[cursor:], plaintext)
				packet = packet[:cursor+len(plaintext)]
			default:
				if len(packet[cursorTmp:])%des.BlockSize != 0 {
					return nil, 0, fmt.Errorf("Error decrypting ScopedPDU: not multiple of des block size.")
				}
				preiv := privkey[8:]
				var iv [8]byte
				for i := 0; i < len(iv); i++ {
					iv[i] = preiv[i] ^ secParams.PrivacyParameters[i]
				}
				block, err := des.NewCipher(privkey[:8])
				if err != nil {
					return nil, 0, err
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
		rawContextEngineID, count, err := x.parseRawField(packet[cursor:], "contextEngineID")
		if err != nil {
			return nil, 0, fmt.Errorf("Error parsing SNMPV3 contextEngineID: %s", err.Error())
		}
		cursor += count
		if contextEngineID, ok := rawContextEngineID.(string); ok {
			response.ContextEngineID = contextEngineID
			if x.loggingEnabled {
				x.Logger.Printf("Parsed contextEngineID %s", contextEngineID)
			}
		}
		rawContextName, count, err := x.parseRawField(packet[cursor:], "contextName")
		if err != nil {
			return nil, 0, fmt.Errorf("Error parsing SNMPV3 contextName: %s", err.Error())
		}
		cursor += count
		if contextName, ok := rawContextName.(string); ok {
			response.ContextName = contextName
			if x.loggingEnabled {
				x.Logger.Printf("Parsed contextName %s", contextName)
			}
		}

	default:
		return nil, 0, fmt.Errorf("Error parsing SNMPV3 scoped PDU\n")
	}
	return packet, cursor, nil
}
