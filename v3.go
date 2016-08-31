package gosnmp

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
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
