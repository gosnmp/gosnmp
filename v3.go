package gosnmp

import (
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
