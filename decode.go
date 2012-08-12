// Copyright 2012 Andreas Louca. All rights reserved.
// Use of this source code is goverend by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"encoding/asn1"
	"fmt"
)

type Asn1BER byte

const (
	Integer          Asn1BER = 0x02
	BitString                = 0x03
	OctetString              = 0x04
	Null                     = 0x05
	ObjectIdentifier         = 0x06
	Counter32                = 0x41
	Gauge32                  = 0x42
	TimeTicks                = 0x43
	Opaque                   = 0x44
	NsapAddress              = 0x45
	Counter64                = 0x46
	Uinteger32               = 0x47
)

// Different packet structure is needed during decode, to trick encoding/asn1 to decode the SNMP packet

type Variable struct {
	Name  asn1.ObjectIdentifier
	Type  Asn1BER
	Value interface{}
}

type VarBind struct {
	Name  asn1.ObjectIdentifier
	Value asn1.RawValue
}

type PDU struct {
	RequestId   int32
	ErrorStatus int
	ErrorIndex  int
	VarBindList []VarBind
}
type PDUResponse struct {
	RequestId   int32
	ErrorStatus int
	ErrorIndex  int
	VarBindList []*Variable
}

type Message struct {
	Version   int
	Community []uint8
	Data      asn1.RawValue
}

func decode(data []byte) (*PDUResponse, error) {
	m := Message{}
	_, err := asn1.Unmarshal(data, &m)
	if err != nil {
		fmt.Printf("Unable to unmarshal first packet: %#v", data)
		return nil, err
	}
	choice := m.Data.FullBytes[0]
	switch choice {
	// SNMP Response
	case 0xa0, 0xa1, 0xa2:

		pdu := new(PDU)

		// hack ANY -> IMPLICIT SEQUENCE
		m.Data.FullBytes[0] = 0x30
		_, err = asn1.Unmarshal(m.Data.FullBytes, pdu)
		if err != nil {
			fmt.Printf("Error decoding pdu: %s\n", err.Error())
			return nil, fmt.Errorf("%#v, %#v, %s", m.Data.FullBytes, pdu, err)
		}

		// make response pdu
		resp := new(PDUResponse)
		// Copy values from parsed pdu
		resp.RequestId = pdu.RequestId
		resp.ErrorIndex = pdu.ErrorIndex
		resp.ErrorStatus = pdu.ErrorStatus

		resp.VarBindList = make([]*Variable, len(pdu.VarBindList))

		// Decode all vars
		for c, v := range pdu.VarBindList {

			val, err := decodeValue(v.Value)
			if err != nil {
				return nil, err
			} else {
				val.Name = v.Name
				resp.VarBindList[c] = val
			}
		}

		return resp, nil
	default:
		return nil, fmt.Errorf("Unable to decode type: %#v\n", choice)
	}
	return nil, fmt.Errorf("Unknown CHOICE: %x", choice)
}

func decodeValue(data asn1.RawValue) (retVal *Variable, err error) {
	retVal = new(Variable)

	switch Asn1BER(data.FullBytes[0]) {

	// Integer
	case Integer:
		ret, err := parseInt(data.FullBytes[2:])
		if err != nil {
			break
		}
		retVal.Type = Integer
		retVal.Value = ret
	// Octet
	case OctetString:
		retVal.Type = OctetString
		retVal.Value = data.FullBytes[2:]
	// Counter32
	case Counter32:
		ret, err := parseInt(data.FullBytes[2:])
		if err != nil {
			break
		}
		retVal.Type = Counter32
		retVal.Value = ret
	case TimeTicks:
		ret, err := parseInt(data.FullBytes[2:])
		if err != nil {
			break
		}
		retVal.Type = TimeTicks
		retVal.Value = ret
	// Gauge32
	case Gauge32:
		ret, err := parseInt(data.FullBytes[2:])
		if err != nil {
			break
		}
		retVal.Type = Gauge32
		retVal.Value = ret
	case Counter64:
		ret, err := parseInt64(data.FullBytes[2:])

		// Decode it
		if err != nil {
			break
		}

		retVal.Type = Counter64
		retVal.Value = ret
	default:
		fmt.Printf("Unable to decode type %x\n", data.FullBytes[0])
	}

	return
}
