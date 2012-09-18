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
	NoSuchObject             = 0x80
	NoSuchInstance           = 0x81
)

// Different packet structure is needed during decode, to trick encoding/asn1 to decode the SNMP packet

type Variable struct {
	Name  []int
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
			return nil, fmt.Errorf("Error decoding pdu: %#v, %#v, %s", m.Data.FullBytes, pdu, err)
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

			val, err := decodeValue(v.Value.FullBytes)
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

func decodeValue(data []byte) (retVal *Variable, err error) {
	retVal = new(Variable)

	switch Asn1BER(data[0]) {

	// Integer
	case Integer:
		ret, err := parseInt(data[2:])
		if err != nil {
			break
		}
		retVal.Type = Integer
		retVal.Value = ret
	// Octet
	case OctetString:
		retVal.Type = OctetString
		retVal.Value = string(data[2:])
	// Counter32
	case Counter32:
		ret, err := parseInt(data[2:])
		if err != nil {
			break
		}
		retVal.Type = Counter32
		retVal.Value = ret
	case TimeTicks:
		ret, err := parseInt(data[2:])
		if err != nil {
			break
		}
		retVal.Type = TimeTicks
		retVal.Value = ret
	// Gauge32
	case Gauge32:
		ret, err := parseInt(data[2:])
		if err != nil {
			break
		}
		retVal.Type = Gauge32
		retVal.Value = ret
	case Counter64:
		ret, err := parseInt64(data[2:])

		// Decode it
		if err != nil {
			break
		}

		retVal.Type = Counter64
		retVal.Value = ret
	case NoSuchInstance:
		return nil, fmt.Errorf("No such instance")
	case NoSuchObject:
		return nil, fmt.Errorf("No such object")
	default:
		err = fmt.Errorf("Unable to decode %x - not implemented", data[0])
	}

	return
}

// Parses UINT16
func ParseUint16(content []byte) int {
	number := uint8(content[1]) | uint8(content[0])<<8
	//fmt.Printf("\t%d\n", number)

	return int(number)
}
