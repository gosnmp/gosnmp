// Copyright 2012 Andreas Louca and Jon Auer, 2013 Sonia Hamilton. All
// rights reserved.  Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"encoding/asn1"
	"fmt"
	l "github.com/alouca/gologger"
)

type Asn1BER byte

const (
	EndOfContents    Asn1BER = 0x00
	Boolean                  = 0x01
	Integer                  = 0x02
	BitString                = 0x03
	OctetString              = 0x04
	Null                     = 0x05
	ObjectIdentifier         = 0x06
	ObjectDesription         = 0x07
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

func decodeValue(data []byte, log *l.Logger, msg string) (retVal *Variable, err error) {
	log.Debug("%s: decodeValue got bytes: % #x...", msg, data[:10])
	retVal = new(Variable)

	switch Asn1BER(data[0]) {

	case Integer:
		// signed
		ret, err := parseInt(data[2:])
		if err != nil {
			break
		}
		retVal.Type = Integer
		retVal.Value = ret
	case OctetString:
		length, cursor := calc_length(data)
		retVal.Type = OctetString
		retVal.Value = string(data[cursor:length])
	case Counter32:
		// unsigned
		ret, err := parseUint(data[2:])
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
	case Gauge32:
		// unsigned
		ret, err := parseUint(data[2:])
		if err != nil {
			break
		}
		retVal.Type = Gauge32
		retVal.Value = ret
	case Counter64:
		ret, err := parseInt64(data[2:])
		if err != nil {
			break
		}
		retVal.Type = Counter64
		retVal.Value = ret
	case ObjectIdentifier:
		rawOid, _, err := parseRawField(data, log, "OID")
		if err != nil {
			return nil, fmt.Errorf("Error parsing OID Value: %s", err.Error())
		}
		var oid []int
		var ok bool
		if oid, ok = rawOid.([]int); !ok {
			return nil, fmt.Errorf("unable to type assert rawOid |%v| to []int", rawOid)
		}
		retVal.Type = ObjectIdentifier
		retVal.Value = oidToString(oid)
	case IpAddress:
		// total hack - IPv6? What IPv6...
		if len(data) < 6 {
			return nil, fmt.Errorf("not enough data for ipaddress: % x", data)
		} else if data[1] != 4 {
			return nil, fmt.Errorf("got ipaddress len %d, expected 4", data[1])
		}
		retVal.Type = IpAddress
		var ipv4 string
		for i := 2; i < 6; i++ {
			ipv4 += fmt.Sprintf(".%d", data[i])
		}
		retVal.Value = ipv4[1:]
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
