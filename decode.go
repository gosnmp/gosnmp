// Copyright 2012 Andreas Louca. All rights reserved.
// Use of this source code is goverend by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"encoding/asn1"
	"errors"
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
	VarBindList []Variable
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

		resp.VarBindList = make([]Variable, len(pdu.VarBindList))

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
		fmt.Printf("Unable to decode type: %#v\n", choice)
	}
	return nil, fmt.Errorf("Unknown CHOICE: %x", choice)
}

func decodeValue(data asn1.RawValue) (retVal Variable, err error) {
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

// The following code bares the following license & copyright
//
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// parseInt64 treats the given bytes as a big-endian, signed integer and
// returns the result.
func parseInt64(bytes []byte) (ret int64, err error) {
	if len(bytes) > 8 {
		// We'll overflow an int64 in this case.
		err = errors.New("integer too large")
		return
	}
	for bytesRead := 0; bytesRead < len(bytes); bytesRead++ {
		ret <<= 8
		ret |= int64(bytes[bytesRead])
	}

	// Shift up and down in order to sign extend the result.
	ret <<= 64 - uint8(len(bytes))*8
	ret >>= 64 - uint8(len(bytes))*8
	return
}

// parseInt treats the given bytes as a big-endian, signed integer and returns
// the result.
func parseInt(bytes []byte) (int, error) {
	ret64, err := parseInt64(bytes)
	if err != nil {
		return 0, err
	}
	if ret64 != int64(int(ret64)) {
		return 0, errors.New("integer too large")
	}
	return int(ret64), nil
}

// BIT STRING

// BitStringValue is the structure to use when you want an ASN.1 BIT STRING type. A
// bit string is padded up to the nearest byte in memory and the number of
// valid bits is recorded. Padding bits will be zero.
type BitStringValue struct {
	Bytes     []byte // bits packed into bytes.
	BitLength int    // length in bits.
}

// At returns the bit at the given index. If the index is out of range it
// returns false.
func (b BitStringValue) At(i int) int {
	if i < 0 || i >= b.BitLength {
		return 0
	}
	x := i / 8
	y := 7 - uint(i%8)
	return int(b.Bytes[x]>>y) & 1
}

// RightAlign returns a slice where the padding bits are at the beginning. The
// slice may share memory with the BitString.
func (b BitStringValue) RightAlign() []byte {
	shift := uint(8 - (b.BitLength % 8))
	if shift == 8 || len(b.Bytes) == 0 {
		return b.Bytes
	}

	a := make([]byte, len(b.Bytes))
	a[0] = b.Bytes[0] >> shift
	for i := 1; i < len(b.Bytes); i++ {
		a[i] = b.Bytes[i-1] << (8 - shift)
		a[i] |= b.Bytes[i] >> shift
	}

	return a
}

// parseBitString parses an ASN.1 bit string from the given byte slice and returns it.
func parseBitString(bytes []byte) (ret BitStringValue, err error) {
	if len(bytes) == 0 {
		err = errors.New("zero length BIT STRING")
		return
	}
	paddingBits := int(bytes[0])
	if paddingBits > 7 ||
		len(bytes) == 1 && paddingBits > 0 ||
		bytes[len(bytes)-1]&((1<<bytes[0])-1) != 0 {
		err = errors.New("invalid padding bits in BIT STRING")
		return
	}
	ret.BitLength = (len(bytes)-1)*8 - paddingBits
	ret.Bytes = bytes[1:]
	return
}
