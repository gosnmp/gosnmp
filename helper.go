// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"strconv"
)

// variable struct is used by decodeValue()
type variable struct {
	Value any
	Type  Asn1BER
}

// helper error modes
var (
	ErrBase128IntegerTooLarge  = errors.New("base 128 integer too large")
	ErrBase128IntegerTruncated = errors.New("base 128 integer truncated")
	ErrFloatBufferTooShort     = errors.New("float buffer too short")
	ErrFloatTooLarge           = errors.New("float too large")
	ErrIntegerTooLarge         = errors.New("integer too large")
	ErrInvalidOidLength        = errors.New("invalid OID length")
	ErrInvalidPacketLength     = errors.New("invalid packet length")
	ErrZeroByteBuffer          = errors.New("zero byte buffer")
	ErrZeroLenInteger          = errors.New("zero length integer")
)

// -- helper functions (mostly) in alphabetical order --------------------------

// Check makes checking errors easy, so they actually get a minimal check
func (x *GoSNMP) Check(err error) {
	if err != nil {
		x.Logger.Printf("Check: %v\n", err)
		os.Exit(1)
	}
}

// Check makes checking errors easy, so they actually get a minimal check
func (packet *SnmpPacket) Check(err error) {
	if err != nil {
		packet.Logger.Printf("Check: %v\n", err)
		os.Exit(1)
	}
}

// Check makes checking errors easy, so they actually get a minimal check
func Check(err error) {
	if err != nil {
		log.Fatalf("Check: %v\n", err)
	}
}

func (x *GoSNMP) decodeValue(data []byte, retVal *variable) error {
	if len(data) == 0 {
		return ErrZeroByteBuffer
	}

	switch Asn1BER(data[0]) {
	case Integer, Uinteger32:
		// 0x02. signed
		x.Logger.Printf("decodeValue: type is %s", Asn1BER(data[0]).String())
		length, cursor, err := parseLength(data)
		if err != nil {
			return err
		}
		// check for truncated packets
		if length > len(data) {
			return fmt.Errorf("bytes: % x err: truncated (data %d length %d)", data, len(data), length)
		}

		var ret int
		if ret, err = parseInt(data[cursor:length]); err != nil {
			x.Logger.Printf("%v:", err)
			return fmt.Errorf("bytes: % x err: %w", data, err)
		}
		retVal.Type = Asn1BER(data[0])
		switch Asn1BER(data[0]) {
		case Uinteger32:
			retVal.Value = uint32(ret) //nolint:gosec
		default:
			retVal.Value = ret
		}

	case OctetString:
		// 0x04
		x.Logger.Print("decodeValue: type is OctetString")
		length, cursor, err := parseLength(data)
		if err != nil {
			return err
		}
		// check for truncated packet and throw an error
		if length > len(data) {
			return fmt.Errorf("bytes: % x err: truncated (data %d length %d)", data, len(data), length)
		}

		retVal.Type = OctetString
		retVal.Value = data[cursor:length]
	case Null:
		// 0x05
		x.Logger.Print("decodeValue: type is Null")
		retVal.Type = Null
		retVal.Value = nil
	case ObjectIdentifier:
		// 0x06
		x.Logger.Print("decodeValue: type is ObjectIdentifier")
		rawOid, _, err := parseRawField(x.Logger, data, "OID")
		if err != nil {
			return fmt.Errorf("error parsing OID Value: %w", err)
		}
		oid, ok := rawOid.(string)
		if !ok {
			return fmt.Errorf("unable to type assert rawOid |%v| to string", rawOid)
		}
		retVal.Type = ObjectIdentifier
		retVal.Value = oid
	case IPAddress:
		// 0x40
		x.Logger.Print("decodeValue: type is IPAddress")
		retVal.Type = IPAddress
		length, cursor, err := parseLength(data)
		if err != nil {
			return err
		}
		// length includes header bytes, ipLen is just the address bytes
		ipLen := length - cursor
		switch ipLen {
		case 0: // real life, buggy devices returning bad data
			retVal.Value = nil
			return nil
		case 4: // IPv4
			if len(data) < cursor+4 {
				return fmt.Errorf("not enough data for ipv4 address: %x", data)
			}
			retVal.Value = net.IP(data[cursor : cursor+4]).String()
		case 16: // IPv6
			if len(data) < cursor+16 {
				return fmt.Errorf("not enough data for ipv6 address: %x", data)
			}
			d := make(net.IP, 16)
			copy(d, data[cursor:cursor+16])
			retVal.Value = d.String()
		default:
			return fmt.Errorf("got ipaddress len %d, expected 4 or 16", ipLen)
		}
	case Counter32:
		// 0x41. unsigned
		x.Logger.Print("decodeValue: type is Counter32")
		length, cursor, err := parseLength(data)
		if err != nil {
			return err
		}
		if length > len(data) {
			return fmt.Errorf("not enough data for Counter32 %x (data %d length %d)", data, len(data), length)
		}

		ret, err := parseUint(data[cursor:length])
		if err != nil {
			x.Logger.Printf("decodeValue: err is %v", err)
			break
		}
		retVal.Type = Counter32
		retVal.Value = ret
	case Gauge32:
		// 0x42. unsigned
		x.Logger.Print("decodeValue: type is Gauge32")
		length, cursor, err := parseLength(data)
		if err != nil {
			return err
		}
		if length > len(data) {
			return fmt.Errorf("not enough data for Gauge32 %x (data %d length %d)", data, len(data), length)
		}

		ret, err := parseUint(data[cursor:length])
		if err != nil {
			x.Logger.Printf("decodeValue: err is %v", err)
			break
		}
		retVal.Type = Gauge32
		retVal.Value = ret
	case TimeTicks:
		// 0x43
		x.Logger.Print("decodeValue: type is TimeTicks")
		length, cursor, err := parseLength(data)
		if err != nil {
			return err
		}
		if length > len(data) {
			return fmt.Errorf("not enough data for TimeTicks %x (data %d length %d)", data, len(data), length)
		}

		ret, err := parseUint32(data[cursor:length])
		if err != nil {
			x.Logger.Printf("decodeValue: err is %v", err)
			break
		}
		retVal.Type = TimeTicks
		retVal.Value = ret
	case Opaque:
		// 0x44
		x.Logger.Print("decodeValue: type is Opaque")
		length, cursor, err := parseLength(data)
		if err != nil {
			return err
		}
		if length > len(data) {
			return fmt.Errorf("not enough data for Opaque %x (data %d length %d)", data, len(data), length)
		}
		return parseOpaque(x.Logger, data[cursor:length], retVal)
	case Counter64:
		// 0x46
		x.Logger.Print("decodeValue: type is Counter64")
		length, cursor, err := parseLength(data)
		if err != nil {
			return err
		}
		if length > len(data) {
			return fmt.Errorf("not enough data for Counter64 %x (data %d length %d)", data, len(data), length)
		}
		ret, err := parseUint64(data[cursor:length])
		if err != nil {
			x.Logger.Printf("decodeValue: err is %v", err)
			break
		}
		retVal.Type = Counter64
		retVal.Value = ret
	case NoSuchObject:
		// 0x80
		x.Logger.Print("decodeValue: type is NoSuchObject")
		retVal.Type = NoSuchObject
		retVal.Value = nil
	case NoSuchInstance:
		// 0x81
		x.Logger.Print("decodeValue: type is NoSuchInstance")
		retVal.Type = NoSuchInstance
		retVal.Value = nil
	case EndOfMibView:
		// 0x82
		x.Logger.Print("decodeValue: type is EndOfMibView")
		retVal.Type = EndOfMibView
		retVal.Value = nil
	default:
		x.Logger.Printf("decodeValue: type %x isn't implemented", data[0])
		retVal.Type = UnknownType
		retVal.Value = nil
	}
	x.Logger.Printf("decodeValue: value is %#v", retVal.Value)
	return nil
}

// appendBase128Int appends a base-128 encoded integer to the given slice.
// Returns the extended slice.
func appendBase128Int(dst []byte, n int64) []byte {
	if n == 0 {
		return append(dst, 0)
	}

	// Count number of 7-bit groups needed
	l := 0
	for i := n; i > 0; i >>= 7 {
		l++
	}

	// Encode from most significant to least significant 7-bit group
	for i := l - 1; i >= 0; i-- {
		o := byte(n>>uint(i*7)) & 0x7f //nolint:gosec
		if i != 0 {
			o |= 0x80
		}
		dst = append(dst, o)
	}

	return dst
}

/*
	snmp Integer32 and INTEGER:
	-2^31 and 2^31-1 inclusive (-2147483648 to 2147483647 decimal)
	(FYI https://groups.google.com/forum/#!topic/comp.protocols.snmp/1xaAMzCe_hE)

	versus:

	snmp Counter32, Gauge32, TimeTicks, Unsigned32: (below)
	non-negative integer, maximum value of 2^32-1 (4294967295 decimal)
*/

// marshalInt32 builds a byte representation of a signed 32 bit int in BigEndian form
// ie -2^31 and 2^31-1 inclusive (-2147483648 to 2147483647 decimal)
func marshalInt32(value int) ([]byte, error) {
	if value < math.MinInt32 || value > math.MaxInt32 {
		return nil, fmt.Errorf("unable to marshal: %d overflows int32", value)
	}
	const mask1 uint32 = 0xFFFFFF80
	const mask2 uint32 = 0xFFFF8000
	const mask3 uint32 = 0xFF800000
	// const mask4 uint32 = 0x80000000
	// ITU-T Rec. X.690 (2002) 8.3.2
	// If the contents octets of an integer value encoding consist of more than
	// one octet, then the bits of the first octet and bit 8 of the second octet:
	//  a) shall not all be ones; and
	//  b) shall not all be zero
	// These rules ensure that an integer value is always encoded in the smallest
	// possible number of octets.
	val := uint32(value) //nolint:gosec
	switch {
	case val&mask1 == 0 || val&mask1 == mask1:
		return []byte{byte(val)}, nil
	case val&mask2 == 0 || val&mask2 == mask2:
		return []byte{byte(val >> 8), byte(val)}, nil
	case val&mask3 == 0 || val&mask3 == mask3:
		return []byte{byte(val >> 16), byte(val >> 8), byte(val)}, nil
	default:
		return []byte{byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val)}, nil
	}
}

// marshalUint64 encodes a uint64 into BER-compliant bytes for SNMP Counter64.
// It trims leading zero bytes and prepends one if MSB is set (per X.690 §8.3.2)
func marshalUint64(v any) ([]byte, error) {
	// gracefully handle type assertion to uint64
	source, ok := v.(uint64)
	if !ok {
		return nil, fmt.Errorf("marshalUint64: input is not a uint64")
	}
	// Step 1: Encode uint64 in big-endian (8 bytes)
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, source)

	// Step 2: Trim leading 0x00 bytes (X.690 §8.3.2: use minimal number of octets)
	trimmed := bytes.TrimLeft(bs, "\x00")

	// Step 3: Ensure at least one byte remains
	if len(trimmed) == 0 {
		return []byte{0}, nil
	}

	// Step 4: If the MSB of the first byte is set, prepend 0x00 to indicate positive value
	if trimmed[0]&0x80 > 0 {
		trimmed = append([]byte{0}, trimmed...)
	}
	return trimmed, nil
}

// Counter32, Gauge32, TimeTicks, Unsigned32, SNMPError
func marshalUint32(v any) ([]byte, error) {
	var source uint32
	switch val := v.(type) {
	case uint32:
		source = val
	case uint:
		source = uint32(val) //nolint:gosec
	case uint8:
		source = uint32(val)
	case SNMPError:
		source = uint32(val)
	// We could do others here, but coercing from anything else is dangerous.
	// Even uint could be 64 bits, though in practice nothing we work with is.
	default:
		return nil, fmt.Errorf("unable to marshal %T to uint32", v)
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, source)
	var i int
	for i = 0; i < 3; i++ {
		if buf[i] != 0 {
			break
		}
	}
	buf = buf[i:]
	// if the highest bit in buf is set and x is not negative - prepend a byte to make it positive
	if len(buf) > 0 && buf[0]&0x80 > 0 {
		buf = append([]byte{0}, buf...)
	}
	return buf, nil
}

func marshalFloat32(v any) ([]byte, error) {
	source, ok := v.(float32)
	if !ok {
		return nil, fmt.Errorf("marshalFloat32: expected float32, got %T", v)
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, math.Float32bits(source))
	return buf, nil
}

func marshalFloat64(v any) ([]byte, error) {
	source, ok := v.(float64)
	if !ok {
		return nil, fmt.Errorf("marshalFloat64: expected float64, got %T", v)
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, math.Float64bits(source))
	return buf, nil
}

// marshalLength builds a byte representation of length
//
// http://luca.ntop.org/Teaching/Appunti/asn1.html
//
// Length octets. There are two forms: short (for lengths between 0 and 127),
// and long definite (for lengths between 0 and 2^1008 -1).
//
//   - Short form. One octet. Bit 8 has value "0" and bits 7-1 give the length.
//   - Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits
//     7-1 give the number of additional length octets. Second and following
//     octets give the length, base 256, most significant digit first.
func marshalLength(length int) ([]byte, error) {
	// more convenient to pass length as int than uint64. Therefore check < 0
	if length < 0 {
		return nil, fmt.Errorf("length must be >= 0")
	}
	if length <= 127 {
		return []byte{byte(length)}, nil
	}

	// Encode length as big-endian uint64 and find first non-zero byte
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(length))

	// Find first non-zero byte to trim leading zeros
	start := 0
	for start < 8 && buf[start] == 0 {
		start++
	}

	// Build result: header byte + length bytes
	numBytes := 8 - start
	result := make([]byte, 1+numBytes)
	result[0] = byte(128 | numBytes)
	copy(result[1:], buf[start:])
	return result, nil
}

// marshalTLV writes a BER TLV (type-length-value) to buf using proper length
// encoding. Handles values of any size, including those exceeding 127 bytes.
func marshalTLV(buf *bytes.Buffer, tag byte, value []byte) error {
	length, err := marshalLength(len(value))
	if err != nil {
		return err
	}
	buf.WriteByte(tag)
	buf.Write(length)
	buf.Write(value)
	return nil
}

func marshalObjectIdentifier(oid string) ([]byte, error) {
	oidLength := len(oid)

	// Worst-case: 2 chars per output byte (e.g., ".128" = 4 chars → 2 bytes)
	// This ratio holds at base-128 boundaries; smaller values use more chars per byte
	out := make([]byte, 0, oidLength/2)

	oidBase := 0
	i := 0
	for j := 0; j < oidLength; {
		if oid[j] == '.' {
			j++
			continue
		}
		var val int64
		for j < oidLength && oid[j] != '.' {
			ch := int64(oid[j] - '0')
			if ch > 9 {
				return nil, fmt.Errorf("unable to marshal OID: Invalid object identifier")
			}
			val *= 10
			val += ch
			j++
		}
		switch i {
		case 0:
			if val > 6 {
				return nil, fmt.Errorf("unable to marshal OID: Invalid object identifier")
			}
			oidBase = int(val * 40)
		case 1:
			if val >= 40 {
				return nil, fmt.Errorf("unable to marshal OID: Invalid object identifier")
			}
			oidBase += int(val)
			out = append(out, byte(oidBase))
		default:
			if val > MaxObjectSubIdentifierValue {
				return nil, fmt.Errorf("unable to marshal OID: Value out of range")
			}
			out = appendBase128Int(out, val)
		}
		i++
	}
	if i < 2 || i > 128 {
		return nil, fmt.Errorf("unable to marshal OID: Invalid object identifier")
	}

	return out, nil
}

// TODO no tests
func ipv4toBytes(ip net.IP) []byte {
	return []byte(ip)[12:]
}

// parseOpaque  parses a Opaque encoded data
// Known data-types is OpaqueDouble and OpaqueFloat
// Other data decoded as binary Opaque data
// TODO: add OpaqueCounter64 (0x76), OpaqueInteger64 (0x80), OpaqueUinteger64 (0x81)
func parseOpaque(logger Logger, data []byte, retVal *variable) error {
	if len(data) == 0 {
		return ErrZeroByteBuffer
	}
	if len(data) > 2 && data[0] == AsnExtensionTag {
		switch Asn1BER(data[1]) {
		case OpaqueDouble:
			// 0x79
			data = data[1:]
			logger.Print("decodeValue: type is OpaqueDouble")
			length, cursor, err := parseLength(data)
			if err != nil {
				return err
			}
			if length > len(data) {
				return fmt.Errorf("not enough data for OpaqueDouble %x (data %d length %d)", data, len(data), length)
			}
			retVal.Type = OpaqueDouble
			retVal.Value, err = parseFloat64(data[cursor:length])
			if err != nil {
				return err
			}
		case OpaqueFloat:
			// 0x78
			data = data[1:]
			logger.Print("decodeValue: type is OpaqueFloat")
			length, cursor, err := parseLength(data)
			if err != nil {
				return err
			}
			if length > len(data) {
				return fmt.Errorf("not enough data for OpaqueFloat %x (data %d length %d)", data, len(data), length)
			}
			if cursor > length {
				return fmt.Errorf("invalid cursor position for OpaqueFloat %x (data %d length %d cursor %d)", data, len(data), length, cursor)
			}
			retVal.Type = OpaqueFloat
			retVal.Value, err = parseFloat32(data[cursor:length])
			if err != nil {
				return err
			}
		default:
			logger.Print("decodeValue: type is Opaque")
			retVal.Type = Opaque
			retVal.Value = data[0:]
		}
	} else {
		logger.Print("decodeValue: type is Opaque")
		retVal.Type = Opaque
		retVal.Value = data[0:]
	}
	return nil
}

// parseBase128Uint32 parses a base-128 encoded unsigned integer from the given
// offset in the given byte slice. Returns the value and the new offset.
func parseBase128Uint32(bytes []byte, initOffset int) (uint32, int, error) {
	var ret uint64
	offset := initOffset
	for offset < len(bytes) {
		b := bytes[offset]
		offset++
		ret = (ret << 7) | uint64(b&0x7f)
		if ret > math.MaxUint32 {
			return 0, 0, ErrBase128IntegerTooLarge
		}
		if b&0x80 == 0 {
			return uint32(ret), offset, nil
		}
	}
	return 0, 0, ErrBase128IntegerTruncated
}

// parseInt64 treats the given bytes as a big-endian, signed integer and
// returns the result.
func parseInt64(bytes []byte) (int64, error) {
	switch {
	case len(bytes) == 0:
		// X.690 8.3.1: Encoding of an integer value:
		// The encoding of an integer value shall be primitive.
		// The contents octets shall consist of one or more octets.
		return 0, ErrZeroLenInteger
	case len(bytes) > 8:
		// We'll overflow an int64 in this case.
		return 0, ErrIntegerTooLarge
	}
	var ret int64
	for bytesRead := range bytes {
		ret <<= 8
		ret |= int64(bytes[bytesRead])
	}
	// Shift up and down in order to sign extend the result.
	ret <<= 64 - uint8(len(bytes))*8 //nolint:gosec
	ret >>= 64 - uint8(len(bytes))*8 //nolint:gosec
	return ret, nil
}

// parseInt treats the given bytes as a big-endian, signed integer and returns
// the result.
func parseInt(bytes []byte) (int, error) {
	ret64, err := parseInt64(bytes)
	if err != nil {
		return 0, err
	}
	if ret64 != int64(int(ret64)) {
		return 0, ErrIntegerTooLarge
	}
	return int(ret64), nil
}

// parseLength parses and calculates an snmp packet length
// and returns an error when invalid data is detected
//
// http://luca.ntop.org/Teaching/Appunti/asn1.html
//
// Length octets. There are two forms: short (for lengths between 0 and 127),
// and long definite (for lengths between 0 and 2^1008 -1).
//
//   - Short form. One octet. Bit 8 has value "0" and bits 7-1 give the length.
//   - Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits
//     7-1 give the number of additional length octets. Second and following
//     octets give the length, base 256, most significant digit first.
func parseLength(bytes []byte) (int, int, error) {
	var cursor, length int
	switch {
	case len(bytes) < 2:
		// handle null octet strings ie "0x04 0x00"
		cursor = len(bytes)
		length = len(bytes)
	case int(bytes[1]) <= 127:
		length = int(bytes[1])
		length += 2
		cursor += 2
	case bytes[1] == 0x80:
		// Indefinite length encoding (0x80) is prohibited in SNMP per RFC 3417 Section 8:
		// "When encoding the length field, only the definite form is used;
		// use of the indefinite form encoding is prohibited."
		return 0, 0, fmt.Errorf("indefinite length encoding (0x80) is not permitted in SNMP")
	default:
		numOctets := int(bytes[1]) & 127
		for i := range numOctets {
			length <<= 8
			if len(bytes) < 2+i+1 {
				// Invalid data detected, return an error
				return 0, 0, ErrInvalidPacketLength
			}
			length += int(bytes[2+i])
			if length < 0 {
				// Invalid length due to overflow, return an error
				return 0, 0, ErrInvalidPacketLength
			}
		}
		length += 2 + numOctets
		cursor += 2 + numOctets
	}
	if length < 0 {
		// Invalid data detected, return an error
		return 0, 0, ErrInvalidPacketLength
	}
	return length, cursor, nil
}

// parseObjectIdentifier parses an OBJECT IDENTIFIER from the given bytes and
// returns it. An object identifier is a sequence of variable length integers
// that are assigned in a hierarchy.
func parseObjectIdentifier(src []byte) (string, error) {
	if len(src) == 0 {
		return "", ErrInvalidOidLength
	}

	// Worst-case: first byte expands to 5 chars (".2.39"), rest to 4 chars (".127")
	out := make([]byte, 0, len(src)*4+1)

	out = append(out, '.')
	out = strconv.AppendUint(out, uint64(src[0]/40), 10)
	out = append(out, '.')
	out = strconv.AppendUint(out, uint64(src[0]%40), 10)

	var v uint32
	var err error
	for offset := 1; offset < len(src); {
		out = append(out, '.')
		v, offset, err = parseBase128Uint32(src, offset)
		if err != nil {
			return "", err
		}
		out = strconv.AppendUint(out, uint64(v), 10)
	}
	return string(out), nil
}

func parseRawField(logger Logger, data []byte, msg string) (any, int, error) {
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("empty data passed to parseRawField")
	}
	logger.Printf("parseRawField: %s", msg)
	switch Asn1BER(data[0]) {
	case Integer:
		length, cursor, err := parseLength(data)
		if err != nil {
			return nil, 0, err
		}
		if length > len(data) {
			return nil, 0, fmt.Errorf("not enough data for Integer (%d vs %d): %x", length, len(data), data)
		}
		if cursor > length {
			return nil, 0, fmt.Errorf("invalid cursor position for Integer %x (data %d length %d cursor %d)", data, len(data), length, cursor)
		}
		i, err := parseInt(data[cursor:length])
		if err != nil {
			return nil, 0, fmt.Errorf("unable to parse raw INTEGER: %x err: %w", data, err)
		}
		return i, length, nil
	case OctetString:
		length, cursor, err := parseLength(data)
		if err != nil {
			return nil, 0, err
		}
		if length > len(data) {
			return nil, 0, fmt.Errorf("not enough data for OctetString (%d vs %d): %x", length, len(data), data)
		}
		if cursor > length {
			return nil, 0, fmt.Errorf("invalid cursor position for OctetString %x (data %d length %d cursor %d)", data, len(data), length, cursor)
		}
		return string(data[cursor:length]), length, nil
	case ObjectIdentifier:
		length, cursor, err := parseLength(data)
		if err != nil {
			return nil, 0, err
		}
		if length > len(data) {
			return nil, 0, fmt.Errorf("not enough data for OID (%d vs %d): %x", length, len(data), data)
		}
		if cursor > length {
			return nil, 0, fmt.Errorf("invalid cursor position for OID %x (data %d length %d cursor %d)", data, len(data), length, cursor)
		}
		oid, err := parseObjectIdentifier(data[cursor:length])
		return oid, length, err
	case IPAddress:
		length, cursor, err := parseLength(data)
		if err != nil {
			return nil, 0, err
		}
		// length includes header bytes, ipLen is just the address bytes
		ipLen := length - cursor
		switch ipLen {
		case 0: // real life, buggy devices returning bad data
			return nil, length, nil
		case 4: // IPv4
			if len(data) < cursor+4 {
				return nil, 0, fmt.Errorf("not enough data for ipv4 address: %x", data)
			}
			return net.IP(data[cursor : cursor+4]).String(), length, nil
		default:
			return nil, 0, fmt.Errorf("got ipaddress len %d, expected 4", ipLen)
		}
	case TimeTicks:
		length, cursor, err := parseLength(data)
		if err != nil {
			return nil, 0, err
		}
		if length > len(data) {
			return nil, 0, fmt.Errorf("not enough data for TimeTicks (%d vs %d): %x", length, len(data), data)
		}
		if cursor > length {
			return nil, 0, fmt.Errorf("invalid cursor position for TimeTicks %x (data %d length %d cursor %d)", data, len(data), length, cursor)
		}
		ret, err := parseUint(data[cursor:length])
		if err != nil {
			return nil, 0, fmt.Errorf("error in parseUint: %w", err)
		}
		return ret, length, nil
	}

	return nil, 0, fmt.Errorf("unknown field type: %x", data[0])
}

// parseUint64 treats the given bytes as a big-endian, unsigned integer and returns
// the result.
func parseUint64(bytes []byte) (uint64, error) {
	var ret uint64
	if len(bytes) > 9 || (len(bytes) > 8 && bytes[0] != 0x0) {
		// We'll overflow a uint64 in this case.
		return 0, ErrIntegerTooLarge
	}
	for bytesRead := range bytes {
		ret <<= 8
		ret |= uint64(bytes[bytesRead])
	}
	return ret, nil
}

// parseUint32 treats the given bytes as a big-endian, signed integer and returns
// the result.
func parseUint32(bytes []byte) (uint32, error) {
	ret, err := parseUint(bytes)
	if err != nil {
		return 0, err
	}
	return uint32(ret), nil //nolint:gosec
}

// parseUint treats the given bytes as a big-endian, signed integer and returns
// the result.
func parseUint(bytes []byte) (uint, error) {
	ret64, err := parseUint64(bytes)
	if err != nil {
		return 0, err
	}
	if ret64 != uint64(uint(ret64)) {
		return 0, ErrIntegerTooLarge
	}
	return uint(ret64), nil
}

func parseFloat32(bytes []byte) (float32, error) {
	if len(bytes) > 4 {
		// We'll overflow a uint64 in this case.
		return 0, ErrFloatTooLarge
	}
	if len(bytes) < 4 {
		// We'll cause a panic in binary.BigEndian.Uint32() in this case
		return 0, ErrFloatBufferTooShort
	}
	return math.Float32frombits(binary.BigEndian.Uint32(bytes)), nil
}

func parseFloat64(bytes []byte) (float64, error) {
	if len(bytes) > 8 {
		// We'll overflow a uint64 in this case.
		return 0, ErrFloatTooLarge
	}
	if len(bytes) < 8 {
		// We'll cause a panic in binary.BigEndian.Uint64() in this case
		return 0, ErrFloatBufferTooShort
	}
	return math.Float64frombits(binary.BigEndian.Uint64(bytes)), nil
}

// -- Bit String ---------------------------------------------------------------

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
	y := 7 - uint(i%8) //nolint:gosec
	return int(b.Bytes[x]>>y) & 1
}

// RightAlign returns a slice where the padding bits are at the beginning. The
// slice may share memory with the BitString.
func (b BitStringValue) RightAlign() []byte {
	shift := uint(8 - (b.BitLength % 8)) //nolint:gosec
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

// -- SnmpVersion --------------------------------------------------------------

func (s SnmpVersion) String() string {
	switch s {
	case Version1:
		return "1"
	case Version2c:
		return "2c"
	case Version3:
		return "3"
	default:
		return "3"
	}
}
