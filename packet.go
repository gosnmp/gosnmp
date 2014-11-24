package gosnmp

import (
	"fmt"
	"net"
)

/*
Sequence       PDUType = 0x30
GetRequest     PDUType = 0xa0
GetNextRequest PDUType = 0xa1
GetResponse    PDUType = 0xa2
SetRequest     PDUType = 0xa3
Trap           PDUType = 0xa4
GetBulkRequest PDUType = 0xa5
*/

/*
Version1  SnmpVersion = 0x0
Version2c SnmpVersion = 0x1
*/

//GenPacket generates the SNMP packet, and returns it.
func GenPacket(community string, version SnmpVersion, reqType PDUType, oids []string) ([]byte, error) {
	var packet []byte
	var pdus []SnmpPDU
	var err error
	for _, oid := range oids {
		pdus = append(pdus, SnmpPDU{oid, Null, nil})
	}

	// build up SnmpPacket
	packetOut := &SnmpPacket{
		Community:  community,
		Error:      0,
		ErrorIndex: 0,
		PDUType:    reqType,
		Version:    version,
	}

	packet, err = packetOut.marshalMsg(pdus, packetOut.PDUType, 0)
	if err != nil {
		return nil, err
	}
	return packet, nil
}

//SendPacket sends a packet generated with GenPacket, or other functions
func SendPacket(packet []byte, conn net.Conn) (result *SnmpPacket, err error) {
	if conn == nil {
		return nil, fmt.Errorf("&GoSNMP.Conn is missing. Provide a connection or use Connect()")
	}
	_, err = conn.Write(packet)
	if err != nil {
		err = fmt.Errorf("Error writing to socket: %s", err.Error())
		return nil, err
	}

	// FIXME: If our packet exceeds our buf size we'll get a partial read
	// and this request, and the next will fail. The correct logic would be
	// to realloc and read more if pack len > buff size.
	resp := make([]byte, rxBufSize, rxBufSize)
	var n int
	n, err = conn.Read(resp)
	if err != nil {
		err = fmt.Errorf("Error reading from UDP: %s", err.Error())
		return nil, err
	}

	result, err = unmarshal(resp[:n])
	if err != nil {
		err = fmt.Errorf("Unable to decode packet: %s", err.Error())
		return nil, err
	}
	if result == nil || len(result.Variables) < 1 {
		err = fmt.Errorf("Unable to decode packet: nil")
		return nil, err
	}
	return result, nil
}
