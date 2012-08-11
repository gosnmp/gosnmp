// Copyright 2012 Andreas Louca. All rights reserved.
// Use of this source code is goverend by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type GoSNMP struct {
	Target    string
	Community string
	Version   uint8
}

func NewGoSNMP(target, community string, version uint8) *GoSNMP {
	s := &GoSNMP{target, community, version}

	return s
}

func (x *GoSNMP) Get(oid string) (*Variable, error) {
	var err error
	// Encode the oid
	oid = strings.Trim(oid, ".")
	oidParts := strings.Split(oid, ".")
	oidBytes := make([]int, len(oidParts))

	for i := 0; i < len(oidParts); i++ {
		oidBytes[i], err = strconv.Atoi(oidParts[i])
		if err != nil {
			return nil, fmt.Errorf("Unable to parse OID: %s\n", err.Error())
		}
	}

	mOid, err := marshalObjectIdentifier(oidBytes)

	if err != nil {
		return nil, fmt.Errorf("Unable to marshal OID: %s\n", err.Error())
	}

	fmt.Printf("OID Length: %d - Target: %s\n", len(mOid), fmt.Sprintf("%s:161", x.Target))

	conn, err := net.Dial("udp", fmt.Sprintf("%s:161", x.Target))
	//addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:161", x.Target))
	//	conn, err := net.DialUDP("udp", nil, addr)
	defer conn.Close()
	// laddr := conn.LocalAddr().String()
	//	laddrUDP, _ := net.ResolveUDPAddr("udp", ":4567")
	//	ln, err := net.ListenUDP("udp", laddrUDP)

	if err != nil {
		return nil, fmt.Errorf("Error on listen: %s\n", err.Error())
	}
	//defer ln.Close()

	if err != nil {
		return nil, fmt.Errorf("Error establishing connection to host: %s\n", err.Error())
	}
	// Prepare the buffer to send
	buffer := make([]byte, 0, 1024)
	buf := bytes.NewBuffer(buffer)

	// Write the packet header (Message type 0x30) & Version = 2
	buf.Write([]byte{0x30, 0, 2, 1, 1})
	// Write Community
	buf.Write([]byte{4, uint8(len(x.Community))})
	buf.WriteString(x.Community)

	// Write the PDU
	buf.Write([]byte{0xa0, uint8(17 + len(mOid)), 2, 1, 1, 2, 1, 0, 2, 1, 0, 0x30, uint8(6 + len(mOid)), 0x30, uint8(4 + len(mOid)), 6, uint8(len(mOid))})
	buf.Write(mOid)
	buf.Write([]byte{5, 0})

	fBuf := buf.Bytes()
	// Set the packet size
	fBuf[1] = uint8(len(fBuf) - 2)

	/*
		for _, b := range fBuf {
			fmt.Printf("%#x ", b)
		}
		fmt.Printf("\n")
		fmt.Printf("Res: %d\n", buf.Len())
	*/

	// Send the packet!
	_, err = conn.Write(fBuf)
	if err != nil {
		return nil, fmt.Errorf("Error writing to socket: %s\n", err.Error())
	}
	// Try to read the response
	resp := make([]byte, 2048, 2048)
	n, err := conn.Read(resp)

	if err != nil {
		return nil, fmt.Errorf("Error reading from UDP: %s\n", err.Error())
	}
	/*
		for _, b := range resp[0:n] {
			fmt.Printf("%#x ", b)
		}
		fmt.Printf("\n")

		fmt.Printf("Read %d bytes (Size: %d) \n", n, resp[1])

			if resp[0] == byte(0x30) && int(resp[1]) == n-2 {
				fmt.Printf("Sanity of response confirmed\n")
			}
	*/
	pdu, err := decode(resp[:n])

	if err != nil {
		return nil, fmt.Errorf("Unable to decode packet: %s\n", err.Error())
	} else {
		fmt.Printf("PDU Request ID %d - Error: %d - Responses: %d\n", pdu.RequestId, pdu.ErrorStatus, len(pdu.VarBindList))

		if len(pdu.VarBindList) < 1 {
			return nil, fmt.Errorf("No responses received.")
		} else {
			return pdu.VarBindList[0], nil
		}
	}

	return nil, nil
}
