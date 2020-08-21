// Copyright 2012-2020 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
)

// GoSNMPAgent is struct for SNMP Agent.
type GoSNMPAgent struct {
	// conn is udp lissten connection
	conn *net.UDPConn

	// SNMP Agent settings
	Snmp *GoSNMP
	// IPAddr is an ipv4 address
	IPAddr string

	// Port is a port
	Port int

	// Logger is error logger for snmp agent
	Logger  Logger
	mibList []*mibEnt
}

type mibEnt struct {
	strOid  string
	oid     []uint16
	objType Asn1BER
	getFunc func(string) interface{}
}

func toNumOid(s string) []uint16 {
	ret := []uint16{}
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			continue
		}
		if n, err := strconv.Atoi(id); err == nil {
			ret = append(ret, uint16(n))
		}
	}
	return ret
}

func cmpOid(oid1, oid2 []uint16) int {
	for i := range oid1 {
		if i >= len(oid2) {
			return 1
		}
		if oid1[i] == oid2[i] {
			continue
		}
		if oid1[i] > oid2[i] {
			return 1
		}
		return -1
	}
	if len(oid1) < len(oid2) {
		return -1
	}
	return 0
}

func (a *GoSNMPAgent) AddMibList(oid string, vbType Asn1BER, get func(string) interface{}) {
	mib := &mibEnt{
		strOid:  oid,
		getFunc: get,
		objType: vbType,
		oid:     toNumOid(oid),
	}
	pos := sort.Search(len(a.mibList), func(i int) bool {
		return cmpOid(mib.oid, a.mibList[i].oid) <= 0
	})
	if pos >= len(a.mibList) {
		a.mibList = append(a.mibList, mib)
		return
	}
	a.mibList = append(a.mibList[:pos+1], a.mibList[pos:]...)
	a.mibList[pos] = mib
}

func (a *GoSNMPAgent) findMib(oid string, bNext bool) (string, Asn1BER, interface{}, error) {
	noid := toNumOid(oid)
	i := sort.Search(len(a.mibList), func(i int) bool {
		return cmpOid(noid, a.mibList[i].oid) <= 0
	})
	if i >= len(a.mibList) {
		return "", Integer, nil, fmt.Errorf("Not found")
	}
	if cmpOid(noid, a.mibList[i].oid) == 0 {
		if !bNext {
			return oid, a.mibList[i].objType, a.mibList[i].getFunc(oid), nil
		}
		i++
		if i >= len(a.mibList) {
			return "", Integer, nil, fmt.Errorf("Not found")
		}
	}
	return a.mibList[i].strOid, a.mibList[i].objType, a.mibList[i].getFunc(oid), nil
}

// Start : start snmp agent
func (a *GoSNMPAgent) Start() error {
	if a.Logger == nil {
		a.Logger = log.New(ioutil.Discard, "", 0)
	}
	a.Stop()
	var err error
	a.conn, err = net.ListenUDP("udp",
		&net.UDPAddr{
			IP:   net.ParseIP(a.IPAddr),
			Port: a.Port,
		})
	if err != nil {
		return err
	}
	go a.process()
	return nil
}

// Stop : stop snmp agent
func (a *GoSNMPAgent) Stop() {
	if a.conn == nil {
		return
	}
	a.conn.Close()
	a.conn = nil
}

func (a *GoSNMPAgent) process() {
	buf := make([]byte, 4096)
	for {
		n, addr, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			a.Logger.Printf("ReadFromUDP err=%v", err)
			return
		}
		p, err := a.Snmp.SnmpDecodePacket(buf[:n])
		if err != nil {
			a.Logger.Printf("SnmpDecodePacket err=%v", err)
			continue
		}
		if p.Version == Version3 {
			a.Logger.Print("Drop SNMP v3 request")
			continue
		}
		if p.Community != a.Snmp.Community {
			a.Logger.Print("Drop Invalid Community request")
			continue
		}
		bNext := p.PDUType == GetNextRequest
		pdus := []SnmpPDU{}
		errIndex := -1
		for i, vb := range p.Variables {
			o, t, m, err := a.findMib(vb.Name, bNext)
			if err == nil {
				vb.Name = o
				vb.Type = t
				vb.Value = m
			} else if errIndex == -1 {
				errIndex = i
			}
			pdus = append(pdus, vb)
		}
		out, err := a.Snmp.SnmpEncodeGetResponsePacket(p.RequestID, int32(errIndex), pdus)
		if err != nil {
			a.Logger.Printf("SnmpEncodeGetResponsePacket err=%v", err)
			continue
		}
		if a.conn == nil {
			return
		}
		a.conn.WriteTo(out, addr)
	}
}
