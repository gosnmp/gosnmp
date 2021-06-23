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

	// ACL
	Acl string

	// Logger is error logger for snmp agent
	Logger  Logger
	mibList []*mibEnt

	// SNMP MIB
	SupportSnmpMIB bool
	snmpCounters   map[string]*uint32
}

var (
	//.1.3.6.1.2.1.11.1,0
	snmpInPkts uint32
	//.1.3.6.1.2.1.11.2.0
	snmpOutPkts uint32
	//.1.3.6.1.2.1.11.3.0
	snmpInBadVersions uint32
	//.1.3.6.1.2.1.11.4.0
	snmpInBadCommunityNames uint32
	//.1.3.6.1.2.1.11.6.0
	snmpInASNParseErrs uint32
	//.1.3.6.1.2.1.11.15.0
	snmpInGetRequests uint32
	//.1.3.6.1.2.1.11.16.0
	snmpInGetNexts uint32
	//.1.3.6.1.2.1.11.21.0
	snmpOutNoSuchNames uint32
	//.1.3.6.1.2.1.11.28.0
	snmpOutGetResponses uint32
	//.1.3.6.1.2.1.11.29
	snmpOutTraps uint32
)

type mibEnt struct {
	strOid  string
	oid     []uint16
	objType Asn1BER
	getFunc func(string) interface{}
	setFunc func(interface{})
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

func (a *GoSNMPAgent) AddMibList(oid string, vbType Asn1BER, get func(string) interface{}, set func(interface{})) {
	mib := &mibEnt{
		strOid:  oid,
		getFunc: get,
		setFunc: set,
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
	if cmpOid(mib.oid, a.mibList[pos].oid) == 0 {
		a.Logger.Printf("AddMibList replace OID=%s", oid)
		a.mibList[pos] = mib
		return
	}
	a.mibList = append(a.mibList[:pos+1], a.mibList[pos:]...)
	a.mibList[pos] = mib
}

func (a *GoSNMPAgent) findMib(oid string, bNext bool, ptype PDUType, value interface{}) (string, Asn1BER, interface{}, error) {
	noid := toNumOid(oid)
	i := sort.Search(len(a.mibList), func(i int) bool {
		return cmpOid(noid, a.mibList[i].oid) <= 0
	})
	if i >= len(a.mibList) {
		return "", Integer, nil, fmt.Errorf("Not found")
	}
	if cmpOid(noid, a.mibList[i].oid) == 0 {
		if !bNext {
			if ptype == SetRequest && a.mibList[i].setFunc != nil {
				a.mibList[i].setFunc(value)
			}
			return oid, a.mibList[i].objType, a.mibList[i].getFunc(oid), nil
		}
		i++
		if i >= len(a.mibList) {
			return "", Integer, nil, fmt.Errorf("Not found")
		}
	}
	oid = a.mibList[i].strOid
	if ptype == SetRequest && a.mibList[i].setFunc != nil {
		a.mibList[i].setFunc(value)
	}
	return oid, a.mibList[i].objType, a.mibList[i].getFunc(oid), nil
}

// Start : start snmp agent
func (a *GoSNMPAgent) Start() error {
	l := Logger{}
	if a.Logger == l {
		a.Logger = Logger{log.New(ioutil.Discard, "", 0)}
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
	a.AddSnmpMib()
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
		if a.Acl != "" {
			bOK := false
			from := addr.IP.String()
			for _, acl := range strings.Split(a.Acl, ",") {
				if from == strings.TrimSpace(acl) {
					bOK = true
				}
			}
			if !bOK {
				a.Logger.Printf("Drop SNMP Pkt from %s by ACL", from)
				continue
			}
		}
		snmpInPkts++
		p, err := a.Snmp.SnmpDecodePacket(buf[:n])
		if err != nil {
			snmpInASNParseErrs++
			a.Logger.Printf("SnmpDecodePacket err=%v", err)
			continue
		}
		if p.Version == Version3 {
			snmpInBadVersions++
			a.Logger.Print("Drop SNMP v3 request")
			continue
		}
		if p.Community != a.Snmp.Community {
			snmpInBadCommunityNames++
			a.Logger.Print("Drop Invalid Community request")
			continue
		}
		if p.PDUType != GetRequest && p.PDUType != GetNextRequest && p.PDUType != SetRequest {
			snmpInBadCommunityNames++
			a.Logger.Printf("Drop Bad PDU Type=%v", p.PDUType)
			continue
		}
		bNext := p.PDUType == GetNextRequest
		if !bNext {
			snmpInGetRequests++
		} else {
			snmpInGetNexts++
		}
		pdus := []SnmpPDU{}
		errIndex := -1
		for i, vb := range p.Variables {
			o, t, m, err := a.findMib(vb.Name, bNext, p.PDUType, vb.Value)
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
		if errIndex != -1 {
			snmpOutNoSuchNames++
		}
		if a.conn == nil {
			return
		}
		snmpOutGetResponses++
		snmpOutPkts++
		a.conn.WriteTo(out, addr)
	}
}

func (a *GoSNMPAgent) getCounter32(oid string) interface{} {
	if p, ok := a.snmpCounters[oid]; ok {
		return *p
	}
	return uint32(0)
}

func (a *GoSNMPAgent) getSnmpEnableAuthenTraps(oid string) interface{} {
	return 2
}

func (a *GoSNMPAgent) AddSnmpMib() {
	if !a.SupportSnmpMIB {
		return
	}
	a.snmpCounters = make(map[string]*uint32)
	snmpInPkts = 0
	a.snmpCounters[".1.3.6.1.2.1.11.1.0"] = &snmpInPkts
	snmpOutPkts = 0
	a.snmpCounters[".1.3.6.1.2.1.11.2.0"] = &snmpOutPkts
	snmpInBadVersions = 0
	a.snmpCounters[".1.3.6.1.2.1.11.3.0"] = &snmpInBadVersions
	snmpInBadCommunityNames = 0
	a.snmpCounters[".1.3.6.1.2.1.11.4.0"] = &snmpInBadCommunityNames
	snmpInASNParseErrs = 0
	a.snmpCounters[".1.3.6.1.2.1.11.6.0"] = &snmpInASNParseErrs
	snmpInGetRequests = 0
	a.snmpCounters[".1.3.6.1.2.1.11.15.0"] = &snmpInGetRequests
	snmpInGetNexts = 0
	a.snmpCounters[".1.3.6.1.2.1.11.16.0"] = &snmpInGetNexts
	snmpOutNoSuchNames = 0
	a.snmpCounters[".1.3.6.1.2.1.11.21.0"] = &snmpOutNoSuchNames
	snmpOutGetResponses = 0
	a.snmpCounters[".1.3.6.1.2.1.11.28.0"] = &snmpOutGetResponses
	snmpOutTraps = 0
	a.snmpCounters[".1.3.6.1.2.1.11.29.0"] = &snmpOutTraps
	for i := 1; i < 30; i++ {
		if i == 7 || i == 23 {
			continue
		}
		a.AddMibList(fmt.Sprintf(".1.3.6.1.2.1.11.%d.0", i), Counter32, a.getCounter32, nil)
	}
	a.AddMibList(".1.3.6.1.2.1.11.30.0", Integer, a.getSnmpEnableAuthenTraps, nil)
}
