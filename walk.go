// Copyright 2014 Chris Dance. All rights reserved.  Use
// of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package gosnmp

import (
	"fmt"
	"strings"
)

const (
	baseOid               = "1.3.6.1.2.1" // Base OID for MIB-2 defined SNMP variables
	defaultMaxRepetitions = 50            // Java SNMP uses 50, snmp-net uses 10
	defaultNonRepeaters   = 0
)

//
// SNMP Walk functions - Analogous to net-snmp's snmpwalk commands
//

// WalkFunc is the type of the function called for each data unit visited
// by the Walk function.  If an error is returned processing stops.
type WalkFunc func(dataUnit SnmpPDU) error

// BulkWalk retrieves a subtree of values using GETBULK. As the tree is
// walked walkFn is called for each new value. The function immediately returns
// an error if either there is an underlaying SNMP error (e.g. GetBulk fails),
// or if walkFn returns an error.
func (x *GoSNMP) BulkWalk(rootOid string, walkFn WalkFunc) error {
	return x.walk(GetBulkRequest, rootOid, walkFn)
}

// Similar to BulkWalk but returns a filled array of all values rather than
// using a callback function to stream results.
func (x *GoSNMP) BulkWalkAll(rootOid string) (results []SnmpPDU, err error) {
	return x.walkAll(GetBulkRequest, rootOid)
}

// Walk retrieves a subtree of values using GETNEXT - a request is made for each
// value, unlike BulkWalk which does this operation in batches. As the tree is
// walked walkFn is called for each new value. The function immediately returns
// an error if either there is an underlaying SNMP error (e.g. GetNext fails),
// or if walkFn returns an error.
func (x *GoSNMP) Walk(rootOid string, walkFn WalkFunc) error {
	return x.walk(GetNextRequest, rootOid, walkFn)
}

// Similar to Walk but returns a filled array of all values rather than
// using a callback function to stream results.
func (x *GoSNMP) WalkAll(rootOid string) (results []SnmpPDU, err error) {
	return x.walkAll(GetNextRequest, rootOid)
}

func (x *GoSNMP) walk(getRequestType byte, rootOid string, walkFn WalkFunc) error {
	if rootOid == "" || rootOid == "." {
		rootOid = baseOid
	}
	oid := rootOid
	requests := 0

	getFn := func(oid string) (result *SnmpPacket, err error) {
		switch getRequestType {
		case GetBulkRequest:
			return x.GetBulk([]string{oid}, defaultNonRepeaters, defaultMaxRepetitions)
		case GetNextRequest:
			return x.GetNext([]string{oid})
		default:
			return nil, fmt.Errorf("Unsupported request type: %d", getRequestType)
		}
	}

RequestLoop:
	for {

		requests++
		response, err := getFn(oid)
		if err != nil {
			return err
		}
		if len(response.Variables) == 0 {
			break RequestLoop
		}

		for _, v := range response.Variables {
			if v.Name == oid {
				return fmt.Errorf("OID not increasing: %s", v.Name)
			}
			if !strings.HasPrefix(v.Name, rootOid) {
				// Not in the requested root range.
				break RequestLoop
			}
			// Report our pdu
			if err := walkFn(v); err != nil {
				return err
			}
			if v.Type == EndOfMibView || v.Type == NoSuchObject || v.Type == NoSuchInstance {
				x.Logger.Printf("BulkWalk terminated with type 0x%x", v.Type)
				break RequestLoop
			}
		}
		// Save last oid for next request
		oid = response.Variables[len(response.Variables)-1].Name
	}
	x.Logger.Printf("BulkWalk completed in %d requests", requests)
	return nil
}

func (x *GoSNMP) walkAll(getRequestType byte, rootOid string) (results []SnmpPDU, err error) {
	err = x.walk(getRequestType, rootOid, func(dataUnit SnmpPDU) error {
		results = append(results, dataUnit)
		return nil
	})
	return results, err
}
