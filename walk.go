// Copyright 2012-2014 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"strings"
)

func (x *GoSNMP) walk(getRequestType PDUType, rootOid string, walkFn WalkFunc) error {
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

func (x *GoSNMP) walkAll(getRequestType PDUType, rootOid string) (results []SnmpPDU, err error) {
	err = x.walk(getRequestType, rootOid, func(dataUnit SnmpPDU) error {
		results = append(results, dataUnit)
		return nil
	})
	return results, err
}
