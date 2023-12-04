// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import "fmt"

// SnmpV3SecurityParametersMap is a mapping of usernames to corresponding SNMP V3 Security Model parameters
type SnmpV3SecurityParametersMap map[string][]SnmpV3SecurityParameters

func NewSnmpV3SecurityParametersMap() SnmpV3SecurityParametersMap {
	return make(map[string][]SnmpV3SecurityParameters)
}

func (uspm SnmpV3SecurityParametersMap) AddEntry(key string, sp SnmpV3SecurityParameters) {
	uspm[key] = append(uspm[key], sp)
}

func (uspm SnmpV3SecurityParametersMap) getEntry(key string) ([]SnmpV3SecurityParameters, error) {
	if sp, ok := uspm[key]; ok {
		return sp, nil
	}
	return nil, fmt.Errorf("No security parameters found for the key %s", key)
}
