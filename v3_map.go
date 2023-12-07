// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"fmt"
	"sync"
)

// SnmpV3SecurityParametersTable is a mapping of identifiers to corresponding SNMP V3 Security Model parameters
type SnmpV3SecurityParametersTable struct {
	table map[string][]SnmpV3SecurityParameters
	mu    sync.RWMutex
}

func NewSnmpV3SecurityParametersTable() *SnmpV3SecurityParametersTable {
	return &SnmpV3SecurityParametersTable{
		table: make(map[string][]SnmpV3SecurityParameters),
	}
}

func (spm *SnmpV3SecurityParametersTable) Add(key string, sp SnmpV3SecurityParameters) {
	spm.mu.Lock()
	defer spm.mu.Unlock()

	spm.table[key] = append(spm.table[key], sp)
}

func (spm *SnmpV3SecurityParametersTable) Get(key string) ([]SnmpV3SecurityParameters, error) {
	spm.mu.RLock()
	defer spm.mu.RUnlock()

	if sp, ok := spm.table[key]; ok {
		return sp, nil
	}
	return nil, fmt.Errorf("No security parameters found for the key %s", key)
}
