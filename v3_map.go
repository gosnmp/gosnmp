// Copyright 2023 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"sync"
)

// SnmpV3SecurityParametersTable is a mapping of identifiers to corresponding SNMP V3 Security Model parameters
type SnmpV3SecurityParametersTable struct {
	table  map[string][]SnmpV3SecurityParameters
	Logger Logger
	mu     sync.RWMutex
}

func NewSnmpV3SecurityParametersTable(logger Logger) *SnmpV3SecurityParametersTable {
	return &SnmpV3SecurityParametersTable{
		table:  make(map[string][]SnmpV3SecurityParameters),
		Logger: logger,
	}
}

func (spm *SnmpV3SecurityParametersTable) Add(key string, sp SnmpV3SecurityParameters) error {
	spm.mu.Lock()
	defer spm.mu.Unlock()

	if err := sp.InitSecurityKeys(); err != nil {
		return err
	}

	// If no logger is set for the security params (empty struct), use the one from the table
	if (Logger{}) == sp.getLogger() {
		sp.setLogger(spm.Logger)
	}

	spm.table[key] = append(spm.table[key], sp)
	spm.Logger.Printf("Added security parameters %s for key: %s", sp.SafeString(), key)

	return nil
}

func (spm *SnmpV3SecurityParametersTable) Get(key string) ([]SnmpV3SecurityParameters, error) {
	spm.mu.RLock()
	defer spm.mu.RUnlock()

	if sp, ok := spm.table[key]; ok {
		return sp, nil
	}
	return nil, fmt.Errorf("no security parameters found for the key %s", key)
}
