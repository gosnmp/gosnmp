package gosnmp

// Copyright 2012-2016 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import (
	//"bytes"
	//"crypto/aes"
	//"crypto/cipher"
	//"crypto/des"
	//"crypto/md5"
	crand "crypto/rand"
	//"crypto/sha1"
	"encoding/binary"
	//"fmt"
	//"hash"
	//"sync/atomic"*/
	"fmt"
)

// SnmpV3AuthProtocol describes the authentication protocol in use by an authenticated SnmpV3 connection.
type SnmpV3AuthProtocol uint8

// NoAuth, MD5, and SHA are implemented
const (
	NoAuth SnmpV3AuthProtocol = 1
	MD5    SnmpV3AuthProtocol = 2
	SHA    SnmpV3AuthProtocol = 3
)

// SnmpV3PrivProtocol is the privacy protocol in use by an private SnmpV3 connection.
type SnmpV3PrivProtocol uint8

// NoPriv, DES implemented, AES planned
const (
	NoPriv SnmpV3PrivProtocol = 1
	DES    SnmpV3PrivProtocol = 2
	AES    SnmpV3PrivProtocol = 3
)

// UsmSecurityParameters is an implementation of SnmpV3SecurityParameters for the UserSecurityModel
type UsmSecurityParameters struct {
	AuthoritativeEngineID    string
	AuthoritativeEngineBoots uint32
	AuthoritativeEngineTime  uint32
	UserName                 string
	AuthenticationParameters string
	PrivacyParameters        []byte

	AuthenticationProtocol SnmpV3AuthProtocol
	PrivacyProtocol        SnmpV3PrivProtocol

	AuthenticationPassphrase string
	PrivacyPassphrase        string

	localDESSalt uint32
	localAESSalt uint64
}

// Copy method for UsmSecurityParameters used to copy a SnmpV3SecurityParameters without knowing it's implementation
func (sp *UsmSecurityParameters) Copy() SnmpV3SecurityParameters {
	return &UsmSecurityParameters{AuthoritativeEngineID: sp.AuthoritativeEngineID,
		AuthoritativeEngineBoots: sp.AuthoritativeEngineBoots,
		AuthoritativeEngineTime:  sp.AuthoritativeEngineTime,
		UserName:                 sp.UserName,
		AuthenticationParameters: sp.AuthenticationParameters,
		PrivacyParameters:        sp.PrivacyParameters,
		AuthenticationProtocol:   sp.AuthenticationProtocol,
		PrivacyProtocol:          sp.PrivacyProtocol,
		AuthenticationPassphrase: sp.AuthenticationPassphrase,
		PrivacyPassphrase:        sp.PrivacyPassphrase,
		localDESSalt:             sp.localDESSalt,
		localAESSalt:             sp.localAESSalt,
	}
}

func (sp *UsmSecurityParameters) Validate(flags SnmpV3MsgFlags) error {

	securityLevel := flags & AuthPriv // isolate flags that determine security level

	switch securityLevel {
	case AuthPriv:
		if sp.PrivacyProtocol <= NoPriv {
			return fmt.Errorf("SecurityParameters.PrivacyProtocol is required")
		}
		if sp.PrivacyPassphrase == "" {
			return fmt.Errorf("SecurityParameters.PrivacyPassphrase is required")
		}
		fallthrough
	case AuthNoPriv:
		if sp.AuthenticationProtocol <= NoAuth {
			return fmt.Errorf("SecurityParameters.AuthenticationProtocol is required")
		}
		if sp.AuthenticationPassphrase == "" {
			return fmt.Errorf("SecurityParameters.AuthenticationPassphrase is required")
		}
		fallthrough
	case NoAuthNoPriv:
		if sp.UserName == "" {
			return fmt.Errorf("SecurityParameters.UserName is required")
		}
	default:
		return fmt.Errorf("MsgFlags must be populated with an appropriate security level")
	}

	return nil
}

func (sp *UsmSecurityParameters) Init() error {
	var err error

	switch sp.PrivacyProtocol {
	case AES:
		salt := make([]byte, 8)
		_, err = crand.Read(salt)
		if err != nil {
			return fmt.Errorf("Error creating a cryptographically secure salt: %s\n", err.Error())
		}
		sp.localAESSalt = binary.BigEndian.Uint64(salt)
	case DES:
		salt := make([]byte, 4)
		_, err = crand.Read(salt)
		if err != nil {
			return fmt.Errorf("Error creating a cryptographically secure salt: %s\n", err.Error())
		}
		sp.localDESSalt = binary.BigEndian.Uint32(salt)
	}

	return nil
}
