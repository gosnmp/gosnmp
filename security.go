// Copyright 2012-2014 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"crypto/md5"
	"crypto/sha1"
	"fmt"
	"hash"
)

// authenticate the marshalled result of a snmp version 3 packet
func (packet *SnmpPacket) authenticate(msg []byte, authParamStart uint32) ([]byte, error) {
	defer func() {
		if e := recover(); e != nil {
			fmt.Printf("recover: %v\n", e)
		}
	}()
	if packet.Version != Version3 {
		return msg, nil
	}
	if packet.MsgFlags&AuthNoPriv == 0 {
		return msg, nil
	}
	if packet.SecurityModel != UserSecurityModel {
		return nil, fmt.Errorf("Error authenticating message: Unknown security model.")
	}

	var secParams *UsmSecurityParameters
	secParams, ok := packet.SecurityParameters.(*UsmSecurityParameters)
	if !ok || secParams == nil {
		return nil, fmt.Errorf("Error authenticating message: Unable to extract UsmSecurityParameters")
	}
	var secretKey = genlocalkey(secParams.AuthenticationProtocol,
		secParams.AuthenticationPassphrase,
		secParams.AuthoritativeEngineID)

	var extkey [64]byte

	copy(extkey[:], secretKey)

	var k1, k2 [64]byte

	for i := 0; i < 64; i++ {
		k1[i] = extkey[i] ^ 0x36
		k2[i] = extkey[i] ^ 0x5c
	}

	var h, h2 hash.Hash

	switch secParams.AuthenticationProtocol {
	default:
		h = md5.New()
		h2 = md5.New()
	case SHA:
		h = sha1.New()
		h2 = sha1.New()
	}

	h.Write(k1[:])
	h.Write(msg)
	d1 := h.Sum(nil)
	h2.Write(k2[:])
	h2.Write(d1)
	copy(msg[authParamStart:authParamStart+12], h2.Sum(nil)[:12])
	return msg, nil
}

// determine whether a message is authentic
func isAuthentic(msg []byte, authParams string, authProtocol SnmpV3AuthProtocol, authPassphrase string, authEngineID string) bool {
	var secretKey = genlocalkey(authProtocol,
		authPassphrase,
		authEngineID)

	var extkey [64]byte

	copy(extkey[:], secretKey)

	var k1, k2 [64]byte

	for i := 0; i < 64; i++ {
		k1[i] = extkey[i] ^ 0x36
		k2[i] = extkey[i] ^ 0x5c
	}

	var h, h2 hash.Hash

	switch authProtocol {
	default:
		h = md5.New()
		h2 = md5.New()
	case SHA:
		h = sha1.New()
		h2 = sha1.New()
	}

	h.Write(k1[:])
	h.Write(msg)
	d1 := h.Sum(nil)
	h2.Write(k2[:])
	h2.Write(d1)

	result := h2.Sum(nil)[:12]
	for k, v := range []byte(authParams) {
		if result[k] != v {
			return false
		}
	}
	return true
}

// MD5 HMAC key calculation algorithm
func md5HMAC(password string, engineID string) []byte {
	comp := md5.New()
	var pi int // password index
	for i := 0; i < 1048576; i += 64 {
		var chunk []byte
		for e := 0; e < 64; e++ {
			chunk = append(chunk, password[pi%len(password)])
			pi++
		}
		comp.Write(chunk)
	}
	compressed := comp.Sum(nil)
	local := md5.New()
	local.Write(compressed)
	local.Write([]byte(engineID))
	local.Write(compressed)
	final := local.Sum(nil)
	return final
}

// SHA HMAC key calculation algorithm
func shaHMAC(password string, engineID string) []byte {
	hash := sha1.New()
	var pi int // password index
	for i := 0; i < 1048576; i += 64 {
		var chunk []byte
		for e := 0; e < 64; e++ {
			chunk = append(chunk, password[pi%len(password)])
			pi++
		}
		hash.Write(chunk)
	}
	hashed := hash.Sum(nil)
	local := sha1.New()
	local.Write(hashed)
	local.Write([]byte(engineID))
	local.Write(hashed)
	final := local.Sum(nil)
	return final
}

func genlocalkey(authProtocol SnmpV3AuthProtocol, passphrase string, engineID string) []byte {
	var secretKey []byte
	switch authProtocol {
	default:
		secretKey = md5HMAC(passphrase, engineID)
	case SHA:
		secretKey = shaHMAC(passphrase, engineID)
	}
	return secretKey
}
