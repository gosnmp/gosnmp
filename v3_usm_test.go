// Copyright 2020 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"encoding/hex"
	"io"
	"log"
	"testing"

	"github.com/stretchr/testify/require"
)

/**
 * This tests use hex dumps from real network traffic produced using net-snmp's snmpget with demo.snmplabs.com as SNMP agent.
 */

func authorativeEngineID(t *testing.T) string {
	// engine ID of demo.snmplabs.com
	engineID, err := hex.DecodeString("80004fb805636c6f75644dab22cc")
	require.NoError(t, err, "EngineId decoding failed.")

	return string(engineID)
}

func correctKeySHA224(t *testing.T) []byte {
	correctKey, err := hex.DecodeString("f2a2ebaa9677ad286255596286ca4fb7ec22f52405cb0aac334c5f15")
	require.NoError(t, err, "Correct key initialization failed.")

	return correctKey
}

func packetSHA224NoAuthentication(t *testing.T) []byte {
	packet, err := hex.DecodeString("308184020103300e02025f84020205c0040105020103043f303d040e80004fb805636c6f75644dab22cc02012b0203203ea5040f7573722d7368613232342d6e6f6e650410000000000000000000000000000000000400302e040e80004fb805636c6f75644dab22cc0400a01a02023ced020100020100300e300c06082b060102010101000500")

	require.NoError(t, err, "Non-authenticated packet data SHA224 decoding failed.")
	return packet
}

func packetSHA224Authenticated(t *testing.T) []byte {
	packet, err := hex.DecodeString("308184020103300e02025f84020205c0040105020103043f303d040e80004fb805636c6f75644dab22cc02012b0203203ea5040f7573722d7368613232342d6e6f6e65041066cd2d9b04cd48b02a9df0c77dc3415d0400302e040e80004fb805636c6f75644dab22cc0400a01a02023ced020100020100300e300c06082b060102010101000500")

	require.NoError(t, err, "Authenticated packet data SHA224 decoding failed.")
	return packet
}

func packetSHA224AuthenticationParams(t *testing.T) string {
	params, err := hex.DecodeString("66cd2d9b04cd48b02a9df0c77dc3415d")

	require.NoError(t, err, "Authentication parameters SHA224 decoding failed.")
	return string(params)
}

func TestIsAuthenticWrongUsername(t *testing.T) {
	var err error

	sp := UsmSecurityParameters{
		localAESSalt:             0,
		localDESSalt:             0,
		AuthoritativeEngineBoots: 43,
		AuthoritativeEngineID:    authorativeEngineID(t),
		AuthoritativeEngineTime:  2113189,
		UserName:                 "usr-sha224-none",
		AuthenticationParameters: packetSHA224AuthenticationParams(t),
		PrivacyParameters:        nil,
		AuthenticationProtocol:   SHA224,
		PrivacyProtocol:          0,
		AuthenticationPassphrase: "authkey1",
		PrivacyPassphrase:        "",
		SecretKey:                nil,
		PrivacyKey:               nil,
		Logger:                   NewLogger(log.New(io.Discard, "", 0)),
	}

	sp.SecretKey, err = genlocalkey(sp.AuthenticationProtocol,
		sp.AuthenticationPassphrase,
		sp.AuthoritativeEngineID)

	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA224(t), sp.SecretKey, "Wrong key generated")

	srcPacket := packetSHA224NoAuthentication(t)

	snmpPacket := SnmpPacket{
		SecurityParameters: sp.Copy(),
	}
	snmpPacket.SecurityParameters.(*UsmSecurityParameters).UserName = "foo"

	authentic, err := sp.isAuthentic(srcPacket, &snmpPacket)
	require.NoError(t, err, "Authentication check of key failed")
	require.False(t, authentic, "Packet was considered to be authentic")
}

func TestAuthenticationSHA224(t *testing.T) {
	var err error

	sp := UsmSecurityParameters{
		localAESSalt:             0,
		localDESSalt:             0,
		AuthoritativeEngineBoots: 43,
		AuthoritativeEngineID:    authorativeEngineID(t),
		AuthoritativeEngineTime:  2113189,
		UserName:                 "usr-sha224-none",
		AuthenticationParameters: "",
		PrivacyParameters:        nil,
		AuthenticationProtocol:   SHA224,
		PrivacyProtocol:          0,
		AuthenticationPassphrase: "authkey1",
		PrivacyPassphrase:        "",
		SecretKey:                nil,
		Logger:                   NewLogger(log.New(io.Discard, "", 0)),
		PrivacyKey:               nil,
	}

	sp.SecretKey, err = genlocalkey(sp.AuthenticationProtocol,
		sp.AuthenticationPassphrase,
		sp.AuthoritativeEngineID)

	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA224(t), sp.SecretKey, "Wrong key generated")

	srcPacket := packetSHA224NoAuthentication(t)
	err = sp.authenticate(srcPacket)
	require.NoError(t, err, "Authentication of packet failed")

	require.Equal(t, packetSHA224Authenticated(t), srcPacket, "Wrong message authentication parameters.")
}

func TestIsAuthenticSHA224(t *testing.T) {
	var err error

	sp := UsmSecurityParameters{
		localAESSalt:             0,
		localDESSalt:             0,
		AuthoritativeEngineBoots: 43,
		AuthoritativeEngineID:    authorativeEngineID(t),
		AuthoritativeEngineTime:  2113189,
		UserName:                 "usr-sha224-none",
		AuthenticationParameters: packetSHA224AuthenticationParams(t),
		PrivacyParameters:        nil,
		AuthenticationProtocol:   SHA224,
		PrivacyProtocol:          0,
		AuthenticationPassphrase: "authkey1",
		PrivacyPassphrase:        "",
		SecretKey:                nil,
		PrivacyKey:               nil,
		Logger:                   NewLogger(log.New(io.Discard, "", 0)),
	}

	sp.SecretKey, err = genlocalkey(sp.AuthenticationProtocol,
		sp.AuthenticationPassphrase,
		sp.AuthoritativeEngineID)

	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA224(t), sp.SecretKey, "Wrong key generated")

	srcPacket := packetSHA224NoAuthentication(t)

	snmpPacket := SnmpPacket{
		SecurityParameters: &sp,
	}

	authentic, err := sp.isAuthentic(srcPacket, &snmpPacket)
	require.NoError(t, err, "Authentication check of key failed")
	require.True(t, authentic, "Packet was not considered to be authentic")
}

func correctKeySHA512(t *testing.T) []byte {
	correctKey, err := hex.DecodeString("c336e5e6396926813d623984610e8f0cd7f419da75c82ac50927c84fd92027f7cdd849ce983036dca67bfb1e8fde2a8c2d45cd2f0d3e0b0b929f7dda462a58cf")
	require.NoError(t, err, "Correct key initialization failed.")

	return correctKey
}

func packetSHA512NoAuthentication(t *testing.T) []byte {
	packet, err := hex.DecodeString("3081a4020103300e0202366e020205c0040105020103045f305d040e80004fb805636c6f75644dab22cc02012b0203203eea040f7573722d7368613531322d6e6f6e6504300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400302e040e80004fb805636c6f75644dab22cc0400a01a020214d9020100020100300e300c06082b060102010101000500")

	require.NoError(t, err, "Not-authenticated packet data SHA512 decoding failed.")
	return packet
}

func packetSHA512Authenticated(t *testing.T) []byte {
	packet, err := hex.DecodeString("3081a4020103300e0202366e020205c0040105020103045f305d040e80004fb805636c6f75644dab22cc02012b0203203eea040f7573722d7368613531322d6e6f6e65043026f8087ced336a394642b8698eba9810929a9bfa44afbf43975a7ad6c4cc55bd279b549a77ec56d791467612747d6f570400302e040e80004fb805636c6f75644dab22cc0400a01a020214d9020100020100300e300c06082b060102010101000500")

	require.NoError(t, err, "Authenticated packet data SHA512 decoding failed.")
	return packet
}

func packetSHA512AuthenticationParams(t *testing.T) string {
	params, err := hex.DecodeString("26f8087ced336a394642b8698eba9810929a9bfa44afbf43975a7ad6c4cc55bd279b549a77ec56d791467612747d6f57")

	require.NoError(t, err, "Authentication parameters SHA512 decoding failed.")
	return string(params)
}

func TestAuthenticationSHA512(t *testing.T) {
	var err error

	sp := UsmSecurityParameters{
		localAESSalt:             0,
		localDESSalt:             0,
		AuthoritativeEngineBoots: 43,
		AuthoritativeEngineID:    authorativeEngineID(t),
		AuthoritativeEngineTime:  2113258,
		UserName:                 "usr-sha512-none",
		AuthenticationParameters: "",
		PrivacyParameters:        nil,
		AuthenticationProtocol:   SHA512,
		PrivacyProtocol:          0,
		AuthenticationPassphrase: "authkey1",
		PrivacyPassphrase:        "",
		SecretKey:                nil,
		PrivacyKey:               nil,
		Logger:                   NewLogger(log.New(io.Discard, "", 0)),
	}

	sp.SecretKey, err = genlocalkey(sp.AuthenticationProtocol,
		sp.AuthenticationPassphrase,
		sp.AuthoritativeEngineID)

	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA512(t), sp.SecretKey, "Wrong key generated")

	srcPacket := packetSHA512NoAuthentication(t)
	err = sp.authenticate(srcPacket)
	require.NoError(t, err, "Generation of key failed")

	require.Equal(t, packetSHA512Authenticated(t), srcPacket, "Wrong message authentication parameters.")
}

func TestIsAuthenticSHA512(t *testing.T) {
	var err error

	sp := UsmSecurityParameters{
		localAESSalt:             0,
		localDESSalt:             0,
		AuthoritativeEngineBoots: 43,
		AuthoritativeEngineID:    authorativeEngineID(t),
		AuthoritativeEngineTime:  2113189,
		UserName:                 "usr-sha512-none",
		AuthenticationParameters: packetSHA512AuthenticationParams(t),
		PrivacyParameters:        nil,
		AuthenticationProtocol:   SHA512,
		PrivacyProtocol:          0,
		AuthenticationPassphrase: "authkey1",
		PrivacyPassphrase:        "",
		SecretKey:                nil,
		Logger:                   NewLogger(log.New(io.Discard, "", 0)),
		PrivacyKey:               nil,
	}

	sp.SecretKey, err = genlocalkey(sp.AuthenticationProtocol,
		sp.AuthenticationPassphrase,
		sp.AuthoritativeEngineID)

	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA512(t), sp.SecretKey, "Wrong key generated")

	srcPacket := packetSHA512NoAuthentication(t)

	snmpPacket := SnmpPacket{
		SecurityParameters: &sp,
	}

	authentic, err := sp.isAuthentic(srcPacket, &snmpPacket)
	require.NoError(t, err, "Authentication check of key failed")
	require.True(t, authentic, "Packet was not considered to be authentic")
}

// TestUnmarshalTruncatedUSMSequence verifies that unmarshal returns an error
// rather than panicking when the USM SEQUENCE body is truncated.
//
// The bounds check at v3_usm.go:991 originally compared cursorTmp (the BER
// length-header size, a small relative increment) against len(packet) rather
// than cursor (the updated absolute position). Because parseLength guarantees
// cursorTmp <= len(packet[cursor:]), cursor after incrementing is at most
// len(packet) and the check never fires either way. The fix uses the correct
// variable so the check reflects its intended purpose.
func TestUnmarshalTruncatedUSMSequence(t *testing.T) {
	sp := &UsmSecurityParameters{
		Logger: NewLogger(log.New(io.Discard, "", 0)),
	}

	tests := []struct {
		name   string
		packet []byte
		cursor int
	}{
		{
			name:   "short-form length zero",
			packet: []byte{0x30, 0x00},
			cursor: 0,
		},
		{
			name: "long-form length one extra byte truncated body",
			// 0x81 signals long-form with 1 extra length byte; body is absent.
			// cursorTmp = 3 (2 + 1); cursor advances to 3 == len(packet).
			// Old check: cursorTmp(3) > len(packet)(3) → false (check is dead).
			// New check: cursor(3)    > len(packet)(3) → false (boundary, not past end).
			// Either way execution reaches parseRawField with an empty slice → error.
			packet: []byte{0x30, 0x81, 0x05},
			cursor: 0,
		},
		{
			name:   "long-form with non-zero starting cursor",
			packet: []byte{0xff, 0xff, 0x30, 0x81, 0x05},
			cursor: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, err := sp.unmarshal(NoAuthNoPriv, tt.packet, tt.cursor)
				require.Error(t, err)
			})
		})
	}
}

func BenchmarkSingleHash(b *testing.B) {
	SetPwdCache()

	engineID, _ := hex.DecodeString("80004fb805636c6f75644dab22cc")

	for i := MD5; i < SHA512; i++ {
		b.Run(b.Name()+i.String(), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, err := genlocalkey(i, "authkey1", string(engineID))
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}

	passwordKeyHashMutex.RLock()
	b.Logf("cache size %d", len(passwordKeyHashCache))
	passwordKeyHashMutex.RUnlock()
}

// The DES and AES branches of encryptPacket/decryptPacket index the privacy
// key and the privacy parameters at fixed offsets. RFC 3414 8.1.1.1 and
// RFC 3826 3.1.2.1 both fix the privacy parameters at 8 octets, but unmarshal
// copies that field verbatim off the wire, so the length has to be checked
// before it is used as IV material.
func TestPrivacyMaterialLength(t *testing.T) {
	tests := []struct {
		name    string
		priv    SnmpV3PrivProtocol
		keyLen  int
		saltLen int
		wantErr string
	}{
		{"DES empty salt", DES, 16, 0, "invalid privacy parameters"},
		{"DES short salt", DES, 16, 7, "invalid privacy parameters"},
		{"DES long salt", DES, 16, 9, "invalid privacy parameters"},
		{"DES no key", DES, 0, 8, "invalid DES privacy key"},
		{"DES short key", DES, 15, 8, "invalid DES privacy key"},
		{"DES ok", DES, 16, 8, ""},
		{"AES empty salt", AES, 16, 0, "invalid privacy parameters"},
		{"AES short salt", AES, 16, 7, "invalid privacy parameters"},
		{"AES long salt", AES, 16, 9, "invalid privacy parameters"},
		{"AES ok", AES, 16, 8, ""},
		{"AES256C ok", AES256C, 32, 8, ""},
		{"NoPriv is not checked", NoPriv, 0, 0, ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sp := &UsmSecurityParameters{
				PrivacyProtocol:   test.priv,
				PrivacyKey:        make([]byte, test.keyLen),
				PrivacyParameters: make([]byte, test.saltLen),
				Logger:            NewLogger(log.New(io.Discard, "", 0)),
			}

			// a well formed OCTET STRING holding one AES block, which is also
			// a whole number of DES blocks
			packet := append([]byte{byte(OctetString), 16}, make([]byte, 16)...)
			_, decErr := sp.decryptPacket(packet, 0)
			_, encErr := sp.encryptPacket(make([]byte, 16))

			for _, err := range []error{decErr, encErr} {
				if test.wantErr == "" {
					require.NoError(t, err)
					continue
				}
				require.ErrorContains(t, err, test.wantErr)
			}
		})
	}
}

// authPriv DES GetRequest for .1.3.6.1.2.1.1.1.0, produced by SnmpEncodePacket
// with the parameters of desPrivSession below, then the same packet with its
// msgPrivacyParameters shortened to 0 and to 1 octet.
func packetDESPriv(t *testing.T) []byte {
	packet, err := hex.DecodeString("30790201033011020400000001020300ffff04010702010304373035040e80004fb805636c6f75644dab22cc02012b0203203ea50403757372040cc1e6d9a212ccfd01ff8dec5604080000002b92db5e0704280351ab9ef9395404ff63637520517fdf079e2ec6f45a1d6512c77f832fb4aff273aa24fcff6cfdbd")
	require.NoError(t, err, "authPriv DES packet decoding failed.")
	return packet
}

func packetDESPrivEmptySalt(t *testing.T) []byte {
	packet, err := hex.DecodeString("30710201033011020400000001020300ffff040107020103042f302d040e80004fb805636c6f75644dab22cc02012b0203203ea50403757372040cc1e6d9a212ccfd01ff8dec56040004280351ab9ef9395404ff63637520517fdf079e2ec6f45a1d6512c77f832fb4aff273aa24fcff6cfdbd")
	require.NoError(t, err, "empty salt packet decoding failed.")
	return packet
}

func packetDESPrivOneByteSalt(t *testing.T) []byte {
	packet, err := hex.DecodeString("30720201033011020400000001020300ffff0401070201030430302e040e80004fb805636c6f75644dab22cc02012b0203203ea50403757372040cc1e6d9a212ccfd01ff8dec560401a004280351ab9ef9395404ff63637520517fdf079e2ec6f45a1d6512c77f832fb4aff273aa24fcff6cfdbd")
	require.NoError(t, err, "one byte salt packet decoding failed.")
	return packet
}

func desPrivSession(t *testing.T) *GoSNMP {
	sp := &UsmSecurityParameters{
		UserName:                 "usr",
		AuthenticationProtocol:   MD5,
		AuthenticationPassphrase: "authkey1",
		PrivacyProtocol:          DES,
		PrivacyPassphrase:        "privkey1",
		AuthoritativeEngineID:    authorativeEngineID(t),
		AuthoritativeEngineBoots: 43,
		AuthoritativeEngineTime:  2113189,
		Logger:                   NewLogger(log.New(io.Discard, "", 0)),
	}
	require.NoError(t, sp.InitSecurityKeys(), "Generation of keys failed")

	return newTestGoSNMPv3(AuthPriv, sp)
}

// SnmpDecodePacket reaches decryptPacket without an authentication check, so a
// short msgPrivacyParameters used to take the DES branch out of bounds.
func TestSnmpDecodePacketPrivacyParametersLength(t *testing.T) {
	result, err := desPrivSession(t).SnmpDecodePacket(packetDESPriv(t))
	require.NoError(t, err, "the unmodified packet must still decode")
	require.Len(t, result.Variables, 1)
	require.Equal(t, ".1.3.6.1.2.1.1.1.0", result.Variables[0].Name)

	for name, packet := range map[string][]byte{
		"empty salt":    packetDESPrivEmptySalt(t),
		"one byte salt": packetDESPrivOneByteSalt(t),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := desPrivSession(t).SnmpDecodePacket(packet)
			require.ErrorContains(t, err, "invalid privacy parameters")
		})
	}
}

// A TrapListener using TrapSecurityParametersTable authenticates with the
// msgFlags of the received message, so a sender that clears the auth flag
// skips the MAC check and still reaches decryptPacket - it is the scoped PDU
// being an OCTET STRING, not the flags, that triggers decryption.
func TestUnmarshalTrapPrivacyParametersLength(t *testing.T) {
	packet := packetDESPrivOneByteSalt(t)
	require.Equal(t, byte(AuthPriv|Reportable), packet[20], "msgFlags is not where it is expected")
	packet[20] = byte(Reportable)

	x := desPrivSession(t)
	table := NewSnmpV3SecurityParametersTable(x.Logger)
	securityParameters := x.SecurityParameters.Copy()
	require.NoError(t, table.Add(securityParameters.getIdentifier(), securityParameters))
	x.TrapSecurityParametersTable = table

	_, err := x.UnmarshalTrap(packet, true)
	require.ErrorContains(t, err, "invalid privacy parameters")
}
