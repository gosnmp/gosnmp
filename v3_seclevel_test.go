// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build all || marshal

package gosnmp

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// The tests below check that an established session takes the security
// level of an incoming message from the message's own msgFlags (RFC 3412
// section 7.2 step 5) and only accepts responses at the level of the request
// (step 12), while a Report below that level is classified but not trusted
// (step 11).

// setV3MsgFlags returns a copy of a marshaled v3 message with its msgFlags
// octet replaced, for flag combinations the marshaling code won't produce.
// The msgFlags field is the one-octet OCTET STRING followed by the USM
// msgSecurityModel INTEGER in msgGlobalData.
func setV3MsgFlags(t *testing.T, msg []byte, flags SnmpV3MsgFlags) []byte {
	t.Helper()
	out := append([]byte(nil), msg...)
	for i := 0; i+6 <= len(out); i++ {
		if out[i] == byte(OctetString) && out[i+1] == 1 &&
			bytes.Equal(out[i+3:i+6], []byte{byte(Integer), 1, byte(UserSecurityModel)}) {
			out[i+2] = byte(flags)
			return out
		}
	}
	t.Fatal("msgFlags not found in marshaled message")
	return nil
}

func v3SeclevelSeedSession(sp *UsmSecurityParameters) {
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = v3HarnessBoots
	sp.AuthoritativeEngineTime = v3HarnessTime
}

// TestV3SeclevelUnauthenticatedReportIsClassified checks that a noAuthNoPriv
// usmStatsNotInTimeWindows Report on an authenticated session is classified
// instead of failing HMAC verification, and that its unauthenticated engine
// boots and time are neither stored nor used for a resend.
func TestV3SeclevelUnauthenticatedReportIsClassified(t *testing.T) {
	const reportedBoots, reportedTime uint32 = 99, 5
	noAuth := NoAuthNoPriv
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{func(req *v3TestAgentRequest) [][]byte {
		boots, engineTime := reportedBoots, reportedTime
		return agent.reply(req, v3TestAgentReply{
			pduType:    Report,
			vars:       []SnmpPDU{{Name: usmStatsNotInTimeWindows, Type: Counter32, Value: uint32(1)}},
			boots:      &boots,
			engineTime: &engineTime,
			msgFlags:   &noAuth,
		})
	}}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3SeclevelSeedSession(sp)
	v3HarnessConnect(t, gs)

	_, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.ErrorIs(t, err, ErrNotInTimeWindow)
	requireRequestCount(t, agent, 1)
	require.Equal(t, v3HarnessBoots, sp.AuthoritativeEngineBoots)
	requireEngineTimeNear(t, v3HarnessTime, sp.AuthoritativeEngineTime)
}

// TestV3SeclevelAuthPrivRejectsAuthNoPrivResponse checks that an authPriv
// request does not accept a correctly authenticated but unencrypted response.
func TestV3SeclevelAuthPrivRejectsAuthNoPrivResponse(t *testing.T) {
	authNoPriv := AuthNoPriv
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthPriv())
	agent.steps = []v3TestAgentStep{func(req *v3TestAgentRequest) [][]byte {
		return agent.reply(req, v3TestAgentReply{
			pduType:  GetResponse,
			vars:     []SnmpPDU{{Name: v3HarnessSysDescrOID, Type: OctetString, Value: v3HarnessSysDescrValue}},
			msgFlags: &authNoPriv,
		})
	}}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthPriv, agent.creds)
	v3SeclevelSeedSession(sp)
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.Error(t, err)
	require.Nil(t, result)
	requireRequestCount(t, agent, 1)
}

// TestV3SeclevelRejectsPrivWithoutAuth checks that a response whose msgFlags
// ask for privacy without authentication is discarded.
func TestV3SeclevelRejectsPrivWithoutAuth(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3TestAgentCreds{username: v3HarnessUser})
	sysDescr := v3AgentSysDescr(agent)
	agent.steps = []v3TestAgentStep{func(req *v3TestAgentRequest) [][]byte {
		out := sysDescr(req)
		if len(out) != 1 {
			return out
		}
		return [][]byte{setV3MsgFlags(t, out[0], AuthPriv&^AuthNoPriv)}
	}}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, NoAuthNoPriv, agent.creds)
	v3SeclevelSeedSession(sp)
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.Error(t, err)
	require.Nil(t, result)
	requireRequestCount(t, agent, 1)
}

// TestV3SeclevelAuthPrivHonoursAuthenticatedReport checks that an
// authenticated Report below an authPriv request's level is still acted on,
// as RFC 3414 section 3.2 step 7(a) sends usmStatsNotInTimeWindows authNoPriv.
func TestV3SeclevelAuthPrivHonoursAuthenticatedReport(t *testing.T) {
	const staleBoots, staleTime uint32 = 1, 100
	authNoPriv := AuthNoPriv
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthPriv())
	agent.steps = []v3TestAgentStep{
		func(req *v3TestAgentRequest) [][]byte {
			return agent.reply(req, v3TestAgentReply{
				pduType:  Report,
				vars:     []SnmpPDU{{Name: usmStatsNotInTimeWindows, Type: Counter32, Value: uint32(1)}},
				msgFlags: &authNoPriv,
			})
		},
		v3AgentSysDescr(agent),
	}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthPriv, agent.creds)
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = staleBoots
	sp.AuthoritativeEngineTime = staleTime
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, 2, agent.requestCount())
	require.Equal(t, v3HarnessBoots, v3ReqSecParams(t, agent.request(1)).AuthoritativeEngineBoots)
}

// TestV3SeclevelPlaintextPDUWithPrivacyFlag checks that a scopedPDU sent in
// the clear is not accepted from a message whose msgFlags ask for privacy.
func TestV3SeclevelPlaintextPDUWithPrivacyFlag(t *testing.T) {
	gs := newTestGoSNMPv3(NoAuthNoPriv, &UsmSecurityParameters{UserName: v3HarnessUser})
	plain := &SnmpPacket{
		Version:            Version3,
		MsgFlags:           NoAuthNoPriv,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{UserName: v3HarnessUser, AuthoritativeEngineID: v3HarnessEngineID},
		PDUType:            GetResponse,
		MsgID:              1,
		RequestID:          1,
		Variables:          []SnmpPDU{{Name: v3HarnessSysDescrOID, Type: OctetString, Value: v3HarnessSysDescrValue}},
	}
	msg, err := plain.MarshalMsg()
	require.NoError(t, err)

	result := &SnmpPacket{SecurityParameters: &UsmSecurityParameters{}, Logger: gs.Logger}
	cursor, err := gs.unmarshalHeader(msg, result)
	require.NoError(t, err)

	_, _, err = gs.decryptPacket(msg, cursor, result)
	require.NoError(t, err, "a plaintext scopedPDU without privacy is accepted")

	result.MsgFlags = AuthPriv
	_, _, err = gs.decryptPacket(msg, cursor, result)
	require.ErrorContains(t, err, "scopedPDU encryption does not match msgFlags")
}
