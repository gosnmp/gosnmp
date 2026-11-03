// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build all || marshal

package gosnmp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/require"
)

// The tests below pin externally visible v3 send-path behavior that is
// intended to stay stable: engine-ID discovery, the authenticated
// notInTimeWindows resend, per-attempt msgID/request-id freshness, and
// retry/callback/timeout accounting. Later behavior changes are expected to
// keep these green.

var v3HarnessEngineID = string([]byte{0x80, 0x00, 0x1f, 0x88, 0x04, 'h', 'a', 'r', 'n', 'e', 's', 's'})

const (
	v3HarnessUser           = "harnessUser"
	v3HarnessAuthKey        = "harnessAuthKey1"
	v3HarnessPrivKey        = "harnessPrivKey1"
	v3HarnessBoots   uint32 = 7
	v3HarnessTime    uint32 = 424242

	v3HarnessSysDescrOID   = ".1.3.6.1.2.1.1.1.0"
	v3HarnessSysDescrValue = "harness sysDescr"
)

func v3HarnessCredsAuthNoPriv() v3TestAgentCreds {
	return v3TestAgentCreds{username: v3HarnessUser, authProto: SHA, authPass: v3HarnessAuthKey}
}

func v3HarnessCredsAuthPriv() v3TestAgentCreds {
	c := v3HarnessCredsAuthNoPriv()
	c.privProto = AES
	c.privPass = v3HarnessPrivKey
	return c
}

// newV3HarnessClient builds a v3 client for the given agent credentials. The
// engine ID is left empty, so the first request triggers discovery unless the
// caller pre-seeds the returned security parameters.
func newV3HarnessClient(port uint16, flags SnmpV3MsgFlags, creds v3TestAgentCreds) (*GoSNMP, *UsmSecurityParameters) {
	sp := &UsmSecurityParameters{
		UserName:                 creds.username,
		AuthenticationProtocol:   creds.authProto,
		AuthenticationPassphrase: creds.authPass,
		PrivacyProtocol:          creds.privProto,
		PrivacyPassphrase:        creds.privPass,
	}
	gs := newTestGoSNMPv3(flags, sp)
	gs.Target = "127.0.0.1"
	gs.Port = port
	gs.Timeout = 500 * time.Millisecond
	gs.Retries = 0
	gs.ExponentialTimeout = false
	return gs, sp
}

func v3HarnessConnect(t *testing.T, gs *GoSNMP) {
	t.Helper()
	require.NoError(t, gs.Connect())
	t.Cleanup(func() { gs.Conn.Close() })
}

// v3AgentDrop ignores the request so the client retries or times out.
func v3AgentDrop(*v3TestAgentRequest) [][]byte { return nil }

// v3AgentSysDescr answers any request with a single-varbind GetResponse.
func v3AgentSysDescr(a *v3TestAgent) v3TestAgentStep {
	return func(req *v3TestAgentRequest) [][]byte {
		return a.reply(req, v3TestAgentReply{pduType: GetResponse, vars: []SnmpPDU{{
			Name:  v3HarnessSysDescrOID,
			Value: v3HarnessSysDescrValue,
			Type:  OctetString,
		}}})
	}
}

// v3AgentFixtureReport replays a complete libsnmp-generated REPORT. It checks
// the fixed identifiers before replying so a missing or misplaced seed fails
// at the harness boundary instead of becoming an opaque client timeout.
func v3AgentFixtureReport(a *v3TestAgent, fixture v3HarnessFixture) v3TestAgentStep {
	return func(req *v3TestAgentRequest) [][]byte {
		if req.Packet.MsgID != fixture.msgID || req.Packet.RequestID != fixture.requestID {
			a.sendErr(fmt.Errorf("%s fixture identifiers: got msgID %d/request-id %d, want %d/%d",
				fixture.name, req.Packet.MsgID, req.Packet.RequestID, fixture.msgID, fixture.requestID))
			return nil
		}
		packet, err := fixture.decode()
		if err != nil {
			a.sendErr(err)
			return nil
		}
		return [][]byte{packet}
	}
}

// v3AgentUnknownEngineIDsReport answers with a standard noAuthNoPriv
// discovery REPORT carrying the agent fixture's engine ID, boots, and time.
func v3AgentUnknownEngineIDsReport(a *v3TestAgent) v3TestAgentStep {
	return v3AgentFixtureReport(a, v3UnknownEngineIDsReportFixture)
}

// v3AgentNotInTimeWindowsReport answers with the RFC 3414 3.2 step 7(a)
// authNoPriv REPORT carrying the agent fixture's current boots/time.
func v3AgentNotInTimeWindowsReport(a *v3TestAgent) v3TestAgentStep {
	return v3AgentFixtureReport(a, v3NotInTimeWindowsReportFixture)
}

func v3ReqSecParams(t *testing.T, req *v3TestAgentRequest) *UsmSecurityParameters {
	t.Helper()
	usp, ok := req.Packet.SecurityParameters.(*UsmSecurityParameters)
	require.True(t, ok)
	return usp
}

// requireEngineTimeNear asserts an engine-time value against a small forward
// window instead of exact equality, so the assertions stay valid if the
// static engine-time snapshot ever becomes an advancing estimate.
func requireEngineTimeNear(t *testing.T, want, got uint32) {
	t.Helper()
	require.GreaterOrEqual(t, got, want)
	require.LessOrEqual(t, got, want+2)
}

// requireRequestCount asserts the number of requests the agent received. For
// timeout-terminated tests the last datagram may still be in flight when the
// client gives up, so wait for the count before pinning it exactly.
func requireRequestCount(t *testing.T, agent *v3TestAgent, want int) {
	t.Helper()
	require.Eventually(t, func() bool { return agent.requestCount() >= want },
		time.Second, 5*time.Millisecond)
	require.Equal(t, want, agent.requestCount())
}

func requireSysDescrResult(t *testing.T, result *SnmpPacket) {
	t.Helper()
	require.NotNil(t, result)
	require.Len(t, result.Variables, 1)
	require.Equal(t, v3HarnessSysDescrOID, result.Variables[0].Name)
	require.Equal(t, []byte(v3HarnessSysDescrValue), result.Variables[0].Value)
}

// TestV3HarnessColdStartGetAuthNoPriv pins the full cold-start flow:
// blank discovery probe, usmStatsUnknownEngineIDs REPORT, engine parameter
// adoption, authenticated GetRequest, GetResponse.
func TestV3HarnessColdStartGetAuthNoPriv(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{
		v3AgentUnknownEngineIDsReport(agent),
		v3AgentSysDescr(agent),
	}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3HarnessConnect(t, gs)
	v3UnknownEngineIDsReportFixture.seedIDs(gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)

	// The engine ID from the discovery REPORT is adopted into the session.
	// Boots/time seeding from this REPORT is deliberately not asserted: the
	// REPORT is unauthenticated, and tightened timeliness handling may stop
	// trusting it without changing the observable flow pinned here.
	require.Equal(t, v3HarnessEngineID, sp.AuthoritativeEngineID)

	require.Equal(t, 2, agent.requestCount())
	probe, get := agent.request(0), agent.request(1)

	// The discovery probe is a blank noAuthNoPriv GetRequest.
	require.Equal(t, Reportable|NoAuthNoPriv, probe.Packet.MsgFlags)
	require.Empty(t, v3ReqSecParams(t, probe).AuthoritativeEngineID)
	require.Empty(t, probe.Packet.Variables)

	// The real request is authenticated under the adopted engine ID.
	require.Equal(t, Reportable|AuthNoPriv, get.Packet.MsgFlags)
	getUsp := v3ReqSecParams(t, get)
	require.Equal(t, v3HarnessEngineID, getUsp.AuthoritativeEngineID)
	require.Equal(t, v3HarnessUser, getUsp.UserName)
}

// TestV3HarnessColdStartGetAuthPriv is the cold-start flow at authPriv: the
// agent decrypts the incoming request and the client accepts an encrypted
// response.
func TestV3HarnessColdStartGetAuthPriv(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthPriv())
	agent.steps = []v3TestAgentStep{
		v3AgentUnknownEngineIDsReport(agent),
		v3AgentSysDescr(agent),
	}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthPriv, agent.creds)
	v3HarnessConnect(t, gs)
	v3UnknownEngineIDsReportFixture.seedIDs(gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)

	require.Equal(t, v3HarnessEngineID, sp.AuthoritativeEngineID)
	require.Equal(t, 2, agent.requestCount())
	require.Equal(t, Reportable|AuthPriv, agent.request(1).Packet.MsgFlags)
	// The agent's parse step decrypted the scoped PDU back to the plain OID.
	require.Len(t, agent.request(1).Packet.Variables, 1)
	require.Equal(t, v3HarnessSysDescrOID, agent.request(1).Packet.Variables[0].Name)
}

// TestV3HarnessNotInTimeWindowResend pins the RFC-conforming
// recovery: a session with stale boots/time receives an authenticated
// notInTimeWindows REPORT and retransmits once with the reported values.
func TestV3HarnessNotInTimeWindowResend(t *testing.T) {
	const staleBoots, staleTime uint32 = 1, 100

	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{
		v3AgentNotInTimeWindowsReport(agent),
		v3AgentSysDescr(agent),
	}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	// Pre-seed an established session with stale engine time.
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = staleBoots
	sp.AuthoritativeEngineTime = staleTime
	var retries, finished int
	gs.OnRetry = func(*GoSNMP) { retries++ }
	gs.OnFinish = func(*GoSNMP) { finished++ }
	v3HarnessConnect(t, gs)
	v3NotInTimeWindowsReportFixture.seedIDs(gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)

	require.Equal(t, 2, agent.requestCount())
	first, second := agent.request(0), agent.request(1)

	// First attempt carries the stale tuple; the corrected send carries the
	// REPORT's boots/time and fresh identifiers.
	require.Equal(t, staleBoots, v3ReqSecParams(t, first).AuthoritativeEngineBoots)
	requireEngineTimeNear(t, staleTime, v3ReqSecParams(t, first).AuthoritativeEngineTime)
	require.Equal(t, v3HarnessBoots, v3ReqSecParams(t, second).AuthoritativeEngineBoots)
	requireEngineTimeNear(t, v3HarnessTime, v3ReqSecParams(t, second).AuthoritativeEngineTime)
	require.NotEqual(t, first.Packet.MsgID, second.Packet.MsgID)
	require.NotEqual(t, first.Packet.RequestID, second.Packet.RequestID)

	// Session state now holds the reported tuple (the REPORT was
	// authenticated with greater boots, so this stays valid under high-water
	// timeliness rules).
	require.Equal(t, v3HarnessBoots, sp.AuthoritativeEngineBoots)
	requireEngineTimeNear(t, v3HarnessTime, sp.AuthoritativeEngineTime)

	// The retry budget is untouched; each of the two sendOneRequest calls
	// (original and corrected) invokes OnFinish once.
	require.Equal(t, 0, retries)
	require.Equal(t, 2, finished)
}

// TestV3HarnessImmediateSuccessAccounting pins callback counts for a plain
// one-exchange Get on an established session.
func TestV3HarnessImmediateSuccessAccounting(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentSysDescr(agent)}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = v3HarnessBoots
	sp.AuthoritativeEngineTime = v3HarnessTime
	var retries, finished int
	gs.OnRetry = func(*GoSNMP) { retries++ }
	gs.OnFinish = func(*GoSNMP) { finished++ }
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, 1, agent.requestCount())
	require.Equal(t, 0, retries)
	require.Equal(t, 1, finished)
}

// TestV3HarnessRejectsUnauthenticatedDiscoveryShapedResponse checks that an
// authNoPriv client does not accept a noAuthNoPriv response just because it
// has the empty user, engine ID and varbind list of an engine discovery
// message, and that such a response does not reset the session's engine state.
func TestV3HarnessRejectsUnauthenticatedDiscoveryShapedResponse(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{func(req *v3TestAgentRequest) [][]byte {
		forged := &SnmpPacket{
			Version:            Version3,
			MsgFlags:           NoAuthNoPriv,
			SecurityModel:      UserSecurityModel,
			SecurityParameters: &UsmSecurityParameters{Logger: agent.logger},
			PDUType:            GetResponse,
			MsgID:              req.Packet.MsgID,
			RequestID:          req.Packet.RequestID,
			Error:              GenErr,
			Logger:             agent.logger,
		}
		out, err := forged.MarshalMsg()
		if err != nil {
			agent.sendErr(fmt.Errorf("marshaling forged reply: %w", err))
			return nil
		}
		return [][]byte{out}
	}}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = v3HarnessBoots
	sp.AuthoritativeEngineTime = v3HarnessTime
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.Error(t, err)
	require.Nil(t, result)
	require.Equal(t, v3HarnessEngineID, sp.AuthoritativeEngineID)
	require.Equal(t, v3HarnessBoots, sp.AuthoritativeEngineBoots)
}

// forgeV3Reply builds an unauthenticated reply with request-id 0, which the
// client accepts for any request. The client still requires msgID to match,
// so a forger that cannot see the request has to guess it.
func forgeV3Reply(t *testing.T, logger Logger, engineID string, msgID uint32, pduType PDUType, vars []SnmpPDU) []byte {
	t.Helper()
	forged := &SnmpPacket{
		Version:            Version3,
		MsgFlags:           NoAuthNoPriv,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{AuthoritativeEngineID: engineID, Logger: logger},
		PDUType:            pduType,
		MsgID:              msgID,
		Variables:          vars,
		Logger:             logger,
	}
	out, err := forged.MarshalMsg()
	require.NoError(t, err)
	return out
}

// TestV3HarnessRejectsDiscoveryReportWithoutEngineID checks that a forged
// discovery REPORT with an empty engine ID fails discovery, rather than
// leaving the engine ID empty so that later responses are trusted on their
// own msgFlags.
func TestV3HarnessRejectsDiscoveryReportWithoutEngineID(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	// The forger sees the probe and echoes its msgID.
	agent.steps = []v3TestAgentStep{
		func(req *v3TestAgentRequest) [][]byte {
			return [][]byte{forgeV3Reply(t, agent.logger, "", req.Packet.MsgID, Report,
				[]SnmpPDU{{Name: usmStatsUnknownEngineIDs, Type: Counter32, Value: uint32(1)}})}
		},
		func(req *v3TestAgentRequest) [][]byte {
			return [][]byte{forgeV3Reply(t, agent.logger, "", req.Packet.MsgID, GetResponse,
				[]SnmpPDU{{Name: v3HarnessSysDescrOID, Type: OctetString, Value: "FORGED"}})}
		},
	}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.ErrorContains(t, err, "invalid authoritative engine ID")
	require.Empty(t, result.Variables)
	require.Empty(t, sp.AuthoritativeEngineID)
	requireRequestCount(t, agent, 1)
}

// TestV3HarnessDiscoveryIgnoresUnauthenticatedResponse checks that while the
// engine ID is unknown, an unauthenticated reply other than a REPORT is
// discarded, so a forged GetResponse cannot set the engine ID and the
// genuine discovery REPORT behind it is still used.
func TestV3HarnessDiscoveryIgnoresUnauthenticatedResponse(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	forged := forgeV3Reply(t, agent.logger, "\x80\x00\x00\x00\x04forged", 1, GetResponse,
		[]SnmpPDU{{Name: v3HarnessSysDescrOID, Type: OctetString, Value: "FORGED"}})
	report := v3AgentUnknownEngineIDsReport(agent)
	agent.steps = []v3TestAgentStep{
		func(req *v3TestAgentRequest) [][]byte { return append([][]byte{forged}, report(req)...) },
		v3AgentSysDescr(agent),
	}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3HarnessConnect(t, gs)
	v3UnknownEngineIDsReportFixture.seedIDs(gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, v3HarnessEngineID, sp.AuthoritativeEngineID)
}

// TestV3HarnessTimeoutAllAttemptsDropped pins retry accounting when
// every attempt is dropped: Retries+1 requests on the wire, each with fresh
// msgID and request-id, ending in a timeout error.
func TestV3HarnessTimeoutAllAttemptsDropped(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentDrop, v3AgentDrop, v3AgentDrop}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = v3HarnessBoots
	sp.AuthoritativeEngineTime = v3HarnessTime
	gs.Timeout = 150 * time.Millisecond
	gs.Retries = 2
	var retries int
	gs.OnRetry = func(*GoSNMP) { retries++ }
	v3HarnessConnect(t, gs)

	_, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "timeout"), "got error: %v", err)

	requireRequestCount(t, agent, 3)
	msgIDs := map[uint32]bool{}
	reqIDs := map[uint32]bool{}
	for i := range 3 {
		req := agent.request(i)
		msgIDs[req.Packet.MsgID] = true
		reqIDs[req.Packet.RequestID] = true
	}
	require.Len(t, msgIDs, 3, "each attempt must use a fresh msgID")
	require.Len(t, reqIDs, 3, "each attempt must use a fresh request-id")
	// OnRetry fires on every loop pass after the first send, including the
	// final pass that gives up: Retries+1 times in total.
	require.Equal(t, 3, retries)
}

// TestV3HarnessRetriesZeroTimeout pins single-attempt behavior: one request
// on the wire and a timeout error.
func TestV3HarnessRetriesZeroTimeout(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentDrop}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = v3HarnessBoots
	sp.AuthoritativeEngineTime = v3HarnessTime
	gs.Timeout = 150 * time.Millisecond
	v3HarnessConnect(t, gs)

	_, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "timeout"), "got error: %v", err)
	requireRequestCount(t, agent, 1)
}

// TestV3HarnessDropFirstAttemptThenRespond pins recovery within the
// retry budget: the first attempt is dropped, the retry is answered.
func TestV3HarnessDropFirstAttemptThenRespond(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentDrop, v3AgentSysDescr(agent)}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = v3HarnessBoots
	sp.AuthoritativeEngineTime = v3HarnessTime
	gs.Timeout = 150 * time.Millisecond
	gs.Retries = 1
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, 2, agent.requestCount())
	require.NotEqual(t, agent.request(0).Packet.MsgID, agent.request(1).Packet.MsgID)
	require.NotEqual(t, agent.request(0).Packet.RequestID, agent.request(1).Packet.RequestID)
}

// The tests below pin how a received message is matched to its request: by
// msgID (RFC 3412 7.2 step 10) and, for an ordinary response, by the
// request-id sent on that same attempt (RFC 3413 3.1). A REPORT is matched by
// msgID alone, as it may legally carry request-id 0. Anything else is ignored
// while the client keeps waiting within the same deadline.

// v3AgentStaleReportThenSysDescr answers with a usmStatsUnknownEngineIDs
// REPORT left over from an earlier exchange (the previous msgID and the given
// request-id), followed by the real GetResponse.
func v3AgentStaleReportThenSysDescr(a *v3TestAgent, staleRequestID uint32) v3TestAgentStep {
	return func(req *v3TestAgentRequest) [][]byte {
		staleMsgID := req.Packet.MsgID - 1
		stale := a.reply(req, v3TestAgentReply{
			pduType:   Report,
			vars:      []SnmpPDU{{Name: usmStatsUnknownEngineIDs, Type: Counter32, Value: uint32(32534)}},
			msgID:     &staleMsgID,
			requestID: &staleRequestID,
		})
		return append(stale, v3AgentSysDescr(a)(req)...)
	}
}

// v3WrongReply builds a GetResponse to req carrying the given msgID and
// request-id and a value the client must not return.
func v3WrongReply(a *v3TestAgent, req *v3TestAgentRequest, msgID, requestID uint32) [][]byte {
	return a.reply(req, v3TestAgentReply{
		pduType:   GetResponse,
		vars:      []SnmpPDU{{Name: v3HarnessSysDescrOID, Type: OctetString, Value: "wrong reply"}},
		msgID:     &msgID,
		requestID: &requestID,
	})
}

// testV3StaleReportDiscarded checks that a REPORT left over from an earlier
// exchange - such as the reply to a retransmitted discovery probe - is
// ignored without a resend and the real reply is returned.
func testV3StaleReportDiscarded(t *testing.T, staleRequestID func(req *v3TestAgentRequest) uint32) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{func(req *v3TestAgentRequest) [][]byte {
		return v3AgentStaleReportThenSysDescr(agent, staleRequestID(req))(req)
	}}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = v3HarnessBoots
	sp.AuthoritativeEngineTime = v3HarnessTime
	var retries, finished int
	gs.OnRetry = func(*GoSNMP) { retries++ }
	gs.OnFinish = func(*GoSNMP) { finished++ }
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, 1, agent.requestCount())
	require.Equal(t, 0, retries)
	require.Equal(t, 1, finished)
}

// TestV3HarnessStaleReportWithOldRequestIDDiscarded covers a stale REPORT echoing an
// earlier request's msgID and request-id.
func TestV3HarnessStaleReportWithOldRequestIDDiscarded(t *testing.T) {
	testV3StaleReportDiscarded(t, func(req *v3TestAgentRequest) uint32 { return req.Packet.RequestID - 1 })
}

// TestV3HarnessStaleReportWithZeroRequestIDDiscarded covers a stale REPORT with
// request-id 0.
func TestV3HarnessStaleReportWithZeroRequestIDDiscarded(t *testing.T) {
	testV3StaleReportDiscarded(t, func(*v3TestAgentRequest) uint32 { return 0 })
}

// TestV3HarnessReportWithZeroRequestIDHandled checks that a REPORT for the current
// request is still acted on when it carries request-id 0.
func TestV3HarnessReportWithZeroRequestIDHandled(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	zero := uint32(0)
	agent.steps = []v3TestAgentStep{func(req *v3TestAgentRequest) [][]byte {
		return agent.reply(req, v3TestAgentReply{
			pduType:   Report,
			vars:      []SnmpPDU{{Name: usmStatsUnknownUserNames, Type: Counter32, Value: uint32(1)}},
			requestID: &zero,
		})
	}}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = v3HarnessBoots
	sp.AuthoritativeEngineTime = v3HarnessTime
	v3HarnessConnect(t, gs)

	_, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.ErrorIs(t, err, ErrUnknownUsername)
	require.Equal(t, 1, agent.requestCount())
}

// TestV3HarnessResponseWithUnknownMsgIDDiscarded covers a GetResponse with the
// expected request-id but a msgID that was never sent.
func TestV3HarnessResponseWithUnknownMsgIDDiscarded(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{func(req *v3TestAgentRequest) [][]byte {
		wrong := v3WrongReply(agent, req, req.Packet.MsgID+1000, req.Packet.RequestID)
		return append(wrong, v3AgentSysDescr(agent)(req)...)
	}}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = v3HarnessBoots
	sp.AuthoritativeEngineTime = v3HarnessTime
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, 1, agent.requestCount())
}

// TestV3HarnessDelayedReplyToEarlierAttemptAccepted covers a reply that arrives after
// the client has retried, carrying the complete msgID and request-id pair of
// the first attempt.
func TestV3HarnessDelayedReplyToEarlierAttemptAccepted(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{
		v3AgentDrop,
		func(req *v3TestAgentRequest) [][]byte {
			first := agent.request(0).Packet
			return agent.reply(req, v3TestAgentReply{
				pduType:   GetResponse,
				vars:      []SnmpPDU{{Name: v3HarnessSysDescrOID, Type: OctetString, Value: v3HarnessSysDescrValue}},
				msgID:     &first.MsgID,
				requestID: &first.RequestID,
			})
		},
	}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = v3HarnessBoots
	sp.AuthoritativeEngineTime = v3HarnessTime
	gs.Timeout = 150 * time.Millisecond
	gs.Retries = 1
	var retries, finished int
	gs.OnRetry = func(*GoSNMP) { retries++ }
	gs.OnFinish = func(*GoSNMP) { finished++ }
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, 2, agent.requestCount())
	require.Equal(t, 1, retries)
	require.Equal(t, 1, finished)
}

// TestV3HarnessCrossedAttemptIdentifiersDiscarded covers replies whose msgID and
// request-id were each sent, but on different attempts. Neither combination
// was sent, so both are ignored in favour of the real reply.
func TestV3HarnessCrossedAttemptIdentifiersDiscarded(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{
		v3AgentDrop,
		func(req *v3TestAgentRequest) [][]byte {
			first, second := agent.request(0).Packet, req.Packet
			wrong := v3WrongReply(agent, req, first.MsgID, second.RequestID)
			wrong = append(wrong, v3WrongReply(agent, req, second.MsgID, first.RequestID)...)
			return append(wrong, v3AgentSysDescr(agent)(req)...)
		},
	}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = v3HarnessBoots
	sp.AuthoritativeEngineTime = v3HarnessTime
	gs.Timeout = 150 * time.Millisecond
	gs.Retries = 1
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, 2, agent.requestCount())
}

// TestV3HarnessResponseWithZeroRequestIDDiscarded covers a GetResponse carrying the
// request's msgID but request-id 0, when the request used another request-id.
func TestV3HarnessResponseWithZeroRequestIDDiscarded(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{func(req *v3TestAgentRequest) [][]byte {
		wrong := v3WrongReply(agent, req, req.Packet.MsgID, 0)
		return append(wrong, v3AgentSysDescr(agent)(req)...)
	}}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = v3HarnessBoots
	sp.AuthoritativeEngineTime = v3HarnessTime
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, 1, agent.requestCount())
	require.NotZero(t, agent.request(0).Packet.RequestID)
}

// TestV3HarnessResponseWithExactZeroRequestIDAccepted covers request-id 0 sent after
// the request-id counter wraps: a response echoing it must be accepted.
func TestV3HarnessResponseWithExactZeroRequestIDAccepted(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentSysDescr(agent)}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = v3HarnessBoots
	sp.AuthoritativeEngineTime = v3HarnessTime
	v3HarnessConnect(t, gs)
	gs.SetRequestID(0x7FFFFFFF) // the next request-id wraps to 0

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, 1, agent.requestCount())
	require.Zero(t, agent.request(0).Packet.RequestID)
}

// TestV3HarnessTCPGet runs the cold-start discovery and Get flow over TCP.
func TestV3HarnessTCPGet(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{
		v3AgentUnknownEngineIDsReport(agent),
		v3AgentSysDescr(agent),
	}
	port := agent.startTCP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	gs.Transport = "tcp"
	v3HarnessConnect(t, gs)
	v3UnknownEngineIDsReportFixture.seedIDs(gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, v3HarnessEngineID, sp.AuthoritativeEngineID)
	require.Equal(t, 2, agent.requestCount())
}

// TestV3HarnessTCPFraming exercises readBERMessage against fragmented and
// coalesced stream reads: two back-to-back messages delivered one byte per
// Read must each come back intact, and malformed framing must error.
func TestV3HarnessTCPFraming(t *testing.T) {
	short := []byte{0x30, 0x03, 0x01, 0x02, 0x03}
	long := append([]byte{0x30, 0x82, 0x01, 0x00}, bytes.Repeat([]byte{0xab}, 256)...)

	r := bufio.NewReader(iotest.OneByteReader(bytes.NewReader(append(bytes.Clone(short), long...))))
	msg, err := readBERMessage(r)
	require.NoError(t, err)
	require.Equal(t, short, msg)
	msg, err = readBERMessage(r)
	require.NoError(t, err)
	require.Equal(t, long, msg)
	_, err = readBERMessage(r)
	require.ErrorIs(t, err, io.EOF)

	for name, in := range map[string][]byte{
		"wrong tag":           {0x04, 0x01, 0x00},
		"indefinite length":   {0x30, 0x80, 0x01, 0x02},
		"oversize length":     {0x30, 0x83, 0xff, 0xff, 0xff},
		"truncated after tag": {0x30},
		"truncated length":    {0x30, 0x82, 0x01},
		"truncated payload":   {0x30, 0x05, 0x01, 0x02},
		"missing payload":     {0x30, 0x05},
	} {
		_, err = readBERMessage(bufio.NewReader(bytes.NewReader(in)))
		require.Error(t, err, name)
		// Truncation inside a message must not read as a clean close.
		require.NotErrorIs(t, err, io.EOF, name)
	}
}
