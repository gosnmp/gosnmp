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
