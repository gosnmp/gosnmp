// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build all || marshal

package gosnmp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

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

// TestV3StaleReportWithOldRequestIDDiscarded covers a stale REPORT echoing an
// earlier request's msgID and request-id.
func TestV3StaleReportWithOldRequestIDDiscarded(t *testing.T) {
	testV3StaleReportDiscarded(t, func(req *v3TestAgentRequest) uint32 { return req.Packet.RequestID - 1 })
}

// TestV3StaleReportWithZeroRequestIDDiscarded covers a stale REPORT with
// request-id 0.
func TestV3StaleReportWithZeroRequestIDDiscarded(t *testing.T) {
	testV3StaleReportDiscarded(t, func(*v3TestAgentRequest) uint32 { return 0 })
}

// TestV3ReportWithZeroRequestIDHandled checks that a REPORT for the current
// request is still acted on when it carries request-id 0.
func TestV3ReportWithZeroRequestIDHandled(t *testing.T) {
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

// TestV3ResponseWithUnknownMsgIDDiscarded covers a GetResponse with the
// expected request-id but a msgID that was never sent.
func TestV3ResponseWithUnknownMsgIDDiscarded(t *testing.T) {
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

// TestV3DelayedReplyToEarlierAttemptAccepted covers a reply that arrives after
// the client has retried, carrying the complete msgID and request-id pair of
// the first attempt.
func TestV3DelayedReplyToEarlierAttemptAccepted(t *testing.T) {
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

// TestV3CrossedAttemptIdentifiersDiscarded covers replies whose msgID and
// request-id were each sent, but on different attempts. Neither combination
// was sent, so both are ignored in favour of the real reply.
func TestV3CrossedAttemptIdentifiersDiscarded(t *testing.T) {
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

// TestV3ResponseWithZeroRequestIDDiscarded covers a GetResponse carrying the
// request's msgID but request-id 0, when the request used another request-id.
func TestV3ResponseWithZeroRequestIDDiscarded(t *testing.T) {
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

// TestV3ResponseWithExactZeroRequestIDAccepted covers request-id 0 sent after
// the request-id counter wraps: a response echoing it must be accepted.
func TestV3ResponseWithExactZeroRequestIDAccepted(t *testing.T) {
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
