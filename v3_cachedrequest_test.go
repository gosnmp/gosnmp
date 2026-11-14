// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build all || marshal

package gosnmp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The tests below check that an ordinary response is only accepted when its
// contextEngineID, contextName and USM user name match the outstanding
// request (RFC 3412 section 7.2 step 12). A mismatched response is discarded,
// so the request ends in a timeout instead of returning the wrong data.

func v3CachedRequestSeedSession(sp *UsmSecurityParameters) {
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = v3HarnessBoots
	sp.AuthoritativeEngineTime = v3HarnessTime
}

// v3AgentSysDescrWith answers with a sysDescr GetResponse, letting the test
// change the fields under test.
func v3AgentSysDescrWith(a *v3TestAgent, r v3TestAgentReply) v3TestAgentStep {
	return func(req *v3TestAgentRequest) [][]byte {
		r.pduType = GetResponse
		r.vars = []SnmpPDU{{Name: v3HarnessSysDescrOID, Value: v3HarnessSysDescrValue, Type: OctetString}}
		return a.reply(req, r)
	}
}

func requireV3ResponseDiscarded(t *testing.T, agent *v3TestAgent, gs *GoSNMP) {
	t.Helper()
	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.Error(t, err)
	require.Nil(t, result)
	requireRequestCount(t, agent, 1)
}

// TestV3CachedRequestRejectsOtherContextEngineID checks that an authenticated
// GetResponse for a different contextEngineID is discarded.
func TestV3CachedRequestRejectsOtherContextEngineID(t *testing.T) {
	other := "\x80\x00\x1f\x88\x04othercontext"
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentSysDescrWith(agent, v3TestAgentReply{contextEngineID: &other})}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3CachedRequestSeedSession(sp)
	v3HarnessConnect(t, gs)

	requireV3ResponseDiscarded(t, agent, gs)
}

// TestV3CachedRequestRejectsOtherContextName checks that an authenticated
// GetResponse for a different contextName is discarded.
func TestV3CachedRequestRejectsOtherContextName(t *testing.T) {
	other := "other-context"
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentSysDescrWith(agent, v3TestAgentReply{contextName: &other})}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3CachedRequestSeedSession(sp)
	v3HarnessConnect(t, gs)

	requireV3ResponseDiscarded(t, agent, gs)
}

// TestV3CachedRequestRejectsOtherUserNameWithoutAuth checks that a
// noAuthNoPriv GetResponse for a different user is discarded. Authenticated
// sessions already reject this in isAuthentic; without authentication nothing
// else does.
func TestV3CachedRequestRejectsOtherUserNameWithoutAuth(t *testing.T) {
	other := "someoneElse"
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3TestAgentCreds{username: v3HarnessUser})
	agent.steps = []v3TestAgentStep{v3AgentSysDescrWith(agent, v3TestAgentReply{userName: &other})}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, NoAuthNoPriv, agent.creds)
	v3CachedRequestSeedSession(sp)
	v3HarnessConnect(t, gs)

	requireV3ResponseDiscarded(t, agent, gs)
}

// TestV3CachedRequestAcceptsMatchingContext checks that a response with the
// request's own non-default contextEngineID and contextName is accepted.
func TestV3CachedRequestAcceptsMatchingContext(t *testing.T) {
	contextEngineID := "\x80\x00\x1f\x88\x04proxiedctx"
	contextName := "vlan-42"
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentSysDescrWith(agent, v3TestAgentReply{
		contextEngineID: &contextEngineID,
		contextName:     &contextName,
	})}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3CachedRequestSeedSession(sp)
	gs.ContextEngineID = contextEngineID
	gs.ContextName = contextName
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Equal(t, contextEngineID, agent.request(0).Packet.ContextEngineID)
	require.Equal(t, contextName, agent.request(0).Packet.ContextName)
}

// TestV3CachedRequestAcceptsDefaultContextEngineID checks that when the
// request leaves contextEngineID empty, a response naming the authoritative
// engine, the default context (RFC 3411 section 3.3.2), is accepted.
func TestV3CachedRequestAcceptsDefaultContextEngineID(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentSysDescr(agent)}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3CachedRequestSeedSession(sp)
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	requireSysDescrResult(t, result)
	require.Empty(t, agent.request(0).Packet.ContextEngineID)
}
