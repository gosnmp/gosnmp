// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build all || marshal

package gosnmp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The tests below check that once a session has an authoritative engine ID,
// responses cannot replace it: only initial discovery adopts an engine ID.
// Each agent answers as a different engine than the one the session has
// established, as after a reboot that generates a new engine ID or from
// another engine sharing the same credentials.

var v3OtherEngineID = string([]byte{0x80, 0x00, 0x1f, 0x88, 0x04, 'r', 'e', 'b', 'o', 'o', 't', 'e', 'd'})

func v3EngineIDSeedSession(sp *UsmSecurityParameters) {
	sp.AuthoritativeEngineID = v3HarnessEngineID
	sp.AuthoritativeEngineBoots = v3HarnessBoots
	sp.AuthoritativeEngineTime = v3HarnessTime
}

// TestV3EngineIDNoAuthResponseKeepsIdentity checks that a noAuthNoPriv
// response from another engine is discarded rather than returned, and leaves
// the session's engine ID alone.
func TestV3EngineIDNoAuthResponseKeepsIdentity(t *testing.T) {
	agent := newV3TestAgent(t, v3OtherEngineID, v3HarnessBoots, v3HarnessTime, v3TestAgentCreds{username: v3HarnessUser})
	agent.steps = []v3TestAgentStep{v3AgentSysDescr(agent)}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, NoAuthNoPriv, agent.creds)
	v3EngineIDSeedSession(sp)
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.Error(t, err)
	require.Nil(t, result)
	require.Equal(t, v3HarnessEngineID, sp.AuthoritativeEngineID)
	requireRequestCount(t, agent, 1)
}

// TestV3EngineIDSignedResponseKeepsIdentity checks that a response signed
// with the user's key localized to another engine ID does not replace the
// established identity. Receive-side parsing relocalizes the copied keys to
// the response's engine ID, so the HMAC itself verifies.
func TestV3EngineIDSignedResponseKeepsIdentity(t *testing.T) {
	agent := newV3TestAgent(t, v3OtherEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentSysDescr(agent)}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3EngineIDSeedSession(sp)
	v3HarnessConnect(t, gs)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.Error(t, err)
	require.Nil(t, result)
	require.Equal(t, v3HarnessEngineID, sp.AuthoritativeEngineID)
	requireRequestCount(t, agent, 1)
}

// TestV3EngineIDChangedReportIsAnError checks that an authenticated
// usmStatsUnknownEngineIDs Report naming another engine comes back as
// ErrUnknownEngineID, without adopting that engine ID or resending to it,
// so the caller can decide whether to rediscover.
func TestV3EngineIDChangedReportIsAnError(t *testing.T) {
	agent := newV3TestAgent(t, v3OtherEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{
		func(req *v3TestAgentRequest) [][]byte {
			return agent.reply(req, v3TestAgentReply{
				pduType: Report,
				vars:    []SnmpPDU{{Name: usmStatsUnknownEngineIDs, Type: Counter32, Value: uint32(1)}},
			})
		},
		// Only reached if the client adopts the new engine ID and resends.
		v3AgentSysDescr(agent),
	}
	port := agent.startUDP(t)

	gs, sp := newV3HarnessClient(port, AuthNoPriv, agent.creds)
	v3EngineIDSeedSession(sp)
	v3HarnessConnect(t, gs)

	_, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.ErrorIs(t, err, ErrUnknownEngineID)
	require.Equal(t, v3HarnessEngineID, sp.AuthoritativeEngineID)
	requireRequestCount(t, agent, 1)
}
