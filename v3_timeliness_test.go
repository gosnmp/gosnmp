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

// The tests below cover the timeliness rules of a non-authoritative engine
// (RFC 3414 section 2.3 and section 3.2 step 7b): outgoing requests carry an
// engine time that advances with local time, and authenticated messages
// outside the time window are discarded without changing the session.

// sentEngineTime returns the engine time the agent received in its i-th
// request.
func sentEngineTime(t *testing.T, agent *v3TestAgent, i int) uint32 {
	t.Helper()
	usp, ok := agent.request(i).Packet.SecurityParameters.(*UsmSecurityParameters)
	require.True(t, ok)
	return usp.AuthoritativeEngineTime
}

// v3AgentSysDescrAt answers like v3AgentSysDescr, with the given boots and
// engine time in the message's security parameters.
func v3AgentSysDescrAt(a *v3TestAgent, boots, engineTime uint32) v3TestAgentStep {
	return func(req *v3TestAgentRequest) [][]byte {
		return a.reply(req, v3TestAgentReply{
			pduType:    GetResponse,
			boots:      &boots,
			engineTime: &engineTime,
			vars: []SnmpPDU{{
				Name:  v3HarnessSysDescrOID,
				Value: v3HarnessSysDescrValue,
				Type:  OctetString,
			}},
		})
	}
}

func newV3TimelinessClient(t *testing.T, agent *v3TestAgent) (*GoSNMP, *UsmSecurityParameters) {
	t.Helper()
	gs, sp := newV3HarnessClient(agent.startUDP(t), AuthNoPriv, agent.creds)
	v3EngineIDSeedSession(sp)
	v3HarnessConnect(t, gs)
	return gs, sp
}

// TestV3TimelinessRequestsAdvanceEngineTime checks that requests made some
// time apart carry an engine time that has advanced with local time, and that
// a response repeating an engine time already received does not reset the
// estimate.
func TestV3TimelinessRequestsAdvanceEngineTime(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentSysDescr(agent), v3AgentSysDescr(agent), v3AgentSysDescr(agent)}
	gs, _ := newV3TimelinessClient(t, agent)

	for i := range 3 {
		if i > 0 {
			time.Sleep(1100 * time.Millisecond)
		}
		_, err := gs.Get([]string{v3HarnessSysDescrOID})
		require.NoError(t, err)
	}

	second := sentEngineTime(t, agent, 1)
	third := sentEngineTime(t, agent, 2)
	require.GreaterOrEqual(t, second, v3HarnessTime+1)
	// The second response repeated v3HarnessTime; the estimate keeps
	// advancing from the first synchronisation instead of restarting.
	require.GreaterOrEqual(t, third, v3HarnessTime+2)
}

// TestV3TimelinessDiscoveredEngineTimeAdvances checks that the engine time
// learned through discovery advances too, on a session without
// authentication.
func TestV3TimelinessDiscoveredEngineTimeAdvances(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3TestAgentCreds{username: v3HarnessUser})
	agent.steps = []v3TestAgentStep{
		func(req *v3TestAgentRequest) [][]byte {
			return agent.reply(req, v3TestAgentReply{
				pduType: Report,
				vars:    []SnmpPDU{{Name: usmStatsUnknownEngineIDs, Type: Counter32, Value: uint32(1)}},
			})
		},
		v3AgentSysDescr(agent),
		v3AgentSysDescr(agent),
	}
	// No engine ID, so the first request starts with engine discovery.
	gs, _ := newV3HarnessClient(agent.startUDP(t), NoAuthNoPriv, agent.creds)
	v3HarnessConnect(t, gs)

	_, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	time.Sleep(1100 * time.Millisecond)
	_, err = gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)

	sent := sentEngineTime(t, agent, 2)
	require.GreaterOrEqual(t, sent, v3HarnessTime+1)
}

// TestV3TimelinessRollbackIsDiscarded reproduces #647: an authenticated
// response whose engine time is far behind the one the session holds is
// discarded instead of being returned and stored.
func TestV3TimelinessRollbackIsDiscarded(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{
		v3AgentSysDescr(agent),
		v3AgentSysDescrAt(agent, v3HarnessBoots, 1),
	}
	gs, sp := newV3TimelinessClient(t, agent)

	_, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.Error(t, err)
	require.Nil(t, result)
	require.Equal(t, v3HarnessBoots, sp.AuthoritativeEngineBoots)
	require.Equal(t, v3HarnessTime, sp.AuthoritativeEngineTime)
}

// TestV3TimelinessStaleResponseLetsTheGenuineOneThrough checks that a stale
// copy arriving before the genuine response is skipped, so the request still
// succeeds with the genuine response and the session keeps its time.
func TestV3TimelinessStaleResponseLetsTheGenuineOneThrough(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	stale := v3AgentSysDescrAt(agent, v3HarnessBoots, 1)
	genuine := v3AgentSysDescr(agent)
	agent.steps = []v3TestAgentStep{func(req *v3TestAgentRequest) [][]byte {
		return append(stale(req), genuine(req)...)
	}}
	gs, sp := newV3TimelinessClient(t, agent)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	require.Equal(t, []byte(v3HarnessSysDescrValue), result.Variables[0].Value)
	require.Equal(t, v3HarnessTime, sp.AuthoritativeEngineTime)
}

// TestV3TimelinessLowerBootsIsDiscarded checks that an authenticated response
// from an earlier boot of the engine is outside the time window.
func TestV3TimelinessLowerBootsIsDiscarded(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentSysDescrAt(agent, v3HarnessBoots-1, v3HarnessTime+600)}
	gs, sp := newV3TimelinessClient(t, agent)

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.Error(t, err)
	require.Nil(t, result)
	require.Equal(t, v3HarnessBoots, sp.AuthoritativeEngineBoots)
	require.Equal(t, v3HarnessTime, sp.AuthoritativeEngineTime)
}

// TestV3TimelinessMaximumBootsIsDiscarded checks that once the engine's boots
// has reached its maximum, every authenticated message is outside the time
// window (RFC 3414 section 3.2 step 7b).
func TestV3TimelinessMaximumBootsIsDiscarded(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, maxEngineBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentSysDescr(agent)}
	gs, sp := newV3TimelinessClient(t, agent)
	sp.AuthoritativeEngineBoots = maxEngineBoots

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.Error(t, err)
	require.Nil(t, result)
}

// TestV3TimelinessRebootIsFollowed checks that an authenticated response with
// a higher boots, as after the engine restarts, is accepted and its boots and
// time are adopted even though the time is lower.
func TestV3TimelinessRebootIsFollowed(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{v3AgentSysDescrAt(agent, v3HarnessBoots+1, 5)}
	gs, sp := newV3TimelinessClient(t, agent)

	_, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	require.Equal(t, v3HarnessBoots+1, sp.AuthoritativeEngineBoots)
	require.Equal(t, uint32(5), sp.AuthoritativeEngineTime)
}

// TestV3TimelinessNotInTimeWindowRecovers checks that an authenticated
// usmStatsNotInTimeWindows Report still resynchronises the session and the
// request is resent with the engine's time.
func TestV3TimelinessNotInTimeWindowRecovers(t *testing.T) {
	agent := newV3TestAgent(t, v3HarnessEngineID, v3HarnessBoots, v3HarnessTime, v3HarnessCredsAuthNoPriv())
	agent.steps = []v3TestAgentStep{
		func(req *v3TestAgentRequest) [][]byte {
			return agent.reply(req, v3TestAgentReply{
				pduType: Report,
				vars:    []SnmpPDU{{Name: usmStatsNotInTimeWindows, Type: Counter32, Value: uint32(1)}},
			})
		},
		v3AgentSysDescr(agent),
	}
	gs, sp := newV3TimelinessClient(t, agent)
	// A stale time, as if the session had been idle across a long gap.
	sp.AuthoritativeEngineTime = 100

	result, err := gs.Get([]string{v3HarnessSysDescrOID})
	require.NoError(t, err)
	require.Equal(t, []byte(v3HarnessSysDescrValue), result.Variables[0].Value)
	requireRequestCount(t, agent, 2)
	resent := sentEngineTime(t, agent, 1)
	require.GreaterOrEqual(t, resent, v3HarnessTime)
	require.Equal(t, v3HarnessTime, sp.AuthoritativeEngineTime)
}
