// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build all || trap

package gosnmp

// Tests for SNMPv3 engine-ID discovery when the device responds with
// usmStatsUnknownUserNames instead of the standard usmStatsUnknownEngineIDs.
//
// Some devices (e.g. Dell EMC switches) behave this way: they respond to the
// discovery probe with a Report containing usmStatsUnknownUserNames
// (.1.3.6.1.6.3.15.1.1.3.0) but still include valid engine parameters
// (AuthoritativeEngineID, boots, time) in the USM security header of that
// same response. net-snmp extracts those parameters and proceeds; GoSNMP
// previously treated the response as a fatal error and aborted.
//
// These tests use the shared scripted SNMPv3 test agent to replicate the exact
// packet exchange observed in packet captures from an affected device.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// testDiscoveryEngineID is the AuthoritativeEngineID the mock agent advertises
// in all discovery tests in this file.
var testDiscoveryEngineID = string([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04})

const (
	testDiscoveryEngineBoots uint32 = 174
	testDiscoveryEngineTime  uint32 = 572518

	testDiscoverySysDescrOID   = ".1.3.6.1.2.1.1.1.0"
	testDiscoverySysDescrValue = "mock sysDescr"
)

// v3DiscoveryUnknownUserNamesReport returns the non-standard discovery REPORT
// used by affected devices. The authoritative engine parameters are valid,
// while the context engine ID remains explicitly empty as in the captured
// response shape.
func v3DiscoveryUnknownUserNamesReport(a *v3TestAgent) v3TestAgentStep {
	empty := ""
	return func(req *v3TestAgentRequest) [][]byte {
		return a.reply(req, v3TestAgentReply{
			pduType:         Report,
			contextEngineID: &empty,
			vars: []SnmpPDU{{
				Name:  usmStatsUnknownUserNames,
				Value: 1,
				Type:  Integer,
			}},
		})
	}
}

// v3DiscoveryUnknownUserNamesNoEngineIDReport returns the malformed variant
// whose authoritative and context engine IDs are both explicitly empty.
func v3DiscoveryUnknownUserNamesNoEngineIDReport(a *v3TestAgent) v3TestAgentStep {
	empty := ""
	return func(req *v3TestAgentRequest) [][]byte {
		return a.reply(req, v3TestAgentReply{
			pduType:               Report,
			authoritativeEngineID: &empty,
			contextEngineID:       &empty,
			vars: []SnmpPDU{{
				Name:  usmStatsUnknownUserNames,
				Value: 1,
				Type:  Integer,
			}},
		})
	}
}

// v3DiscoverySysDescr returns the response used after successful discovery.
func v3DiscoverySysDescr(a *v3TestAgent) v3TestAgentStep {
	return func(req *v3TestAgentRequest) [][]byte {
		return a.reply(req, v3TestAgentReply{
			pduType: GetResponse,
			vars: []SnmpPDU{{
				Name:  testDiscoverySysDescrOID,
				Value: testDiscoverySysDescrValue,
				Type:  OctetString,
			}},
		})
	}
}

// newV3NoAuthClientForDiscoveryTest returns a GoSNMP client configured for
// NoAuthNoPriv SNMPv3 with an empty AuthoritativeEngineID so that
// discoveryRequired() triggers engine-ID discovery on the first request.
func newV3NoAuthClientForDiscoveryTest(port uint16) *GoSNMP {
	gs := newTestGoSNMPv3(NoAuthNoPriv, &UsmSecurityParameters{
		UserName: "testUser",
		// AuthoritativeEngineID intentionally empty to trigger discovery.
	})
	gs.Target = "127.0.0.1"
	gs.Port = port
	gs.Retries = 0
	return gs
}

// setupDiscoveryTest creates a noAuth test agent with the supplied script and
// a connected SNMPv3 client. Cleanup is registered automatically; callers must
// not close the agent or connection themselves.
func setupDiscoveryTest(t *testing.T, buildSteps func(*v3TestAgent) []v3TestAgentStep) *GoSNMP {
	t.Helper()
	agent := newV3TestAgent(t, testDiscoveryEngineID, testDiscoveryEngineBoots, testDiscoveryEngineTime,
		v3TestAgentCreds{})
	agent.steps = buildSteps(agent)
	port := agent.startUDP(t)

	ts := newV3NoAuthClientForDiscoveryTest(port)
	require.NoError(t, ts.Connect())
	t.Cleanup(func() { ts.Conn.Close() })

	return ts
}

// TestV3DiscoveryUnknownUserNames verifies that negotiateInitialSecurityParameters
// succeeds — and correctly stores the engine ID, boots, and time — when the
// device responds to the discovery probe with usmStatsUnknownUserNames instead
// of the standard usmStatsUnknownEngineIDs.
//
// Before the fix this test fails: negotiateInitialSecurityParameters propagates
// ErrUnknownUsername and never stores the engine parameters.
func TestV3DiscoveryUnknownUserNames(t *testing.T) {
	ts := setupDiscoveryTest(t, func(agent *v3TestAgent) []v3TestAgentStep {
		return []v3TestAgentStep{v3DiscoveryUnknownUserNamesReport(agent)}
	})

	// mkSnmpPacket produces the same packet shape that Get() passes to
	// negotiateInitialSecurityParameters internally.
	pkt := ts.mkSnmpPacket(GetRequest, nil, 0, 0)
	err := ts.negotiateInitialSecurityParameters(pkt)
	require.NoError(t, err, "negotiateInitialSecurityParameters must succeed even when the device "+
		"responds with usmStatsUnknownUserNames during engine-ID discovery")

	storedParams := ts.SecurityParameters.(*UsmSecurityParameters)
	require.Equal(t, testDiscoveryEngineID, storedParams.AuthoritativeEngineID,
		"engine ID must be extracted from the usmStatsUnknownUserNames Report")
	require.Equal(t, testDiscoveryEngineBoots, storedParams.AuthoritativeEngineBoots,
		"engine boots must be extracted from the usmStatsUnknownUserNames Report")
	require.Equal(t, testDiscoveryEngineTime, storedParams.AuthoritativeEngineTime,
		"engine time must be extracted from the usmStatsUnknownUserNames Report")
}

// TestV3GetWithDiscoveryUnknownUserNames is an end-to-end test that exercises
// the complete Get() flow against a mock agent that returns
// usmStatsUnknownUserNames during discovery. It mirrors the packet exchange
// observed in the real-world packet captures:
//
//  1. Client sends discovery probe (engineID="", userName="").
//  2. Agent responds: Report with usmStatsUnknownUserNames + valid engine params.
//  3. Client sends authenticated GetRequest.
//  4. Agent responds: GetResponse with OID data.
//
// Before the fix, step 2 causes Get() to return ErrUnknownUsername. After the
// fix, all four steps complete successfully.
func TestV3GetWithDiscoveryUnknownUserNames(t *testing.T) {
	ts := setupDiscoveryTest(t, func(agent *v3TestAgent) []v3TestAgentStep {
		return []v3TestAgentStep{
			v3DiscoveryUnknownUserNamesReport(agent),
			v3DiscoverySysDescr(agent),
		}
	})

	result, err := ts.Get([]string{testDiscoverySysDescrOID})
	require.NoError(t, err, "Get() must succeed when the device responds with "+
		"usmStatsUnknownUserNames during engine-ID discovery")
	require.NotNil(t, result)
	require.Len(t, result.Variables, 1)
	require.Equal(t, testDiscoverySysDescrOID, result.Variables[0].Name)
	require.Equal(t, []byte(testDiscoverySysDescrValue), result.Variables[0].Value)
}

// TestV3DiscoveryUnknownUserNamesNoEngineID verifies that ErrUnknownUsername is
// propagated when the device responds to the discovery probe with
// usmStatsUnknownUserNames but provides an empty AuthoritativeEngineID in the
// USM security parameters. Without a valid engine ID there is nothing useful to
// extract, so the error must not be suppressed.
func TestV3DiscoveryUnknownUserNamesNoEngineID(t *testing.T) {
	ts := setupDiscoveryTest(t, func(agent *v3TestAgent) []v3TestAgentStep {
		return []v3TestAgentStep{v3DiscoveryUnknownUserNamesNoEngineIDReport(agent)}
	})

	pkt := ts.mkSnmpPacket(GetRequest, nil, 0, 0)
	err := ts.negotiateInitialSecurityParameters(pkt)
	require.ErrorIs(t, err, ErrUnknownUsername,
		"ErrUnknownUsername must not be suppressed when the Report carries an empty engine ID")
}

// TestV3GetRealUnknownUserNameStillFails verifies that ErrUnknownUsername is
// still returned for actual (post-discovery) requests, confirming the fix does
// not suppress genuine authentication failures.
//
// The mock is configured to return usmStatsUnknownUserNames for all requests.
// Discovery succeeds (the fix applies), but the subsequent Get fails because
// the agent continues to reject the user on the actual request.
func TestV3GetRealUnknownUserNameStillFails(t *testing.T) {
	ts := setupDiscoveryTest(t, func(agent *v3TestAgent) []v3TestAgentStep {
		return []v3TestAgentStep{
			v3DiscoveryUnknownUserNamesReport(agent),
			v3DiscoveryUnknownUserNamesReport(agent),
		}
	})

	_, err := ts.Get([]string{testDiscoverySysDescrOID})
	require.ErrorIs(t, err, ErrUnknownUsername,
		"ErrUnknownUsername from a post-discovery request must not be suppressed")
}
