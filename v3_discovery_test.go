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
// These tests use a minimal mock UDP agent that replicates the exact packet
// exchange observed in packet captures from an affected device.

import (
	"fmt"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// testDiscoveryEngineID is the AuthoritativeEngineID the mock agent advertises
// in all discovery tests in this file.
var testDiscoveryEngineID = string([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04})

const (
	testDiscoveryEngineBoots uint32 = 174
	testDiscoveryEngineTime  uint32 = 572518
)

// mockAgentUnknownUserNames is a minimal UDP SNMP agent that responds to
// SNMPv3 discovery probes with usmStatsUnknownUserNames rather than the
// standard usmStatsUnknownEngineIDs. Subsequent authenticated requests
// receive a minimal GetResponse so the full Get() call can succeed.
//
// Set failAuthRequests to true before calling serve() to make the mock also
// return usmStatsUnknownUserNames for post-discovery authenticated requests,
// simulating an agent that does not recognise the user credentials.
type mockAgentUnknownUserNames struct {
	conn               *net.UDPConn
	engineID           string
	boots              uint32
	engineTime         uint32
	logger             Logger
	done               chan struct{}
	errs               chan error
	failAuthRequests   bool
	omitEngineIDInReport bool // send usmStatsUnknownUserNames with empty AuthoritativeEngineID
}

func newMockAgentUnknownUserNames(t *testing.T, engineID string, boots, engineTime uint32) *mockAgentUnknownUserNames {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	return &mockAgentUnknownUserNames{
		conn:       conn,
		engineID:   engineID,
		boots:      boots,
		engineTime: engineTime,
		logger:     NewLogger(log.New(io.Discard, "", 0)),
		done:       make(chan struct{}),
		errs:       make(chan error, 16),
	}
}

func (m *mockAgentUnknownUserNames) port() uint16 {
	return uint16(m.conn.LocalAddr().(*net.UDPAddr).Port) //nolint:gosec
}

// closeAndCheck stops the mock server and fails the test if any internal
// error occurred during packet processing (e.g. parse or marshal failure).
// It must be called after the goroutine started by serve() has been launched.
func (m *mockAgentUnknownUserNames) closeAndCheck(t *testing.T) {
	t.Helper()
	m.conn.Close()
	<-m.done
	for {
		select {
		case err := <-m.errs:
			t.Errorf("mock agent internal error: %v", err)
		default:
			return
		}
	}
}

func (m *mockAgentUnknownUserNames) sendErr(err error) {
	select {
	case m.errs <- err:
	default:
	}
}

// serve processes packets until the connection is closed. It detects discovery
// probes by the empty AuthoritativeEngineID in the USM security parameters and
// responds with usmStatsUnknownUserNames. All other packets are treated as
// authenticated requests and receive a GetResponse, unless failAuthRequests is
// set in which case they also receive usmStatsUnknownUserNames.
func (m *mockAgentUnknownUserNames) serve() {
	defer close(m.done)

	// A GoSNMP instance is used solely as a parser for incoming packets.
	parser := &GoSNMP{Version: Version3, Logger: m.logger}

	buf := make([]byte, rxBufSize)
	for {
		n, addr, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		req := &SnmpPacket{
			Logger:             m.logger,
			SecurityParameters: &UsmSecurityParameters{Logger: m.logger},
		}

		cursor, err := parser.unmarshalHeader(buf[:n], req)
		if err != nil {
			m.sendErr(fmt.Errorf("unmarshalHeader: %w", err))
			continue
		}

		// decryptPacket advances the cursor past the ScopedPDU wrapper and
		// context fields, leaving it at the PDU type byte.
		pkt, cursor, err := parser.decryptPacket(buf[:n], cursor, req)
		if err != nil {
			m.sendErr(fmt.Errorf("decryptPacket: %w", err))
			continue
		}

		if err = parser.unmarshalPayload(pkt, cursor, req); err != nil {
			m.sendErr(fmt.Errorf("unmarshalPayload: %w", err))
			continue
		}

		usp := req.SecurityParameters.(*UsmSecurityParameters)

		var responseBytes []byte
		if usp.AuthoritativeEngineID == "" || m.failAuthRequests {
			// Discovery probe (empty engine ID) or an agent configured to
			// reject all users: respond with usmStatsUnknownUserNames and
			// include valid engine parameters in the USM security header.
			responseBytes, err = m.marshalUnknownUserNamesReport(req)
		} else {
			responseBytes, err = m.marshalGetResponse(req)
		}
		if err != nil {
			m.sendErr(fmt.Errorf("marshal response: %w", err))
			continue
		}
		if _, err = m.conn.WriteToUDP(responseBytes, addr); err != nil {
			m.sendErr(fmt.Errorf("WriteToUDP: %w", err))
		}
	}
}

func (m *mockAgentUnknownUserNames) secParams() *UsmSecurityParameters {
	return &UsmSecurityParameters{
		AuthoritativeEngineID:    m.engineID,
		AuthoritativeEngineBoots: m.boots,
		AuthoritativeEngineTime:  m.engineTime,
		Logger:                   m.logger,
	}
}

// marshalUnknownUserNamesReport builds a Report PDU that carries
// usmStatsUnknownUserNames but contains valid engine parameters — the
// non-standard response that triggers the bug. If omitEngineIDInReport is set,
// the AuthoritativeEngineID in the security parameters is left empty to simulate
// a malformed device response.
func (m *mockAgentUnknownUserNames) marshalUnknownUserNamesReport(req *SnmpPacket) ([]byte, error) {
	secParams := m.secParams()
	if m.omitEngineIDInReport {
		secParams.AuthoritativeEngineID = ""
	}
	pkt := &SnmpPacket{
		Version:            Version3,
		MsgFlags:           NoAuthNoPriv,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: secParams,
		PDUType:            Report,
		MsgID:              req.MsgID,
		RequestID:          req.RequestID,
		Logger:             m.logger,
		Variables: []SnmpPDU{{
			Name:  usmStatsUnknownUserNames,
			Value: 1,
			Type:  Integer,
		}},
	}
	return pkt.MarshalMsg()
}

// marshalGetResponse builds a GetResponse that echoes the client's MsgID and
// RequestID and returns a single OID value.
func (m *mockAgentUnknownUserNames) marshalGetResponse(req *SnmpPacket) ([]byte, error) {
	pkt := &SnmpPacket{
		Version:            Version3,
		MsgFlags:           NoAuthNoPriv,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: m.secParams(),
		PDUType:            GetResponse,
		MsgID:              req.MsgID,
		RequestID:          req.RequestID,
		ContextEngineID:    m.engineID,
		Logger:             m.logger,
		Variables: []SnmpPDU{{
			Name:  ".1.3.6.1.2.1.1.1.0",
			Value: "mock sysDescr",
			Type:  OctetString,
		}},
	}
	return pkt.MarshalMsg()
}

// newV3NoAuthClientForDiscoveryTest returns a GoSNMP client configured for
// NoAuthNoPriv SNMPv3 with an empty AuthoritativeEngineID so that
// discoveryRequired() triggers engine-ID discovery on the first request.
func newV3NoAuthClientForDiscoveryTest(port uint16) *GoSNMP {
	return &GoSNMP{
		Target:        "127.0.0.1",
		Port:          port,
		Version:       Version3,
		Timeout:       2 * time.Second,
		Retries:       0,
		MaxOids:       MaxOids,
		Logger:        NewLogger(log.New(io.Discard, "", 0)),
		SecurityModel: UserSecurityModel,
		MsgFlags:      NoAuthNoPriv,
		SecurityParameters: &UsmSecurityParameters{
			UserName: "testUser",
			// AuthoritativeEngineID intentionally empty to trigger discovery.
		},
	}
}

// setupDiscoveryTest creates a mock agent and a connected SNMPv3 client for
// the usmStatsUnknownUserNames discovery tests. Cleanup is registered
// automatically via t.Cleanup; callers must not close the agent or connection
// themselves.
func setupDiscoveryTest(t *testing.T) (*mockAgentUnknownUserNames, *GoSNMP) {
	t.Helper()
	agent := newMockAgentUnknownUserNames(t, testDiscoveryEngineID, testDiscoveryEngineBoots, testDiscoveryEngineTime)
	go agent.serve()
	t.Cleanup(func() { agent.closeAndCheck(t) })

	ts := newV3NoAuthClientForDiscoveryTest(agent.port())
	require.NoError(t, ts.Connect())
	t.Cleanup(func() { ts.Conn.Close() })

	return agent, ts
}

// TestV3DiscoveryUnknownUserNames verifies that negotiateInitialSecurityParameters
// succeeds — and correctly stores the engine ID, boots, and time — when the
// device responds to the discovery probe with usmStatsUnknownUserNames instead
// of the standard usmStatsUnknownEngineIDs.
//
// Before the fix this test fails: negotiateInitialSecurityParameters propagates
// ErrUnknownUsername and never stores the engine parameters.
func TestV3DiscoveryUnknownUserNames(t *testing.T) {
	_, ts := setupDiscoveryTest(t)

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
	_, ts := setupDiscoveryTest(t)

	result, err := ts.Get([]string{".1.3.6.1.2.1.1.1.0"})
	require.NoError(t, err, "Get() must succeed when the device responds with "+
		"usmStatsUnknownUserNames during engine-ID discovery")
	require.NotNil(t, result)
	require.Len(t, result.Variables, 1)
	require.Equal(t, ".1.3.6.1.2.1.1.1.0", result.Variables[0].Name)
	require.Equal(t, []byte("mock sysDescr"), result.Variables[0].Value)
}

// TestV3DiscoveryUnknownUserNamesNoEngineID verifies that ErrUnknownUsername is
// propagated when the device responds to the discovery probe with
// usmStatsUnknownUserNames but provides an empty AuthoritativeEngineID in the
// USM security parameters. Without a valid engine ID there is nothing useful to
// extract, so the error must not be suppressed.
func TestV3DiscoveryUnknownUserNamesNoEngineID(t *testing.T) {
	agent := newMockAgentUnknownUserNames(t, testDiscoveryEngineID, testDiscoveryEngineBoots, testDiscoveryEngineTime)
	agent.omitEngineIDInReport = true
	go agent.serve()
	t.Cleanup(func() { agent.closeAndCheck(t) })

	ts := newV3NoAuthClientForDiscoveryTest(agent.port())
	require.NoError(t, ts.Connect())
	t.Cleanup(func() { ts.Conn.Close() })

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
	agent := newMockAgentUnknownUserNames(t, testDiscoveryEngineID, testDiscoveryEngineBoots, testDiscoveryEngineTime)
	// failAuthRequests must be set before serve() is started.
	agent.failAuthRequests = true
	go agent.serve()
	t.Cleanup(func() { agent.closeAndCheck(t) })

	ts := newV3NoAuthClientForDiscoveryTest(agent.port())
	require.NoError(t, ts.Connect())
	t.Cleanup(func() { ts.Conn.Close() })

	_, err := ts.Get([]string{".1.3.6.1.2.1.1.1.0"})
	require.ErrorIs(t, err, ErrUnknownUsername,
		"ErrUnknownUsername from a post-discovery request must not be suppressed")
}
