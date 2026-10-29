// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build all || walk

package gosnmp

import (
	"io"
	"log"
	"net"
	"testing"
)

// trailingDotMIB is the small subtree served by startTrailingDotAgent. The
// leading leaf is intentionally a scalar under the root so the walk stops
// after exactly len(trailingDotMIB) callbacks.
var trailingDotMIB = []string{
	".1.0.8802.1.1.2.1.3.7.0.1",
	".1.0.8802.1.1.2.1.3.7.0.2",
	".1.0.8802.1.1.2.1.3.7.0.3",
}

// startTrailingDotAgent runs a minimal self-contained SNMPv2c agent that
// answers GET / GETNEXT / GETBULK for trailingDotMIB over UDP on loopback.
// It returns the bound port.
func startTrailingDotAgent(t *testing.T) uint16 {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	decoder := &GoSNMP{
		Version:   Version2c,
		Community: "public",
		Logger:    NewLogger(log.New(io.Discard, "", 0)),
	}

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req, err := decoder.SnmpDecodePacket(buf[:n])
			if err != nil {
				continue
			}
			out := trailingDotRespond(req)
			if out == nil {
				continue
			}
			if _, err := conn.WriteToUDP(out, addr); err != nil {
				return
			}
		}
	}()

	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

// trailingDotRespond builds the raw v2c response bytes for a single-varbind
// request against trailingDotMIB.
func trailingDotRespond(req *SnmpPacket) []byte {
	resp := &SnmpPacket{
		Version:   Version2c,
		Community: req.Community,
		PDUType:   GetResponse,
		RequestID: req.RequestID,
		Error:     NoError,
		Logger:    req.Logger,
	}

	root := req.Variables[0].Name
	switch req.PDUType {
	case GetBulkRequest:
		maxReps := int(req.MaxRepetitions)
		if maxReps <= 0 {
			maxReps = 1
		}
		for _, oid := range trailingDotMIB {
			if oidCompare(oid, root) > 0 {
				resp.Variables = append(resp.Variables, SnmpPDU{Name: oid, Type: Integer, Value: 0})
				if len(resp.Variables) >= maxReps {
					break
				}
			}
		}
	case GetNextRequest:
		for _, oid := range trailingDotMIB {
			if oidCompare(oid, root) > 0 {
				resp.Variables = append(resp.Variables, SnmpPDU{Name: oid, Type: Integer, Value: 0})
				break
			}
		}
	case GetRequest:
		for _, oid := range trailingDotMIB {
			if oid == root {
				resp.Variables = append(resp.Variables, SnmpPDU{Name: oid, Type: Integer, Value: 0})
				break
			}
		}
	}

	if len(resp.Variables) == 0 {
		// Signal end of walk to the client.
		resp.Variables = append(resp.Variables, SnmpPDU{Name: root, Type: EndOfMibView})
	}

	out, err := resp.marshalMsg()
	if err != nil {
		return nil
	}
	return out
}

// walkCollect collects the OIDs reported to a walkFn.
func walkCollect(t *testing.T, gs *GoSNMP, rootOid string, walkFn WalkFunc) []string {
	t.Helper()
	var got []string
	err := gs.BulkWalk(rootOid, func(pdu SnmpPDU) error {
		got = append(got, pdu.Name)
		if walkFn != nil {
			return walkFn(pdu)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("BulkWalk(%q): %v", rootOid, err)
	}
	return got
}

// TestBulkWalkTrailingDotRootOID guards issue #480: a walk rooted at an OID
// with a trailing dot must behave exactly like the same OID without it.
func TestBulkWalkTrailingDotRootOID(t *testing.T) {
	port := startTrailingDotAgent(t)

	gs := newTestGoSNMP()
	gs.Target = "127.0.0.1"
	gs.Port = port
	if err := gs.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = gs.Conn.Close() })

	// A trailing-dot rootOID is not a valid OID and must be rejected with an
	// error instead of silently walking nothing (issue #480).
	err := gs.BulkWalk(".1.0.8802.1.1.2.1.3.7.", func(pdu SnmpPDU) error { return nil })
	if err == nil {
		t.Fatal("BulkWalk with trailing-dot OID: expected an error, got nil")
	}

	// The same OID without the trailing dot must still walk the subtree.
	got := walkCollect(t, gs, ".1.0.8802.1.1.2.1.3.7", nil)
	if len(got) != len(trailingDotMIB) {
		t.Fatalf("no-dot walk: callback invoked %d times, want %d (walked: %v)", len(got), len(trailingDotMIB), got)
	}
	for i, name := range got {
		if name != trailingDotMIB[i] {
			t.Errorf("no-dot walk: walked[%d] = %q, want %q", i, name, trailingDotMIB[i])
		}
	}
}
