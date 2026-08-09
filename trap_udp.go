// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// reflectorUDPConn is a net.UDPConn wrapper that records both source IP:port for incoming packets and local IP they
// were received on, enabling correctly sourced responses on a multihomed host. When a platform lacks
// PacketConn.SetControlMessage support, like Windows, it gracefully degrades to just remembering the source IP:port.
type reflectorUDPConn struct {
	conn *net.UDPConn
}

var (
	oobLen = max(len(ipv4.NewControlMessage(ipv4.FlagDst)), len(ipv6.NewControlMessage(ipv6.FlagDst)))
)

func newReflectorUDPConn(conn *net.UDPConn) *reflectorUDPConn {
	c := &reflectorUDPConn{conn: conn}
	// We don't know address family of conn, so try both and see what sticks. Windows will fail both.
	_ = ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst, true)
	_ = ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst, true)
	return c
}

func (c *reflectorUDPConn) readUDPFrom(b []byte) (n int, src *net.UDPAddr, respond func(b []byte) (n int, err error), err error) {
	oob := make([]byte, oobLen) // TODO: we could reuse a buffer if we can guarantee no concurrent accesses to readFrom
	n, oobn, _, src, err := c.conn.ReadMsgUDP(b, oob)
	if err != nil {
		return
	}
	oob = oob[:oobn]

	// Try both families, ControlMessage.Parse quietly skips mismatched family messages, so we're checking for Dst.
	// IfIndex is ignored on purpose, it breaks Src outright on MacOS and is incompatible with asymmetric routing.
	var dst net.IP
	var cm4, cm6 = ipv4.ControlMessage{}, ipv6.ControlMessage{}
	if err = cm4.Parse(oob); err == nil && cm4.Dst != nil {
		dst = cm4.Dst
	} else if err = cm6.Parse(oob); err == nil && cm6.Dst != nil {
		dst = cm6.Dst
	}

	// On a dual-stack host a wildcard socket will serve both IPv4 & IPv6 in IPv6 mode. A packet directed at a local
	// IPv4 address will produce an ipv6.ControlMessage containing an 16-byte long IPv4 Dst. On the other hand,
	// ControlMessage.Marshal ignores Src with mismatched family, so here we are doing a bit of a repack.
	if dst4 := dst.To4(); dst4 != nil {
		oob = (&ipv4.ControlMessage{Src: dst}).Marshal()
	} else if dst6 := dst.To16(); dst6 != nil {
		oob = (&ipv6.ControlMessage{Src: dst}).Marshal()
	} else {
		// Windows fallback
		respond = func(b []byte) (int, error) { return c.conn.WriteToUDP(b, src) }
		return
	}

	respond = func(b []byte) (int, error) {
		n, _, err := c.conn.WriteMsgUDP(b, oob, src)
		return n, err
	}

	return
}
