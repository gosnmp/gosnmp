// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build all || trap

package gosnmp

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReflectorUDPConn(t *testing.T) {
	subs := []struct {
		name                      string
		bindIP, targetIP, bindNet string
		clientIP, clientNet       string
	}{
		// Linux binds 127.0.0.x to loopback by default, but not MacOS or Windows
		//{"udp bind * send 127.0.0.2 from 127.0.0.3", "*", "127.0.0.2", "udp", "127.0.0.3", "udp"},
		// TODO: use getNonLoopbackIPs to pick up some other address(-es) to test with

		{"udp bind * send localhost", "*", "127.0.0.1", "udp", "*", "udp"},
		{"udp bind * send localhost6", "*", "::1", "udp", "*", "udp"},
		{"udp4 bind * send localhost", "*", "127.0.0.1", "udp4", "*", "udp"},
		{"udp6 bind * send localhost6", "*", "::1", "udp6", "*", "udp"},

		{"udp bind localhost send localhost", "127.0.0.1", "127.0.0.1", "udp", "*", "udp"},
		{"udp bind localhost6 send localhost6", "::1", "::1", "udp", "*", "udp"},
		{"udp4 bind localhost send localhost", "127.0.0.1", "127.0.0.1", "udp4", "*", "udp"},
		{"udp6 bind localhost6 send localhost6", "::1", "::1", "udp6", "*", "udp"},
	}

	for _, sub := range subs {
		t.Run(sub.name, func(t *testing.T) {
			srvAddr := &net.UDPAddr{IP: net.ParseIP(sub.bindIP)}
			srv, err := net.ListenUDP(sub.bindNet, srvAddr)
			require.NoError(t, err)
			defer srv.Close()

			srvRealAddr := srv.LocalAddr().(*net.UDPAddr)
			srvFamily, err := addrFamily(srv)
			require.NoError(t, err)

			r := newReflectorUDPConn(srv)

			t.Logf("SERVER: bind %v real %v, family %d\n", srvAddr, srvRealAddr, srvFamily)

			clientAddr := &net.UDPAddr{IP: net.ParseIP(sub.clientIP)}
			client, err := net.ListenUDP(sub.clientNet, clientAddr)
			require.NoError(t, err)

			clientRealAddr := client.LocalAddr().(*net.UDPAddr)
			clientFamily, err := addrFamily(client)
			require.NoError(t, err)

			t.Logf("CLIENT: bind %v real %v, family %d\n", clientAddr, clientRealAddr, clientFamily)

			payload := []byte("payload")
			srvErr := make(chan error, 1)
			go func() {
				require.NoError(t, srv.SetDeadline(time.Now().Add(1*time.Second)))
				buf := make([]byte, 1024)
				n, src, respond, err := r.readUDPFrom(buf)
				if err != nil {
					srvErr <- err
					return
				}
				t.Logf("REQUEST: from %v", src)

				_, err = respond(buf[:n])
				if err != nil {
					srvErr <- err
					return
				}

				srvErr <- nil
			}()

			_, err = client.WriteToUDP(payload, &net.UDPAddr{IP: net.ParseIP(sub.targetIP), Port: srvRealAddr.Port})
			require.NoError(t, err)

			require.NoError(t, <-srvErr) // wait for the server to respond

			require.NoError(t, client.SetDeadline(time.Now().Add(1*time.Second)))
			buf := make([]byte, 1024)
			n, src, err := client.ReadFromUDP(buf)
			require.NoError(t, err)
			require.Equal(t, payload, buf[:n])

			t.Logf("RESPONSE: from %v", src)
			require.Equal(t, net.UDPAddr{IP: net.ParseIP(sub.targetIP).To16(), Port: srvRealAddr.Port}, net.UDPAddr{IP: src.IP.To16(), Port: src.Port})
		})
	}
}

func addrFamily(c syscall.Conn) (family int, err error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return
	}

	var sockAddr syscall.Sockaddr
	var sysErr error
	err = errors.Join(sysErr, rc.Control(func(fd uintptr) { sockAddr, sysErr = syscall.Getsockname(int(fd)) }))
	if err != nil {
		return
	}

	switch sockAddr.(type) {
	case *syscall.SockaddrInet4:
		family = syscall.AF_INET
	case *syscall.SockaddrInet6:
		family = syscall.AF_INET6
	default:
		err = fmt.Errorf("unexpected socket address type %T", sockAddr)
	}
	return
}

func getNonLoopbackIPs() (ipv4 net.IP, ipv6 net.IP, err error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	for _, addr := range addrs {
		ipAddr, ok := addr.(*net.IPNet)
		if !ok {
			continue
		} else if !ipAddr.IP.IsGlobalUnicast() && !ipAddr.IP.IsPrivate() {
			continue
		}
		if ip := ipAddr.IP.To4(); ip != nil {
			ipv4 = ip
		}
		if ip := ipAddr.IP.To16(); ip != nil {
			ipv6 = ip
		}
	}
	if ipv4 == nil && ipv6 == nil {
		err = errors.New("no non-loopback IP addresses found")
	}
	return
}
