// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build netsnmp

package netsnmp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // SHA-1 is the fixture's SNMPv3 auth protocol
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type v3ReportFixtureCase struct {
	name string
	kind int
	file string
}

func TestV3ReportFixtures(t *testing.T) {
	fixtures := []v3ReportFixtureCase{
		{name: "unknownEngineIDs", kind: 0, file: "unknown_engine_ids_report.b64"},
		{name: "notInTimeWindowsSHA1", kind: 1, file: "not_in_time_windows_report_sha1.b64"},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			packet, err := netSnmpV3ReportFixture(fixture.kind)
			if err != nil {
				t.Fatal(err)
			}
			if fixture.kind == 1 {
				verifyV3ReportFixtureHMAC(t, packet)
			}

			path := filepath.Join("..", "testdata", "v3_harness", fixture.file)
			if *rec {
				encoded := base64.StdEncoding.EncodeToString(packet) + "\n"
				if err = os.WriteFile(path, []byte(encoded), 0600); err != nil {
					t.Fatalf("recording %s: %v", path, err)
				}
			}
			expectedBase64, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(expectedBase64)))
			if err != nil {
				t.Fatalf("decoding %s: %v", path, err)
			}
			if !bytes.Equal(packet, expected) {
				t.Fatalf("libsnmp output differs from %s\ngot:  %x\nwant: %x", path, packet, expected)
			}
		})
	}
}

func verifyV3ReportFixtureHMAC(t *testing.T, packet []byte) {
	t.Helper()
	localizedKey := mustDecodeHex(t, "47df9195cd6ac751ed9a2b4ba3025e75a605a227")
	receivedMAC := mustDecodeHex(t, "b6c19348934db5b8a57c6435")
	if count := bytes.Count(packet, receivedMAC); count != 1 {
		t.Fatalf("authentication field occurs %d times, want 1", count)
	}
	unsigned := bytes.Replace(bytes.Clone(packet), receivedMAC, make([]byte, len(receivedMAC)), 1)
	mac := hmac.New(sha1.New, localizedKey)
	_, _ = mac.Write(unsigned)
	computed := mac.Sum(nil)[:len(receivedMAC)]
	if !hmac.Equal(computed, receivedMAC) {
		t.Fatalf("HMAC-SHA-96 mismatch: got %x, want %x", computed, receivedMAC)
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(fmt.Errorf("decoding fixture hex: %w", err))
	}
	return decoded
}
