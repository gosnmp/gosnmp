// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build !netsnmp

package netsnmp

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/gosnmp/gosnmp"
)

func isPlayback() bool {
	return true
}

func netSnmpPduPkt(fname string, _ gosnmp.SnmpPDU, _ *gosnmp.GoSNMP, _ uint32, _ bool) ([]byte, error) {
	pberr := "error with net-snmp playback file, run test with `-rec=true` to create missing playback files: %w"

	// find and return the capture file, else error
	b64, err := os.ReadFile(fname)
	if err != nil {
		return nil, fmt.Errorf(pberr, err)
	}

	out, err := base64.StdEncoding.DecodeString(string(b64))
	if err != nil {
		return nil, fmt.Errorf(pberr, err)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf(pberr, errors.New("empty file"))
	}

	return out, nil
}
