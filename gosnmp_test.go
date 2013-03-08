// Copyright 2013 Sonia Hamilton. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package gosnmp

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var veraxDevices = []struct {
	path string
	port uint16
}{
	{"device/os/os-linux-std.txt", 161},
	{"device/cisco/cisco_router.txt", 162},
}

func TestGet(t *testing.T) {
	for i, test := range veraxDevices {
		var err error

		// load verax results
		var vresults testResults
		if vresults, err = ReadVeraxResults(test.path); err != nil {
			t.Errorf("#%d, |%s|: ReadVeraxResults error: |%s|", i, test.path, err)
		}

		// load gosnmp results
		var gresults = make(testResults)
		x, err := NewGoSNMP("127.0.0.1", test.port, "public", Version2c, 2)
		if err != nil {
			t.Errorf("%s, err |%s| NewGoSNMP()", test.path, err)
		} else {
			defer x.Conn.Close()
		}
		for oid, _ := range vresults {
			if packet, err := x.Get(oid); err == nil {
				gresults[oid] = packet
			} else {
				t.Errorf("%s, err |%s| Get() for oid |%s|", test.path, err, oid)
			}
		}

		// compare results
		for oid, vpacket := range vresults {
			if len(vpacket.Variables) < 1 {
				t.Errorf("%s, vpacket.Variables < 1 for oid |%s|", test.path, oid)
			}
			vpdu := vpacket.Variables[0]
			vtype := vpdu.Type
			vvalue := vpdu.Value

			gpacket := gresults[oid]
			if gpacket == nil || len(gpacket.Variables) < 1 {
				t.Errorf("%s, gpacket.Variables < 1 for oid |%s|", test.path, oid)
				continue
			}
			gpdu := gpacket.Variables[0]
			gtype := gpdu.Type
			gvalue := gpdu.Value

			// the actual comparison testing
			if vtype != gtype {
				t.Errorf("vtype |%#x| doesn't match gtype |%#x| for oid |%s|", vtype, gtype, oid)
				continue
			}

			switch vtype {
			case Integer, Gauge32, Counter32, TimeTicks, Counter64:
				vval := ToBigInt(vvalue)
				gval := ToBigInt(gvalue)
				if vval.Cmp(gval) != 0 {
					t.Errorf("vvalue |%v|%s| doesn't match gvalue |%v|%s| for type |%#x| oid |%s|",
						vvalue, vval, gvalue, gval, vtype, oid)
				}
			case OctetString:
				var vval, gval string
				var ok bool
				if vval, ok = vvalue.(string); !ok {
					t.Errorf("failed string assert vvalue |%v|", vval)
				} else if gval, ok = gvalue.(string); !ok {
					t.Errorf("failed string assert gvalue |%v|", gval)

				} else if strings.HasPrefix(vval, "2010-") {
					// skip weird Verax encoded hex strings
					continue
				} else if strings.HasPrefix(vval, "2011-") {
					// skip weird Verax encoded hex strings
					continue
				} else if vval != gval && oid != "1.3.6.1.2.1.1.1.0" {
					// Verax mishandles 1.3.6.1.2.1.1.1.0 on Cisco device
					t.Errorf("failed string comparison\nVVAL |%s|\nGVAL |%s|\ntype |%#x| oid |%s|",
						vval, gval, vtype, oid)
				}
			case ObjectIdentifier, IpAddress:
				var vval, gval string
				var ok bool
				if vval, ok = vvalue.(string); !ok {
					t.Errorf("failed string assert vvalue |%v|", vval)
				} else if gval, ok = gvalue.(string); !ok {
					t.Errorf("failed string assert gvalue |%v|", gval)
				} else if vval != gval {
					t.Errorf("failed comparison\nVVAL |%s|\nGVAL |%s|\ntype |%#x| oid |%s|",
						vval, gval, vtype, oid)
				}
			default:
				t.Errorf("unhandled case: vtype |%#x| vvalue |%v| oid |%s|", vtype, vvalue, oid)
			}

		}
	}
}

type testResults map[string]*SnmpPacket

func ReadVeraxResults(filename string) (results testResults, err error) {
	var lines []byte
	if lines, err = ioutil.ReadFile(filename); err != nil {
		return nil, fmt.Errorf("unable to open file %s", filename)
	}
	results = make(testResults)

	// some lines have newlines in them, therefore can't just split on newline
	lines_split := re_split(regexp.MustCompile(`\n\.`), string(lines), -1)
LINE:
	for _, line := range lines_split {
		splits_a := strings.SplitN(line, " = ", 2)
		oid := splits_a[0]
		splits_b := strings.SplitN(splits_a[1], ": ", 2)
		oidtype := splits_b[0]
		oidval := strings.TrimSpace(splits_b[1])

		// removing leading . first oid
		if string(oid[0]) == "." {
			oid = oid[1:]
		}

		var pdu SnmpPDU
		switch oidtype {

		// listed in order of RFC2578

		case "INTEGER":
			if value, err := strconv.ParseInt(oidval, 10, 64); err != nil {
				panic(fmt.Sprintf("Err converting integer. oid: %s err: %v", oid, err))
			} else {
				pdu.Type = Integer
				pdu.Value = value
			}

		case "STRING", "String":
			oidval = strings.Trim(oidval, `"`)
			oidval = strings.Replace(oidval, string(0x0d), "", -1)
			pdu.Type = OctetString
			pdu.Value = oidval

		case "Hex-STRING":
			// TODO - ran out of time...
			continue LINE

		case "OID":
			pdu.Type = ObjectIdentifier
			pdu.Value = oidval

		case "BITS":
			// TODO - ran out of time...
			continue LINE

		case "IpAddress", "Network Address":
			pdu.Type = IpAddress
			pdu.Value = oidval
			if strings.Contains(oidval, ":") {
				// IpAddress is in "C0:A8:C4:01" format
				octets := strings.Split(oidval, ":")
				for i, octet := range octets {
					n, _ := strconv.ParseUint(octet, 16, 8)
					octets[i] = fmt.Sprintf("%d", n)
				}
				pdu.Value = strings.Join(octets, ".")
			}

		case "Counter32":
			if value, err := strconv.ParseInt(oidval, 10, 64); err != nil {
				panic(fmt.Sprintf("Err converting integer. oid: %s err: %v", oid, err))
			} else {
				pdu.Type = Counter32
				pdu.Value = value
			}

		case "Gauge32":
			if value, err := strconv.ParseInt(oidval, 10, 64); err != nil {
				panic(fmt.Sprintf("Err converting integer. oid: %s err: %v", oid, err))
			} else {
				pdu.Type = Gauge32
				pdu.Value = value
			}

		case "Timeticks":
			matches := regexp.MustCompile(`\d+`).FindAllString(oidval, 1) // pull out "(value)"
			oidval := matches[0]
			if value, err := strconv.ParseInt(oidval, 10, 64); err != nil {
				panic(fmt.Sprintf("Err converting integer. oid: %s err: %v", oid, err))
			} else {
				pdu.Type = TimeTicks
				pdu.Value = value
			}

		case "Counter64":
			if value, err := strconv.ParseUint(oidval, 10, 64); err != nil {
				panic(fmt.Sprintf("Err converting integer. oid: %s err: %v", oid, err))
			} else {
				pdu.Type = Counter64
				pdu.Value = value
			}

		default:
			panic(fmt.Sprintf("Unhandled type: %s, %s\n", oidtype, oidval))
		}

		packet := &SnmpPacket{
			Variables: []SnmpPDU{pdu},
		}
		results[oid] = packet
	}
	return results, nil
}

// adapted from http://codereview.appspot.com/6846048/
//
// re_split slices s into substrings separated by the expression and returns a slice of
// the substrings between those expression matches.
//
// The slice returned by this method consists of all the substrings of s
// not contained in the slice returned by FindAllString(). When called on an exp ression
// that contains no metacharacters, it is equivalent to strings.SplitN().
// Example:
// s := regexp.MustCompile("a*").re_split("abaabaccadaaae", 5)
// // s: ["", "b", "b", "c", "cadaaae"]
//
// The count determines the number of substrings to return:
// n > 0: at most n substrings; the last substring will be the unsplit remaind er.
// n == 0: the result is nil (zero substrings)
// n < 0: all substrings
func re_split(re *regexp.Regexp, s string, n int) []string {
	if n == 0 {
		return nil
	}
	if len(s) == 0 {
		return []string{""}
	}
	matches := re.FindAllStringIndex(s, n)
	strings := make([]string, 0, len(matches))
	beg := 0
	end := 0
	for _, match := range matches {
		if n > 0 && len(strings) >= n-1 {
			break
		}
		end = match[0]
		if match[1] != 0 {
			strings = append(strings, s[beg:end])
		}
		beg = match[1]
	}
	if end != len(s) {
		strings = append(strings, s[beg:])
	}
	return strings
}
