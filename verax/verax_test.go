// Copyright 2012-2014 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package verax_test

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"testing"
	. "github.com/soniah/gosnmp"
)

type testResults map[string]SnmpPDU

var veraxDevices = []struct {
	path string
	port uint16
}{
	{"device/os/os-linux-std.txt", 161},
	{"device/cisco/cisco_router.txt", 162},
}

// 1 <= PARTITION_SIZE <= maxOids - adjust as required
const PARTITION_SIZE = 3

// reduce OID_COUNT to speed up tests;
// set to 1<<32 - 1 (MaxUint32) for everything
const OID_COUNT = 1<<16 - 1

func TestVeraxGet(t *testing.T) {

	for i, test := range veraxDevices {
		var err error

		// load verax results
		var vresults testResults
		if vresults, err = ReadVeraxResults(test.path); err != nil {
			t.Errorf("#%d, |%s|: ReadVeraxResults error: |%s|", i, test.path, err)
		}

		// load gosnmp results
		var gresults = make(testResults)

		Default.Target = "127.0.0.1"
		Default.Port = test.port
		// Default.Logger = log.New(os.Stdout, "", 0) // for verbose logging
		err = Default.Connect()
		if err != nil {
			t.Errorf("%s, err |%s| Connect()", test.path, err)
		} else {
			defer Default.Conn.Close()
		}

		var oids []string
		i := 0
		oids_count := len(vresults)
		for oid, _ := range vresults {
			oids = append(oids, oid)
			i++
			if Partition(i, PARTITION_SIZE, oids_count) {
				if get_results, err := Default.Get(oids); err == nil {
					for _, vb := range get_results.Variables {
						gresults[vb.Name] = vb
					}
				} else {
					t.Errorf("%s, err |%s| Get() for oids |%s|", test.path, err, oids)
				}
				i = 0
				oids = nil // "truncate" oids
			}
		}

		// compare results
		for oid, vpdu := range vresults {
			vtype := vpdu.Type
			vvalue := vpdu.Value
			gpdu := gresults[oid]
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
				} else if b, ok := gvalue.([]byte); !ok {
					gval = string(b)
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
			case ObjectIdentifier, IPAddress:
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

func TestVeraxGetNext(t *testing.T) {

	for i, test := range veraxDevices {
		var err error

		oid_map := getnext_expected(test.port)

		// load gosnmp results
		var gresults = make(testResults)

		Default.Target = "127.0.0.1"
		Default.Port = test.port
		// Default.Logger = log.New(os.Stdout, "", 0) // for verbose logging
		err = Default.Connect()
		if err != nil {
			t.Errorf("%s, err |%s| Connect()", test.path, err)
		} else {
			defer Default.Conn.Close()
		}

		var oids []string
		oids_count := len(oid_map)
		for oid, snmp_packet := range oid_map {
			oids = append(oids, oid)
			if Partition(i, PARTITION_SIZE, oids_count) {
				if get_results, err := Default.GetNext(oids); err == nil {
					for _, vb := range get_results.Variables {
						gresults[vb.Name] = vb
					}
				} else {
					t.Errorf("%s, err |%s| Get() for oids |%s|", test.path, err, oids)
				}
				i = 0
				oids = nil // "truncate" oids
			}

			// compare results
			i := 0
			for oid, gpdu := range gresults {
				vpdu := snmp_packet.Variables[i]
				vtype := vpdu.Type
				vvalue := vpdu.Value
				gtype := gpdu.Type
				gvalue := gpdu.Value
				i++

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
				case ObjectIdentifier, IPAddress:
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
}

func TestVeraxGetBulk(t *testing.T) {

	for i, test := range veraxDevices {
		var err error

		oid_map := getbulk_expected(test.port)

		// load gosnmp results
		var gresults = make(testResults)

		Default.Target = "127.0.0.1"
		Default.Port = test.port
		// Default.Logger = log.New(os.Stdout, "", 0) // for verbose logging
		err = Default.Connect()
		if err != nil {
			t.Errorf("%s, err |%s| Connect()", test.path, err)
		} else {
			defer Default.Conn.Close()
		}

		var oids []string
		oids_count := len(oid_map)
		for oid, snmp_packet := range oid_map {
			oids = append(oids, oid)
			if Partition(i, PARTITION_SIZE, oids_count) {
				if get_results, err := Default.GetBulk(oids, 0, 10); err == nil {
					for _, vb := range get_results.Variables {
						gresults[vb.Name] = vb
					}
				} else {
					t.Errorf("%s, err |%s| Get() for oids |%s|", test.path, err, oids)
				}
				i = 0
				oids = nil // "truncate" oids
			}

			// compare results
			i := 0
			for oid, gpdu := range gresults {
				vpdu := snmp_packet.Variables[i]
				vname := vpdu.Name
				// doesn't always come back in order'
				for i := 0; vname != gpdu.Name; i++ {
					vpdu = snmp_packet.Variables[i]
					vname = vpdu.Name
				}
				vtype := vpdu.Type
				vvalue := vpdu.Value
				gtype := gpdu.Type
				gvalue := gpdu.Value
				i++

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
				case ObjectIdentifier, IPAddress:
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
}

func getnext_expected(port uint16) map[string]*SnmpPacket {
	// maps a an oid string to an SnmpPacket
	switch port {
	case 161:
		return map[string]*SnmpPacket{
			"1.3.6.1.2.1.1.9.1.4.8": &SnmpPacket{
				Version:    Version2c,
				Community:  "public",
				PDUType:    GetResponse,
				RequestID:  0,
				Error:      0,
				ErrorIndex: 0,
				Variables: []SnmpPDU{
					{
						Name:  "1.3.6.1.2.1.2.1.0",
						Type:  Integer,
						Value: 3,
					},
				},
			},
			"1.3.6.1.2.1.92.1.2": &SnmpPacket{
				Version:    Version2c,
				Community:  "public",
				PDUType:    GetResponse,
				RequestID:  0,
				Error:      0,
				ErrorIndex: 0,
				Variables: []SnmpPDU{
					{
						Name:  "1.3.6.1.2.1.92.1.2.1.0",
						Type:  Counter32,
						Value: 0,
					},
				},
			},
			"1.3.6.1.2.1.1.9.1.3.52": &SnmpPacket{
				Version:    Version2c,
				Community:  "public",
				PDUType:    GetResponse,
				RequestID:  0,
				Error:      0,
				ErrorIndex: 0,
				Variables: []SnmpPDU{
					{
						Name:  "1.3.6.1.2.1.1.9.1.4.1",
						Type:  TimeTicks,
						Value: 21,
					},
				},
			},
			"1.3.6.1.2.1.3.1.1.3.2.1.192.168.104.1": &SnmpPacket{
				Version:    Version2c,
				Community:  "public",
				PDUType:    GetResponse,
				RequestID:  0,
				Error:      0,
				ErrorIndex: 0,
				Variables: []SnmpPDU{
					{
						Name:  "1.3.6.1.2.1.3.1.1.3.2.1.192.168.104.2",
						Type:  IPAddress,
						Value: "192.168.104.2",
					},
				},
			},
		}
	case 162:
		return map[string]*SnmpPacket{
			"1.3.6.1.2.1.3.1.1.3.2.1.192.168.104.1": &SnmpPacket{
				Version:    Version2c,
				Community:  "public",
				PDUType:    GetResponse,
				RequestID:  0,
				Error:      0,
				ErrorIndex: 0,
				Variables: []SnmpPDU{
					{
						Name:  "1.3.6.1.2.1.3.1.1.3.9.1.192.168.1.250",
						Type:  IPAddress,
						Value: "192.168.1.250",
					},
				},
			},
			"1.3.6.1.2.1.1.9.1.4.8": &SnmpPacket{
				Version:    Version2c,
				Community:  "public",
				PDUType:    GetResponse,
				RequestID:  0,
				Error:      0,
				ErrorIndex: 0,
				Variables: []SnmpPDU{
					{
						Name:  "1.3.6.1.2.1.1.9.1.4.9",
						Type:  TimeTicks,
						Value: 0,
					},
				},
			},
			"1.3.6.1.2.1.92.1.2": &SnmpPacket{
				Version:    Version2c,
				Community:  "public",
				PDUType:    GetResponse,
				RequestID:  0,
				Error:      0,
				ErrorIndex: 0,
				Variables: []SnmpPDU{
					{
						Name:  "1.3.6.1.2.1.92.1.2.1.0",
						Type:  Counter32,
						Value: 0,
					},
				},
			},
			"1.3.6.1.2.1.1.9.1.5": &SnmpPacket{
				Version:    Version2c,
				Community:  "public",
				PDUType:    GetResponse,
				RequestID:  0,
				Error:      0,
				ErrorIndex: 0,
				Variables: []SnmpPDU{
					{
						Name:  "1.3.6.1.2.1.2.1.0",
						Type:  Integer,
						Value: 30,
					},
				},
			},
		}
	default:
		return nil
	}
}

func getbulk_expected(port uint16) map[string]*SnmpPacket {
	// maps a an oid string to an SnmpPacket
	switch port {
	case 161:
		return map[string]*SnmpPacket{
			"1.3.6.1.2.1.1.9.1.4.8": &SnmpPacket{
				Version:        Version2c,
				Community:      "public",
				PDUType:        GetResponse,
				RequestID:      0,
				NonRepeaters:   0,
				MaxRepetitions: 0,
				Variables: []SnmpPDU{
					{
						Name:  "1.3.6.1.2.1.2.1.0",
						Type:  Integer,
						Value: 3,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.1",
						Type:  Integer,
						Value: 1,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.2",
						Type:  Integer,
						Value: 2,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.3",
						Type:  Integer,
						Value: 3,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.2.1",
						Type:  OctetString,
						Value: "lo",
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.2.2",
						Type:  OctetString,
						Value: "eth0",
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.2.3",
						Type:  OctetString,
						Value: "sit0",
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.3.1",
						Type:  Integer,
						Value: 24,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.3.2",
						Type:  Integer,
						Value: 6,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.3.3",
						Type:  Integer,
						Value: 131,
					},
				},
			},
		}
	case 162:
		return map[string]*SnmpPacket{
			"1.3.6.1.2.1.1.9.1.5": &SnmpPacket{
				Version:        Version2c,
				Community:      "public",
				PDUType:        GetResponse,
				RequestID:      0,
				NonRepeaters:   0,
				MaxRepetitions: 0,
				Variables: []SnmpPDU{
					{
						Name:  "1.3.6.1.2.1.2.1.0",
						Type:  Integer,
						Value: 30,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.1",
						Type:  Integer,
						Value: 1,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.2",
						Type:  Integer,
						Value: 2,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.3",
						Type:  Integer,
						Value: 3,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.4",
						Type:  Integer,
						Value: 4,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.5",
						Type:  Integer,
						Value: 5,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.6",
						Type:  Integer,
						Value: 6,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.7",
						Type:  Integer,
						Value: 7,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.8",
						Type:  Integer,
						Value: 8,
					},
					{
						Name:  "1.3.6.1.2.1.2.2.1.1.9",
						Type:  Integer,
						Value: 9,
					},
				},
			},
		}
	default:
		return nil
	}
}

func ReadVeraxResults(filename string) (results testResults, err error) {
	var lines []byte
	var oid_count int64
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
		oid_count++
		if oid_count > OID_COUNT {
			break LINE
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
			if string(oidval[0]) == "." {
				oidval = oidval[1:]
			}
			pdu.Value = oidval

		case "BITS":
			// TODO - ran out of time...
			continue LINE

		case "IPAddress", "Network Address":
			pdu.Type = IPAddress
			pdu.Value = oidval
			if strings.Contains(oidval, ":") {
				// IPAddress is in "C0:A8:C4:01" format
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
			if value, err := strconv.ParseUint(oidval, 10, 64); err != nil {
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

		results[oid] = pdu
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
