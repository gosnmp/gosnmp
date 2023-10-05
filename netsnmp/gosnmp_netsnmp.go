// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build netsnmp

package netsnmp

/*
#cgo LDFLAGS: -lnetsnmp
#include <stdint.h>
#include <stdlib.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/output_api.h>
#include <net-snmp/config_api.h>

u_char* getPktStart(u_char* pkt, ulong len, ulong off){
	return pkt+len-off;
}
*/
import "C"
import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"github.com/gosnmp/gosnmp"
)

func isPlayback() bool {
	return false
}

type netSnmpValType int

/*
case TYPE_INTEGER:

	case TYPE_INTEGER32:
	    type = 'i';
	    break;
	case TYPE_GAUGE:
	case TYPE_UNSIGNED32:
	    type = 'u';
	    break;
	case TYPE_UINTEGER:
	    type = '3';
	    break;
	case TYPE_COUNTER:
	    type = 'c';
	    break;
	case TYPE_COUNTER64:
	    type = 'C';
	    break;
	case TYPE_TIMETICKS:
	    type = 't';
	    break;
	case TYPE_OCTETSTR:
	    type = 's';
	    break;
	case TYPE_BITSTRING:
	    type = 'b';
	    break;
	case TYPE_IPADDR:
	    type = 'a';
	    break;
	case TYPE_OBJID:
	    type = 'o';
	    break;
*/
func berToSnmpValType(in gosnmp.Asn1BER) (C.char, error) {
	switch in {
	case gosnmp.Gauge32:
		return 'u', nil
	case gosnmp.Integer:
		return 'i', nil
	case gosnmp.OctetString:
		return 's', nil
	case gosnmp.IPAddress:
		return 'a', nil
	case gosnmp.ObjectIdentifier:
		return 'o', nil
	case gosnmp.Counter32:
		return 'c', nil
	case gosnmp.Counter64:
		return 'C', nil
	case gosnmp.OpaqueFloat:
		return 'F', nil
	case gosnmp.OpaqueDouble:
		return 'D', nil
	case gosnmp.TimeTicks:
		return 't', nil
	case gosnmp.Uinteger32:
		return '3', nil
	default:
		return 0, errors.New("unhandled asn1 ber type" + in.String())
	}
}

func verToSnmpVer(in gosnmp.SnmpVersion) (C.int, error) {
	switch in {
	case gosnmp.Version1:
		return C.SNMP_VERSION_1, nil
	case gosnmp.Version2c:
		return C.SNMP_VERSION_2c, nil
	case gosnmp.Version3:
		return C.SNMP_VERSION_3, nil
	default:
		return 0, errors.New("handled snmp version " + in.String())
	}
}

func netSnmpPduPkt(fname string, gopdu gosnmp.SnmpPDU, gosess *gosnmp.GoSNMP, reqid uint32, verbose bool) ([]byte, error) {

	var errout *C.char
	var err error

	oid := oidStringToInts(gopdu.Name)

	if verbose {
		netSnmpEnableLogging()
	}

	//enable reverse encode
	C.netsnmp_ds_set_boolean(C.NETSNMP_DS_LIBRARY_ID,
		C.NETSNMP_DS_LIB_REVERSE_ENCODE,
		C.NETSNMP_DEFAULT_ASNENCODING_DIRECTION)

	//create session
	sess := &C.struct_snmp_session{
		version:       C.SNMP_DEFAULT_VERSION,
		community:     (*C.uchar)((unsafe.Pointer)(C.CString(gosess.Community))),
		community_len: C.size_t(len(gosess.Community)),
	}
	defer C.free(unsafe.Pointer(sess.community))

	//create pdu
	pdu := C.snmp_pdu_create(C.SNMP_MSG_SET)
	defer C.free(unsafe.Pointer(pdu))
	tmp, err := verToSnmpVer(gosess.Version)
	if err != nil {
		return nil, err
	}
	pdu.version = C.long(tmp)
	pdu.reqid = C.long(reqid)

	tstoid := [1024]C.oid{}
	tstoidcnt := C.size_t(0)
	for i := range oid {
		tstoid[i] = C.oid(oid[i])
		tstoidcnt++
	}
	cval := C.CString(valToString(gopdu))
	defer C.free(unsafe.Pointer(cval))
	ctype, err := berToSnmpValType(gopdu.Type)
	if err != nil {
		return nil, err
	}
	rv := C.snmp_add_var(pdu, (*C.oid)(unsafe.Pointer(&tstoid)), tstoidcnt, ctype, cval)
	if rv < 0 {
		C.snmp_perror(errout)
		err = fmt.Errorf("net-snmp error: snmp_add_var: %s", C.GoString(errout))
		return nil, err
	}

	//render packet
	sz := 2048
	pktout := (*C.uchar)(C.malloc(C.size_t(sz)))
	pktoutlen := C.size_t(sz)
	var pktoutoffset C.size_t

	rv = C.snmp_build(&pktout, &pktoutlen, &pktoutoffset, sess, pdu)
	if rv < C.int(0) {
		C.snmp_error(sess, nil, nil, &errout)
		err = fmt.Errorf("net-snmp error: snmp_build: %s", C.GoString(errout))
		return nil, err
	}
	defer C.free(unsafe.Pointer(pktout))

	return C.GoBytes(unsafe.Pointer(C.getPktStart(pktout, pktoutlen, pktoutoffset)), C.int(pktoutoffset)), nil

}

func netSnmpEnableLogging() {
	C.snmp_enable_stderrlog()
	C.snmp_set_do_debugging(1)
	C.snmp_set_dump_packet(1)
	tmp := C.CString("")
	C.debug_register_tokens(tmp)
	C.free(unsafe.Pointer(tmp))
}

func oidStringToInts(in string) []int {
	out := make([]int, 0, len(in))

	for _, oi := range strings.Split(in, ".") {
		tmp, err := strconv.Atoi(oi)
		if err == nil {
			out = append(out, tmp)
		}
	}
	return out
}

func valToString(gopdu gosnmp.SnmpPDU) string {
	var val any
	switch gopdu.Type {
	case gosnmp.OctetString:
		b, ok := gopdu.Value.([]byte)
		if ok {
			val = string(b)
		} else {
			val = gopdu.Value
		}
	default:
		val = gopdu.Value

	}
	return fmt.Sprintf("%v", val)
}
