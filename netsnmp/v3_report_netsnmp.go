// Copyright 2026 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build netsnmp

package netsnmp

/*
#cgo LDFLAGS: -lnetsnmp
#include <stdlib.h>
#include <string.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/keytools.h>
#include <net-snmp/library/lcd_time.h>
#include <net-snmp/library/snmpusm.h>
#include <net-snmp/library/transform_oids.h>

static const u_char harness_engine_id[] = {
    0x80, 0x00, 0x1f, 0x88, 0x04, 'h', 'a', 'r', 'n', 'e', 's', 's'
};
static const oid unknown_engine_ids_oid[] = {1,3,6,1,6,3,15,1,1,4,0};
static const oid not_in_time_windows_oid[] = {1,3,6,1,6,3,15,1,1,2,0};
static const char harness_user[] = "harnessUser";
static const char harness_auth_pass[] = "harnessAuthKey1";
static const u_char harness_engine_time_tlv[] = {0x02, 0x03, 0x06, 0x79, 0x32};

static int count_bytes(const u_char *data, size_t data_len,
                       const u_char *needle, size_t needle_len) {
    int count = 0;
    size_t i;
    for (i = 0; i + needle_len <= data_len; i++) {
        if (memcmp(data + i, needle, needle_len) == 0) {
            count++;
        }
    }
    return count;
}

static void init_v3_report_fixture_generator(void) {
    setenv("MIBS", "", 1);
    // Keep initialization free of host/user configuration and persistent
    // state: no config files are read and no persistent file is loaded or
    // written, so the generator neither depends on nor touches files
    // outside the repository.
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DONT_READ_CONFIGS, 1);
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DISABLE_PERSISTENT_LOAD, 1);
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DISABLE_PERSISTENT_SAVE, 1);
    init_snmp("gosnmp-v3-fixture-generator");
    // Pin reverse encoding rather than inheriting the build's compile-time
    // default: the result extraction below assumes snmp_build filled the
    // buffer from the end (packet + packet_len - offset).
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_REVERSE_ENCODE, 1);
}

// build_v3_report_fixture returns a complete malloc-allocated message.
// kind 0 builds unknownEngineIDs/noAuthNoPriv; kind 1 builds
// notInTimeWindows/authNoPriv with HMAC-SHA-96.
static u_char *build_v3_report_fixture(int kind, size_t *result_len, int *error_code) {
    const int authenticated = kind == 1;
    const oid *var_oid = authenticated ? not_in_time_windows_oid : unknown_engine_ids_oid;
    const size_t var_oid_len = authenticated
        ? OID_LENGTH(not_in_time_windows_oid)
        : OID_LENGTH(unknown_engine_ids_oid);
    const long msg_id = authenticated ? 170000101 : 170000001;
    const long request_id = authenticated ? 270000101 : 270000001;
    const int security_level = authenticated
        ? SNMP_SEC_LEVEL_AUTHNOPRIV
        : SNMP_SEC_LEVEL_NOAUTH;
    netsnmp_session session;
    netsnmp_pdu *pdu = NULL;
    struct usmUser *fixture_user = NULL;
    u_char *packet = NULL;
    u_char *result = NULL;
    size_t packet_len = 65535;
    size_t offset = 0;
    unsigned long counter = 1;

    *result_len = 0;
    *error_code = SNMPERR_SUCCESS;
    snmp_sess_init(&session);
    session.version = SNMP_VERSION_3;
    session.rcvMsgMaxSize = 65507;
    session.sndMsgMaxSize = 65507;
    session.securityModel = SNMP_SEC_MODEL_USM;
    session.securityLevel = security_level;
    session.isAuthoritative = SNMP_SESS_AUTHORITATIVE;
    session.securityEngineID = (u_char *)harness_engine_id;
    session.securityEngineIDLen = sizeof(harness_engine_id);
    session.contextEngineID = (u_char *)harness_engine_id;
    session.contextEngineIDLen = sizeof(harness_engine_id);
    session.contextName = "";
    session.contextNameLen = 0;
    session.engineBoots = 7;
    session.engineTime = 424242;
    session.securityName = (char *)(authenticated ? harness_user : "");
    session.securityNameLen = strlen(session.securityName);

    if (authenticated) {
        // usm_create_user_from_session updates an existing matching user
        // instead of creating one. Refuse to run against a user this
        // invocation does not own, so cleanup never removes foreign state.
        if (usm_get_user(harness_engine_id, sizeof(harness_engine_id),
                         harness_user) != NULL) {
            *error_code = SNMPERR_USM_GENERICERROR;
            goto out;
        }
        session.securityAuthProto = usmHMACSHA1AuthProtocol;
        session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
        session.securityPrivProto = usmNoPrivProtocol;
        session.securityPrivProtoLen = USM_PRIV_PROTO_NOPRIV_LEN;
        session.securityAuthKeyLen = sizeof(session.securityAuthKey);
        if (generate_Ku(session.securityAuthProto, session.securityAuthProtoLen,
                        (const u_char *)harness_auth_pass, strlen(harness_auth_pass),
                        session.securityAuthKey, &session.securityAuthKeyLen) != SNMPERR_SUCCESS ||
            usm_create_user_from_session(&session) != SNMPERR_SUCCESS) {
            *error_code = SNMPERR_USM_GENERICERROR;
            goto out;
        }
        fixture_user = usm_get_user(harness_engine_id,
                                    sizeof(harness_engine_id), harness_user);
        if (fixture_user == NULL) {
            *error_code = SNMPERR_USM_UNKNOWNSECURITYNAME;
            goto out;
        }
    }

    pdu = snmp_pdu_create(SNMP_MSG_REPORT);
    if (pdu == NULL) {
        *error_code = SNMPERR_MALLOC;
        goto out;
    }
    pdu->version = SNMP_VERSION_3;
    pdu->msgid = msg_id;
    pdu->reqid = request_id;
    pdu->errstat = 0;
    pdu->errindex = 0;
    pdu->securityModel = SNMP_SEC_MODEL_USM;
    pdu->securityLevel = security_level;
    if (snmp_clone_mem((void **)&pdu->securityEngineID,
                       harness_engine_id, sizeof(harness_engine_id)) != 0 ||
        snmp_clone_mem((void **)&pdu->contextEngineID,
                       harness_engine_id, sizeof(harness_engine_id)) != 0) {
        *error_code = SNMPERR_MALLOC;
        goto out;
    }
    pdu->securityEngineIDLen = sizeof(harness_engine_id);
    pdu->contextEngineIDLen = sizeof(harness_engine_id);
    pdu->contextName = strdup("");
    pdu->securityName = strdup(authenticated ? harness_user : "");
    if (pdu->contextName == NULL || pdu->securityName == NULL) {
        *error_code = SNMPERR_MALLOC;
        goto out;
    }
    pdu->contextNameLen = 0;
    pdu->securityNameLen = strlen(pdu->securityName);
    if (snmp_pdu_add_variable(pdu, var_oid, var_oid_len, ASN_COUNTER,
                              (const u_char *)&counter, sizeof(counter)) == NULL) {
        *error_code = SNMPERR_GENERR;
        goto out;
    }

    packet = malloc(packet_len);
    if (packet == NULL) {
        *error_code = SNMPERR_MALLOC;
        goto out;
    }
    // set_enginetime records a local-time anchor. Reset it immediately before
    // encoding, then reject a packet that crossed a one-second boundary.
    if (set_enginetime(harness_engine_id, sizeof(harness_engine_id),
                       7, 424242, TRUE) != SNMPERR_SUCCESS) {
        *error_code = SNMPERR_USM_GENERICERROR;
        goto out;
    }
    if (snmp_build(&packet, &packet_len, &offset, &session, pdu) < 0) {
        *error_code = session.s_snmp_errno;
        goto out;
    }
    if (count_bytes(packet + packet_len - offset, offset,
                    harness_engine_time_tlv, sizeof(harness_engine_time_tlv)) != 1) {
        *error_code = SNMPERR_USM_NOTINTIMEWINDOW;
        goto out;
    }

    result = malloc(offset);
    if (result == NULL) {
        *error_code = SNMPERR_MALLOC;
        goto out;
    }
    memcpy(result, packet + packet_len - offset, offset);
    *result_len = offset;

out:
    free(packet);
    if (pdu != NULL) {
        snmp_free_pdu(pdu);
    }
    // fixture_user is non-NULL only when this invocation created it (a
    // pre-existing user is rejected above), so removal cannot free foreign
    // state. The engine-time entry set above is left in place deliberately:
    // free_enginetime clears every entry in its hash bucket, including
    // unrelated colliding engine IDs, and a repeat invocation overwrites the
    // entry via set_enginetime anyway.
    if (fixture_user != NULL) {
        usm_remove_user(fixture_user);
        fixture_user->next = NULL;
        fixture_user->prev = NULL;
        usm_free_user(fixture_user);
    }
    return result;
}
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

var (
	initV3ReportFixtureGenerator sync.Once
	v3ReportFixtureGeneratorMu   sync.Mutex
)

func netSnmpV3ReportFixture(kind int) ([]byte, error) {
	initV3ReportFixtureGenerator.Do(func() { C.init_v3_report_fixture_generator() })
	v3ReportFixtureGeneratorMu.Lock()
	defer v3ReportFixtureGeneratorMu.Unlock()

	// The build rejects a packet whose encoding crossed the next engine-time
	// second (the encoded time TLV no longer matches the value set
	// immediately beforehand). A scheduler pause can trigger that on an
	// otherwise valid run, so retry this specific condition a few times.
	var errorCode C.int
	for range 5 {
		var resultLen C.size_t
		result := C.build_v3_report_fixture(C.int(kind), &resultLen, &errorCode)
		if result != nil {
			packet := C.GoBytes(unsafe.Pointer(result), C.int(resultLen))
			C.free(unsafe.Pointer(result))
			return packet, nil
		}
		if errorCode != C.SNMPERR_USM_NOTINTIMEWINDOW {
			break
		}
	}
	return nil, fmt.Errorf("libsnmp v3 REPORT build failed: %d", int(errorCode))
}
