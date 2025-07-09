#!/usr/bin/env bash

echo "Using $(snmpd --version | awk /version:/)"
./snmp_users.sh
sed -i -e 's/^agentAddress.*/agentAddress udp:127.0.0.1:1024/' /etc/snmp/snmpd.conf
sed -i -e 's/ localhost / 127.0.0.1 /' /etc/snmp/snmpd.conf
sed -i -e 's/.*trapsink.*//' /etc/snmp/snmpd.conf
sed -i -e 's/.*master\s*agentx//' /etc/snmp/snmpd.conf
snmpd

go test -v -tags helper
go test -v -tags marshal
go test -v -tags misc
go test -v -tags api
go test -v -tags end2end
go test -v -tags trap
go test -v -tags all -race
