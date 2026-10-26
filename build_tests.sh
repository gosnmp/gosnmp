#!/usr/bin/env bash

echo "Using $(snmpd --version | awk /version:/)"
./snmp_users.sh
sed -i -e 's/^agentAddress.*/agentAddress udp:127.0.0.1:1024/' /etc/snmp/snmpd.conf
sed -i -e 's/ localhost / 127.0.0.1 /' /etc/snmp/snmpd.conf
sed -i -e 's/.*trapsink.*//' /etc/snmp/snmpd.conf
sed -i -e 's/.*master\s*agentx//' /etc/snmp/snmpd.conf
snmpd

make test
make test-race
