#!/bin/sh
set -e

echo "Starting gosnmp e2e test container"
echo "SNMPv2c communities: public (ro), private (rw)"
echo "SNMPv3 users: noAuthNoPrivUser, auth*OnlyUser, auth*Priv{DES,AES}User"

# Run snmpd in foreground with logging to stdout
# Don't use -C as it prevents loading /var/lib/snmp/snmpd.conf (createUser directives)
/usr/sbin/snmpd -f -Lo &
SNMPD_PID=$!

# Wait for snmpd to be responsive (up to 5 seconds)
for i in $(seq 1 50); do
    if snmpget -v2c -c public -t 0.1 localhost 1.3.6.1.2.1.1.1.0 >/dev/null 2>&1; then
        echo "SNMPD_READY"
        break
    fi
    sleep 0.1
done

wait $SNMPD_PID
