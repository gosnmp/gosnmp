FROM debian:trixie-slim

# Install snmpd from distro (includes AES-192/256 support since 5.9.1+dfsg-1)
# See: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=972985
RUN apt-get update && apt-get install -y --no-install-recommends \
    snmpd \
    snmp \
    && rm -rf /var/lib/apt/lists/*

# Copy configuration
COPY snmpd.conf /etc/snmp/snmpd.conf
# Debian snmpd uses /var/lib/snmp/ for persistent storage (createUser directives)
COPY snmpd.users.conf /var/lib/snmp/snmpd.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 161/udp 161/tcp

# Health check verifies snmpd is responding to requests
HEALTHCHECK --interval=500ms --timeout=2s --start-period=3s --retries=10 \
  CMD snmpget -v2c -c public -t 1 localhost 1.3.6.1.2.1.1.1.0 || exit 1

ENTRYPOINT ["/entrypoint.sh"]
