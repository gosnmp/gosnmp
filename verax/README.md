gosnmp verax tests
==================

Introduction
------------

**soniah/gosnmp** at one stage used the Verax snmp simulator for
testing. With the move to Travis, Verax is deprecated.

This readme is included for reference.

Verax Tests
-----------

The other integration test uses the **Verax Snmp Simulator** [1]: download,
install and run it with the default configuration. Then, in the gosnmp
directory, run these commands (or equivalents for your system):

    cd ~/go/src/github.com/soniah/gosnmp
    ln -s /usr/local/vxsnmpsimulator/device device

    # remove randomising elements from Verax device files
    cd device/cisco
    sed -i -e 's!\/\/\$.*!!' -e 's!^M!!' cisco_router.txt
    sed -i -e 's/\/\/\^int.unq()\^\/\//2/' cisco_router.txt
    cd ../os
    sed -i -e 's!\/\/\$.*!!' -e 's!^M!!' os-linux-std.txt
    sed -i -e 's/\/\/\^int.unq()\^\/\//2/' os-linux-std.txt
    cd ~/go/src/github.com/soniah/gosnmp
    go test

To run only the Verax tests:

    cd verax
    go test

I have noticed that the Verax tests randomly fail when using multi-OID
Get() requests. I believe these bugs come from Verax not GoSNMP.
