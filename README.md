gosnmp
======

GoSNMP is a simple SNMP client library, written fully in Go. Currently it supports only GetRequest (with the rest GetNextRequest, SetRequest in the pipe line). Support for traps is also in the plans.


Install
-------

The easiest way to install is via go get:

    go get github.com/alouca/gosnmp

License
-------

Some parts of the code are borrowed by the Golang project (specifically some functions for unmarshaling BER responses), which are under the same terms and conditions as the Go language, which are marked appropriately in the source code. The rest of the code is under the BSD license.

See the LICENSE file for more details.

Usage
-----
The library usage is pretty simple:

    s := gosnmp.NewGoSNMP("192.168.0.1", "public", gosnmp.Version2c)
    resp, err := s.Get(".1.3.6.1.2.1.1.1.0")

    if err == nil {
      switch resp.Type {
        case OctetString:
          fmt.Printf("Response: %s\n", string(resp.Value))
      }
    }

The response value is always given as an interface{} depending on the PDU response from the SNMP server. For an example checkout examples/example.go.

Responses are a struct of the following format:

    type Variable struct {
      Name  asn1.ObjectIdentifier
      Type  Asn1BER
      Value interface{}
    }

Where Name is the OID encoded as an object identifier, Type is the encoding type of the response and Value is an interface{} type, with the response appropriately decoded.

SNMP BER Types can be one of the following:

    type Asn1BER byte

    const (
        EndOfContents    Asn1BER = 0x00
        Boolean                  = 0x01
        Integer                  = 0x02
        BitString                = 0x03
        OctetString              = 0x04
        Null                     = 0x05
        ObjectIdentifier         = 0x06
        ObjectDesription         = 0x07
        IpAddress                = 0x40
        Counter32                = 0x41
        Gauge32                  = 0x42
        TimeTicks                = 0x43
        Opaque                   = 0x44
        NsapAddress              = 0x45
        Counter64                = 0x46
        Uinteger32               = 0x47
        NoSuchObject             = 0x80
        NoSuchInstance           = 0x81
    )

GoSNMP supports most of the above values, subsequent releases will support all of them.

Testing
-------

Many, many thanks to Andreas Louca for writing **alouca/gosnmp**. The major
difference between his version and **soniah/gosnmp** is that the latter has
tests written. (However the code could do with refactoring). The tests were
used to find and correct errors in the following SNMP BER Types:

* Counter32
* Gauge32
* Counter64
* OctetString
* ObjectIdentifier
* IpAddress

Also, this version contains functions for treating the returned snmp values as
`*big.Int` (convenient, as SNMP can return int32, uint32, and uint64 values):

    func ToBigInt(value interface{}) *big.Int

Running the Tests
-----------------

The tests use the Verax Snmp Simulator [1]; setup Verax before running "go test":

* download, install and run Verax with the default configuration

* in the gosnmp directory, setup these symlinks (or equivalents for your system):

    ln -s /usr/local/vxsnmpsimulator/device device
    ln -s /usr/local/vxsnmpsimulator/conf/devices.conf.xml devices.conf.xml

* remove randomising elements from Verax device files:

    cd device/cisco
    sed -i -e 's!\/\/\$.*!!' -e 's!^M!!' cisco_router.txt
    sed -i -e 's/\/\/\^int.unq()\^\/\//2/' cisco_router.txt
    cd ../os
    sed -i -e 's!\/\/\$.*!!' -e 's!^M!!' os-linux-std.txt
    sed -i -e 's/\/\/\^int.unq()\^\/\//2/' os-linux-std.txt

[1] http://www.veraxsystems.com/en/products/snmpsimulator
