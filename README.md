gosnmp
======
[![Build Status](https://travis-ci.org/soniah/gosnmp.svg?branch=master)](https://travis-ci.org/soniah/gosnmp)
[![Coverage](http://gocover.io/_badge/github.com/soniah/gosnmp)](http://gocover.io/github.com/soniah/gosnmp)
[![GoDoc](https://godoc.org/github.com/soniah/gosnmp?status.png)](http://godoc.org/github.com/soniah/gosnmp)


GoSNMP is an SNMP client library written fully in Go. Currently it
supports GetRequest, GetNext, GetBulk, Walk (beta, see below), and SetRequest (beta, see below).

About
-----

**soniah/gosnmp** is based on **alouca/gosnmp** - many thanks to Andreas
Louca for starting the project, other contributors (AUTHORS.md) and
these project collaborators:

* Chris Dance ([@codedance](https://github.com/codedance/))
* Nathan Owens ([@virtuallynathan](https://github.com/virtuallynathan/))

Overview
--------

GoSNMP has the following SNMP functions:

* **Get** (single or multiple OIDs)
* **GetNext**
* **GetBulk**
* **Walk** - retrieves a subtree of values using GETNEXT.
* **BulkWalk** - retrieves a subtree of values using GETBULK.
* **Set** (beta - currently supports Integers and OctetStrings)

GoSNMP also has the following helper functions:

* **ToBigInt** - treat returned values as `*big.Int`
* **Partition** - facilitates dividing up large slices of OIDs

**soniah/gosnmp** has diverged from **alouca/gosnmp** - your existing
code will require slight modification:

* the **Get** function has a different method signature
* the **NewGoSNMP** function has been removed, use **Connect** instead
  (see Usage below)
* GoSNMP no longer relies on **alouca/gologger** - you can use your
  logger if it conforms to the simple interface (Print and Printf).
  Otherwise debugging will be discarded (/dev/null).

gosnmp is still under development, therefore API's may change and bugs
will be squashed. Test Driven Development is used - you can help by
sending packet captures (see Packet Captures below). There may be more
than one branch on github. **master** is safe to pull from, other
branches unsafe as history may be rewritten.

Sonia Hamilton, sonia@snowfrog.net, http://blog.snowfrog.net.

Installation
------------

Install via **go get**:

    go get github.com/soniah/gosnmp

Documentation
-------------

See http://godoc.org/github.com/soniah/gosnmp or your local go doc
server for full documentation, as well as the examples.

    cd $GOPATH
    godoc -http=:6060 &
    $preferred_browser http://localhost:6060/pkg &

Usage
-----

Here is code from **example/example.go**, demonstrating how to use GoSNMP:

```go
    // Default is a pointer to a GoSNMP struct that contains sensible defaults
    // eg port 161, community public, etc
    g.Default.Target = "192.168.1.10"
    err := g.Default.Connect()
    if err != nil {
        log.Fatalf("Connect() err: %v", err)
    }
    defer g.Default.Conn.Close()

    oids := []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}
    result, err2 := g.Default.Get(oids) // Get() accepts up to g.MAX_OIDS
    if err2 != nil {
        log.Fatalf("Get() err: %v", err2)
    }

    for i, variable := range result.Variables {
        fmt.Printf("%d: oid: %s ", i, variable.Name)

        // the Value of each variable returned by Get() implements
        // interface{}. You could do a type switch...
        switch variable.Type {
        case g.OctetString:
            bytes := variable.Value.([]bytes)
            fmt.Printf("string: %s\n", string(bytes))
        default:
            // ... or often you're just interested in numeric values.
            // ToBigInt() will return the Value as a BigInt, for plugging
            // into your calculations.
            fmt.Printf("number: %d\n", g.ToBigInt(variable.Value))
        }
    }
```
Running this example gives the following output (from my printer):

    % go run example.go
    0: oid: 1.3.6.1.2.1.1.4.0 string: Administrator
    1: oid: 1.3.6.1.2.1.1.7.0 number: 104

**example/example2.go** is similar to example.go, however is uses a custom
```&GoSNMP``` rather than ```g.Default```.

**example/walkexample.go** demonstrates using ```BulkWalk```.

Bugs
----

The following BER types have been implemented:

* 0x02 Integer
* 0x04 OctetString
* 0x06 ObjectIdentifier
* 0x40 IPAddress (IPv4 & IPv6)
* 0x41 Counter32
* 0x42 Gauge32
* 0x43 TimeTicks
* 0x46 Counter64
* 0x80 NoSuchObject
* 0x81 NoSuchInstance
* 0x82 EndOfMibView

The following (less common) BER types haven't been implemented, as I ran out of
time or haven't been able to find example devices to query:

* 0x00 EndOfContents
* 0x01 Boolean
* 0x03 BitString
* 0x07 ObjectDescription
* 0x44 Opaque
* 0x45 NsapAddress
* 0x47 Uinteger32

Packet Captures
---------------

Please create an issue on GitHub with packet captures (upload them somewhere) containing
samples of the missing BER types, or of any other bugs you find. Please include
2 or 3 examples of the missing/faulty BER type, interspersed with a couple of
other common BER's eg an Integer, a Counter32 ie about 6-8 OIDs.

Create your packet captures in the following way:

Expected output, obtained via an **snmp** command. For example:

    % snmpget -On -v2c -c public 203.50.251.17 1.3.6.1.2.1.1.7.0 \
      1.3.6.1.2.1.2.2.1.2.6 1.3.6.1.2.1.2.2.1.5.3
    .1.3.6.1.2.1.1.7.0 = INTEGER: 78
    .1.3.6.1.2.1.2.2.1.2.6 = STRING: GigabitEthernet0
    .1.3.6.1.2.1.2.2.1.5.3 = Gauge32: 4294967295

A packet capture, obtained while running the snmpget. For example:

    sudo tcpdump -s 0 -i eth0 -w foo.pcap host 203.50.251.17 and port 161

Running the Tests
-----------------

Tests are grouped as follows:

* Unit tests (validating data packing and marshalling):
   * `marshal_test.go`
   * `misc_test.go`
* Public API consistency tests:
   * `gosnmp_api_test.go`
* End-to-end integration tests:
   * `generic_e2e_test.go` - currently disabled
   * (deprecated) Verax tests - see readme in verax directory

The generic end-to-end integration test `generic_e2e_test.go` should
work against any SNMP MIB-2 compliant host (e.g. a router, NAS box, printer).
To use, edit your host file so `gosnmp-test-host` resolves to the system's IP.

To profile cpu usage:

    go test -cpuprofile cpu.out
    go test -c
    go tool pprof gosnmp.test cpu.out

To profile memory usage:

    go test -memprofile mem.out
    go test -c
    go tool pprof gosnmp.test mem.out

To check test coverage:

    go get github.com/axw/gocov/gocov
    go get github.com/matm/gocov-html
    gocov test github.com/soniah/gosnmp | gocov-html > gosnmp.html && firefox gosnmp.html &

License
-------

Some parts of the code are borrowed by the Golang project (specifically some
functions for unmarshaling BER responses), which are under the same terms and
conditions as the Go language. The rest of the code is under a BSD license.

See the LICENSE file for more details.

The remaining code is Copyright 2012-2014 the GoSNMP Authors - see
AUTHORS.md for a list of authors.
