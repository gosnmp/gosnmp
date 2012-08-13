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

    s := gosnmp.NewGoSNMP("192.168.0.1", "public", 1)
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
      Integer          Asn1BER = 0x02
    	BitString                = 0x03
    	OctetString              = 0x04
    	Null                     = 0x05
    	ObjectIdentifier         = 0x06
    	Counter32                = 0x41
    	Gauge32                  = 0x42
    	TimeTicks                = 0x43
    	Opaque                   = 0x44
    	NsapAddress              = 0x45
    	Counter64                = 0x46
    	Uinteger32               = 0x47
    )
    
GoSNMP supports most of the above values, subsequent releases will support all of them.