gosnmp
======

GoSNMP is a simple SNMP client library, written fully in Go. Currently it supports only GetRequest (with the rest GetNextRequest, SetRequest in the pipe line). Support for traps is also in the plans.

Usage
-----
The library usage is pretty simple:

  s := gosnmp.NewGoSNMP("192.168.0.1", "public", 1)
  resp := s.Get(".1.3.6.1.2.1.1.1.0")

The response is always given as an interface{} depending on the response.