module github.com/gosnmp/gosnmp/netsnmp

go 1.24.0

require (
	github.com/google/go-cmp v0.7.0
	github.com/google/gopacket v1.1.19
	github.com/gosnmp/gosnmp v1.43.2
)

require (
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
)

replace github.com/gosnmp/gosnmp => ../
