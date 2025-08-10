package main

import (
	"fmt"
	"log"
	"time"

	g "github.com/gosnmp/gosnmp"
)

// This example demonstrates ICMP ping verification (ICMPPingOnConnect) during UDP connection establishment.
// If the ping fails, Connect returns an error.
func main() {
	client := &g.GoSNMP{
		Target:            "192.0.2.10", // enter your target IP
		Port:              161,
		Community:         "public",
		Version:           g.Version2c,
		Timeout:           2 * time.Second,
		Retries:           1,
		Transport:         "udp", // default udp
		ICMPPingOnConnect: true,  // parallel ICMP ping with Connect
		ICMPPrivileged:    true,  // set to true if necessary (requires root/CAP_NET_RAW)
	}

	if err := client.Connect(); err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer client.Close()

	// Let's proceed with a simple GET (sysDescr.0)
	pkt, err := client.Get([]string{".1.3.6.1.2.1.1.1.0"})
	if err != nil {
		log.Fatalf("Get() err: %v", err)
	}

	for i, v := range pkt.Variables {
		fmt.Printf("%d: oid=%s type=%v\n", i, v.Name, v.Type)
		switch v.Type {
		case g.OctetString:
			fmt.Printf("  value=%s\n", string(v.Value.([]byte)))
		default:
			fmt.Printf("  value=%v\n", v.Value)
		}
	}
}
