// Copyright 2020 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

/*

This is an example of a Prometheus endpoing to query SNMP.  We provide prometheus
a cached version of the values so that our SNMP endpoint is not hit should there be
multiple queries over a short period of time.  Too many SNMP queries to older (and
some newer routers) will cause the control plane to stop responding.

To run this, first edit the source to have the correct IP address,

$ go run main.go

then curl the http address like this:

$ curl localhost:8436/metrics
# HELP snmp_about_info SNMP narrative metric with a default value of 1
# TYPE snmp_about_info gauge
snmp_about_info{contact="contact",site="hq",sysServices="1001110",target="10.12.0.1"} 1
# HELP snmp_build_info A metric with a constant '1' value labeled by version, revision, branch, and goversion from which snmp was built.
# TYPE snmp_build_info gauge
snmp_build_info{branch="",goversion="go1.15.2",revision="",version=""} 1
# HELP snmp_response_duration_seconds SNMP packet response latency
# TYPE snmp_response_duration_seconds histogram
snmp_response_duration_seconds_bucket{site="hq",target="10.12.0.1",le="0.0005"} 0
snmp_response_duration_seconds_bucket{site="hq",target="10.12.0.1",le="0.001"} 9
snmp_response_duration_seconds_bucket{site="hq",target="10.12.0.1",le="0.0025"} 10
snmp_response_duration_seconds_bucket{site="hq",target="10.12.0.1",le="0.005"} 10
snmp_response_duration_seconds_bucket{site="hq",target="10.12.0.1",le="0.01"} 10
snmp_response_duration_seconds_bucket{site="hq",target="10.12.0.1",le="0.025"} 10
snmp_response_duration_seconds_bucket{site="hq",target="10.12.0.1",le="0.05"} 10
snmp_response_duration_seconds_bucket{site="hq",target="10.12.0.1",le="0.1"} 10
snmp_response_duration_seconds_bucket{site="hq",target="10.12.0.1",le="0.25"} 10
snmp_response_duration_seconds_bucket{site="hq",target="10.12.0.1",le="0.5"} 10
snmp_response_duration_seconds_bucket{site="hq",target="10.12.0.1",le="1"} 10
snmp_response_duration_seconds_bucket{site="hq",target="10.12.0.1",le="+Inf"} 10
snmp_response_duration_seconds_sum{site="hq",target="10.12.0.1"} 0.007858001
snmp_response_duration_seconds_count{site="hq",target="10.12.0.1"} 10
# HELP snmp_response_latency_seconds SNMP packet response latency
# TYPE snmp_response_latency_seconds gauge
snmp_response_latency_seconds{site="hq",target="10.12.0.1"} 0.000714456 1609641200001

*/

package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	g "github.com/gosnmp/gosnmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
)

func main() {
	// Default is a pointer to a GoSNMP struct that contains sensible defaults
	// eg port 161, community public, etc
	g.Default.Target = "10.12.0.1"
	err := g.Default.Connect()
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer g.Default.Conn.Close()

	// Function handles for collecting metrics on SNMP query latencies.
	var sent time.Time
	g.Default.OnSent = func(x *g.GoSNMP) {
		sent = time.Now()
	}
	g.Default.OnRecv = func(x *g.GoSNMP) {
		ObserveLatency(time.Since(sent).Seconds())
	}

	// Set constant prometheus labels
	snmpLabels["target"] = g.Default.Target
	snmpLabels["site"] = "hq"

	// Configure the prometheus collector
	promInit()

	// Setup http listener to serve prometheus metrics
	http.Handle("/metrics", promhttp.HandlerFor(snmpRegistry, promhttp.HandlerOpts{}))
	go func() {
		if err := http.ListenAndServe(":8436", nil); err != nil {
			log.Fatal("Error starting HTTP server", "err", err)
		}
	}()

	for {
		// We don't want prometheus to query our SNMP endpoints too quickly,
		// so instead we will do our own queries at a defined interval and
		// provide the latest cached value in the collection.  This also helps
		// with making sure that the evaluations have temporal consistency.
		SleepDuration("120s")

		oids := []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}
		result, err2 := g.Default.Get(oids) // Get() accepts up to g.MAX_OIDS
		if err2 != nil {
			log.Fatalf("Get() err: %v", err2)
		}

		snmpInfoLabels := make(map[string]string)
		for i, variable := range result.Variables {
			switch variable.Name {
			case ".1.3.6.1.2.1.1.4.0":
				// Store the contact string into our about labels for parsing
				snmpInfoLabels["contact"] = string(variable.Value.([]byte))
			case ".1.3.6.1.2.1.1.7.0":
				// Store the sysServices into our about labels for parsing
				snmpInfoLabels["sysServices"] = strconv.FormatInt(g.ToBigInt(variable.Value).Int64(), 2)
			default:
				// ... or often you're just interested in numeric values.
				// ToBigInt() will return the Value as a BigInt, for plugging
				// into your calculations.
				fmt.Printf("%d: unmatched oid: %s  value: %v\n", i, variable.Name, variable.Value)
			}

		}

		variableLabels, labelValues := promMap(snmpInfoLabels)
		snmpInfo = prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				"snmp_about_info",
				"SNMP narrative metric with a default value of 1",
				variableLabels, snmpLabels),
			prometheus.GaugeValue, 1, labelValues...,
		)
	}
}

func promMap(inVarLbl map[string]string) (varLbl []string, varVal []string) {
	for k, v := range inVarLbl {
		varLbl = append(varLbl, k)
		varVal = append(varVal, v)
	}
	return
}

func SleepDuration(d string) (next time.Time) {
	// Sleep until the 0 mark on the minute, or interval since epoch
	duration, err := time.ParseDuration(d)
	if err != nil {
		log.Fatalf("Invalid duration: %v", err)
	}
	next = time.Now()
	next = next.Add(time.Duration(duration.Nanoseconds() - ((next.UnixNano()) % duration.Nanoseconds())))
	time.Sleep(time.Until(next))
	return
}

var snmpLatency prometheus.Metric
var snmpInfo prometheus.Metric
var snmpDurationHist prometheus.Histogram
var snmpRegistry = prometheus.NewRegistry()
var snmpLabels = make(map[string]string)

func ObserveLatency(latency float64) {
	// Send latency value to our auto histogram function
	snmpDurationHist.Observe(latency)

	// Record latency value into a gauge metric with timestamp
	snmpLatency = prometheus.NewMetricWithTimestamp(
		time.Now(), prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				"snmp_response_latency_seconds",
				"SNMP packet response latency",
				nil, snmpLabels),
			prometheus.GaugeValue, latency,
		),
	)

}

func promInit() {
	// Create snmp_response_latency_seconds metric for gauge with timestamp
	snmpRegistry.MustRegister(snmpCollectorInterface)

	// Create snmp_response_duration_seconds for a histogram buckets of durations
	snmpDurationHist = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:        "snmp_response_duration_seconds",
			Help:        "SNMP packet response latency",
			ConstLabels: snmpLabels,
			Buckets:     []float64{0.0005, 0.001, 0.0025, .005, .01, .025, .05, .1, .25, .5, 1},
			//Buckets: prometheus.DefBuckets,  // or use the defaults
		},
	)
	snmpRegistry.MustRegister(snmpDurationHist)

	// Collect the local version numbers
	snmpRegistry.MustRegister(version.NewCollector("snmp"))
}

var snmpCollectorInterface = &snmpCollector{}

type snmpCollector struct{}

// Describe implements prometheus.Collector.
func (c *snmpCollector) Describe(ch chan<- *prometheus.Desc) {
	if snmpLatency != nil {
		ch <- snmpLatency.Desc()
	}
	if snmpInfo != nil {
		ch <- snmpInfo.Desc()
	}
}

// Collect implements prometheus.Collector.
func (c *snmpCollector) Collect(ch chan<- prometheus.Metric) {
	if snmpLatency != nil {
		ch <- snmpLatency
	}
	if snmpInfo != nil {
		ch <- snmpInfo
	}
}
