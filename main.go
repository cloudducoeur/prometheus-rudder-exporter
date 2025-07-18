package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	listenAddress = flag.String("web.listen-address", ":9091", "Address to listen on for web interface and telemetry.")
	rudderURL     = flag.String("rudder.url", "", "URL of the Rudder API.")
	apiToken      = flag.String("rudder.api-token", "", "Token for the Rudder API.")
)

func main() {
	flag.Parse()

	if *rudderURL == "" {
		log.Fatal("Rudder URL is required. Use -rudder.url flag.")
	}

	if *apiToken == "" {
		log.Fatal("Rudder API token is required. Use -rudder.api-token flag.")
	}

	log.Println("Starting Rudder exporter")

	// Create a new collector.
	collector := newCollector(*rudderURL, *apiToken)
	prometheus.MustRegister(collector)

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><head><title>Rudder Exporter</title></head><body><h1>Rudder Exporter</h1><p><a href='/metrics'>Metrics</a></p></body></html>`))
	})

	log.Printf("Listening on %s", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
