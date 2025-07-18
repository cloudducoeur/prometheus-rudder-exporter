package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

// Config holds the configuration values.

type Config struct {
	URL           string `yaml:"url"`
	Token         string `yaml:"api-token"`
	ListenAddress string `yaml:"listen-address"`
	Insecure      bool   `yaml:"insecure"`
}

var (
	listenAddress = flag.String("web.listen-address", ":9091", "Address to listen on for web interface and telemetry.")
	configFile    = flag.String("config.file", "/etc/prometheus/prometheus-rudder-exporter.yaml", "Path to the configuration file.")
	rudderURL     = flag.String("rudder.url", "", "URL of the Rudder API (overrides config file).")
	apiToken      = flag.String("rudder.api-token", "", "Token for the Rudder API (overrides config file).")
	insecure      = flag.Bool("insecure", false, "Skip TLS certificate verification.")
)

func main() {
	flag.Parse()

	config := &Config{}

	if *configFile != "" {
		yamlFile, err := os.ReadFile(*configFile)
		if err != nil {
			// If the file doesn't exist, we just ignore it.
			if !os.IsNotExist(err) {
				log.Fatalf("Error reading config file: %s", err)
			}
		} else {
			err = yaml.Unmarshal(yamlFile, config)
			if err != nil {
				log.Fatalf("Error parsing config file: %s", err)
			}
		}
	}

	// Command-line flags override config file values.
	if *rudderURL == "" {
		*rudderURL = config.URL
	}

	if *apiToken == "" {
		*apiToken = config.Token
	}

	if *listenAddress == ":9091" && config.ListenAddress != "" {
		*listenAddress = config.ListenAddress
	}

	if !*insecure {
		*insecure = config.Insecure
	}

	if *rudderURL == "" {
		log.Fatal("Rudder URL is required. It must be provided via the --rudder.url flag or in the configuration file.")
	}

	if *apiToken == "" {
		log.Fatal("Rudder API token is required. It must be provided via the --rudder.api-token flag or in the configuration file.")
	}

	log.Println("Starting Rudder exporter")

	// Create a new collector.
	collector := newCollector(*rudderURL, *apiToken, *insecure)
	prometheus.MustRegister(collector)

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><head><title>Rudder Exporter</title></head><body><h1>Rudder Exporter</h1><p><a href='/metrics'>Metrics</a></p></body></html>`))
	})

	log.Printf("Listening on %s", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
