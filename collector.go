package main

import (
	"log"

	"github.com/prometheus/client_golang/prometheus"
)

// Collector implements the prometheus.Collector interface.
type Collector struct {
	rudderURL string
	apiToken  string
	client    *RudderClient

	// Metrics
	up                  *prometheus.Desc
	globalCompliance    *prometheus.Desc
	nodesTotal          *prometheus.Desc
	pendingNodesTotal   *prometheus.Desc
	rulesTotal          *prometheus.Desc
	directivesTotal     *prometheus.Desc
	nodeCompliance      *prometheus.Desc
	cvesTotal           *prometheus.Desc
	nodeVulnerabilities *prometheus.Desc
	campaignInfo        *prometheus.Desc
}

// newCollector creates a new Collector.
func newCollector(rudderURL, apiToken string, insecure bool) *Collector {
	return &Collector{
		rudderURL:           rudderURL,
		apiToken:            apiToken,
		client:              NewRudderClient(rudderURL, apiToken, insecure),
		up:                  prometheus.NewDesc("rudder_up", "Wether the Rudder API is up.", nil, nil),
		globalCompliance:    prometheus.NewDesc("rudder_global_compliance", "Global compliance percentage.", nil, nil),
		nodesTotal:          prometheus.NewDesc("rudder_nodes_total", "Total number of nodes.", nil, nil),
		pendingNodesTotal:   prometheus.NewDesc("rudder_pending_nodes_total", "Total number of pending nodes.", nil, nil),
		rulesTotal:          prometheus.NewDesc("rudder_rules_total", "Total number of rules.", nil, nil),
		directivesTotal:     prometheus.NewDesc("rudder_directives_total", "Total number of directives.", nil, nil),
		nodeCompliance:      prometheus.NewDesc("rudder_node_compliance", "Compliance per node.", []string{"node_id", "node_hostname"}, nil),
		cvesTotal:           prometheus.NewDesc("rudder_cves_total", "Total number of CVEs.", nil, nil),
		nodeVulnerabilities: prometheus.NewDesc("rudder_node_vulnerabilities", "Vulnerabilities per node.", []string{"node_id", "node_hostname"}, nil),
		campaignInfo:        prometheus.NewDesc("rudder_campaign_info", "Campaign info.", []string{"campaign_id", "campaign_name"}, nil),
	}
}

// Describe implements the prometheus.Collector interface.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.up
	ch <- c.globalCompliance
	ch <- c.nodesTotal
	ch <- c.pendingNodesTotal
	ch <- c.rulesTotal
	ch <- c.directivesTotal
	ch <- c.nodeCompliance
}

// Collect implements the prometheus.Collector interface.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	log.Println("Collecting metrics from Rudder API")

	up := 1.0

	// Global Compliance
	compliance, err := c.client.GetGlobalCompliance()
	if err != nil {
		log.Printf("Error getting global compliance: %s", err)
		up = 0
	} else {
		ch <- prometheus.MustNewConstMetric(c.globalCompliance, prometheus.GaugeValue, compliance.GlobalCompliance.Compliance)
	}

	// Nodes
	nodes, err := c.client.GetNodes()
	if err != nil {
		log.Printf("Error getting nodes: %s", err)
		up = 0
	} else {
		ch <- prometheus.MustNewConstMetric(c.nodesTotal, prometheus.GaugeValue, float64(len(nodes)))
	}

	// Pending Nodes
	pendingNodes, err := c.client.GetPendingNodes()
	if err != nil {
		log.Printf("Error getting pending nodes: %s", err)
		up = 0
	} else {
		ch <- prometheus.MustNewConstMetric(c.pendingNodesTotal, prometheus.GaugeValue, float64(len(pendingNodes)))
	}

	// Rules
	rules, err := c.client.GetRules()
	if err != nil {
		log.Printf("Error getting rules: %s", err)
		up = 0
	} else {
		ch <- prometheus.MustNewConstMetric(c.rulesTotal, prometheus.GaugeValue, float64(len(rules)))
	}

	// Directives
	directives, err := c.client.GetDirectives()
	if err != nil {
		log.Printf("Error getting directives: %s", err)
		up = 0
	} else {
		ch <- prometheus.MustNewConstMetric(c.directivesTotal, prometheus.GaugeValue, float64(len(directives)))
	}

	// Node Compliance
	nodeCompliance, err := c.client.GetNodeCompliance()
	if err != nil {
		log.Printf("Error getting node compliance: %s", err)
		up = 0
	} else {
		for _, nc := range nodeCompliance {
			ch <- prometheus.MustNewConstMetric(c.nodeCompliance, prometheus.GaugeValue, nc.Compliance, nc.ID, nc.Hostname)
		}
	}

	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, up)
}
