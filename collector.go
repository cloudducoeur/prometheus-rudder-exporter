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
	up                      *prometheus.Desc
	globalCompliance        *prometheus.Desc
	nodesTotal              *prometheus.Desc
	pendingNodesTotal       *prometheus.Desc
	groupsTotal             *prometheus.Desc
	rulesTotal              *prometheus.Desc
	directivesTotal         *prometheus.Desc
	nodeCompliance          *prometheus.Desc
	cvesTotal               *prometheus.Desc
	nodeVulnerabilities     *prometheus.Desc
	campaignInfo            *prometheus.Desc
	campaignEventsScheduled *prometheus.Desc
	campaignEventsRunning   *prometheus.Desc
	campaignEventsFinished  *prometheus.Desc
	campaignEventsSkipped   *prometheus.Desc
	campaignEventDetails    *prometheus.Desc
	campaignsSystemUpdate   *prometheus.Desc
	campaignsSoftwareUpdate *prometheus.Desc
	campaignsTotal          *prometheus.Desc
	pluginsTotal            *prometheus.Desc
	pluginsEnabled          *prometheus.Desc
	pluginsDisabled         *prometheus.Desc
	pluginInfo              *prometheus.Desc
}

// newCollector creates a new Collector.
func newCollector(rudderURL, apiToken string, insecure bool) *Collector {
	return &Collector{
		rudderURL:               rudderURL,
		apiToken:                apiToken,
		client:                  NewRudderClient(rudderURL, apiToken, insecure),
		up:                      prometheus.NewDesc("rudder_up", "Wether the Rudder API is up.", nil, nil),
		globalCompliance:        prometheus.NewDesc("rudder_global_compliance", "Global compliance percentage.", nil, nil),
		nodesTotal:              prometheus.NewDesc("rudder_nodes_total", "Total number of nodes.", nil, nil),
		pendingNodesTotal:       prometheus.NewDesc("rudder_pending_nodes_total", "Total number of pending nodes.", nil, nil),
		groupsTotal:             prometheus.NewDesc("rudder_groups_total", "Total number of groups.", nil, nil),
		rulesTotal:              prometheus.NewDesc("rudder_rules_total", "Total number of rules.", nil, nil),
		directivesTotal:         prometheus.NewDesc("rudder_directives_total", "Total number of directives.", nil, nil),
		nodeCompliance:          prometheus.NewDesc("rudder_node_compliance", "Compliance per node.", []string{"node_id", "node_hostname"}, nil),
		cvesTotal:               prometheus.NewDesc("rudder_cves_total", "Total number of CVEs.", nil, nil),
		nodeVulnerabilities:     prometheus.NewDesc("rudder_node_vulnerabilities", "Vulnerabilities per node.", []string{"node_id", "node_hostname"}, nil),
		campaignInfo:            prometheus.NewDesc("rudder_campaign_info", "Campaign info.", []string{"campaign_id", "campaign_name"}, nil),
		campaignEventsScheduled: prometheus.NewDesc("rudder_campaign_events_scheduled_total", "Total number of scheduled campaign events.", nil, nil),
		campaignEventsRunning:   prometheus.NewDesc("rudder_campaign_events_running_total", "Total number of running campaign events.", nil, nil),
		campaignEventsFinished:  prometheus.NewDesc("rudder_campaign_events_finished_total", "Total number of finished campaign events.", nil, nil),
		campaignEventsSkipped:   prometheus.NewDesc("rudder_campaign_events_skipped_total", "Total number of skipped campaign events.", nil, nil),
		campaignEventDetails:    prometheus.NewDesc("rudder_campaign_event_info", "Campaign event details.", []string{"event_id", "campaign_id", "event_name", "event_type", "state"}, nil),
		campaignsSystemUpdate:   prometheus.NewDesc("rudder_campaigns_system_update_total", "Total number of system-update campaigns.", nil, nil),
		campaignsSoftwareUpdate: prometheus.NewDesc("rudder_campaigns_software_update_total", "Total number of software-update campaigns.", nil, nil),
		campaignsTotal:          prometheus.NewDesc("rudder_campaigns_total", "Total number of campaigns.", nil, nil),
		pluginsTotal:            prometheus.NewDesc("rudder_plugins_total", "Total number of plugins.", nil, nil),
		pluginsEnabled:          prometheus.NewDesc("rudder_plugins_enabled_total", "Total number of enabled plugins.", nil, nil),
		pluginsDisabled:         prometheus.NewDesc("rudder_plugins_disabled_total", "Total number of disabled plugins.", nil, nil),
		pluginInfo:              prometheus.NewDesc("rudder_plugin_info", "Plugin information.", []string{"plugin_id", "plugin_name", "version", "enabled"}, nil),
	}
}

// Describe implements the prometheus.Collector interface.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.up
	ch <- c.globalCompliance
	ch <- c.nodesTotal
	ch <- c.pendingNodesTotal
	ch <- c.groupsTotal
	ch <- c.rulesTotal
	ch <- c.directivesTotal
	ch <- c.nodeCompliance
	ch <- c.campaignEventsScheduled
	ch <- c.campaignEventsRunning
	ch <- c.campaignEventsFinished
	ch <- c.campaignEventsSkipped
	ch <- c.campaignEventDetails
	ch <- c.campaignsSystemUpdate
	ch <- c.campaignsSoftwareUpdate
	ch <- c.campaignsTotal
	ch <- c.pluginsTotal
	ch <- c.pluginsEnabled
	ch <- c.pluginsDisabled
	ch <- c.pluginInfo
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

	// Groups
	groups, err := c.client.GetGroups()
	if err != nil {
		log.Printf("Error getting groups: %s", err)
		up = 0
	} else {
		ch <- prometheus.MustNewConstMetric(c.groupsTotal, prometheus.GaugeValue, float64(len(groups)))
	}

	// Campaign Events - Scheduled
	scheduledEvents, err := c.client.GetScheduledCampaignEvents()
	if err != nil {
		log.Printf("Error getting scheduled campaign events: %s", err)
		up = 0
	} else {
		ch <- prometheus.MustNewConstMetric(c.campaignEventsScheduled, prometheus.GaugeValue, float64(len(scheduledEvents)))
	}

	// Campaign Events - Running
	runningEvents, err := c.client.GetRunningCampaignEvents()
	if err != nil {
		log.Printf("Error getting running campaign events: %s", err)
		up = 0
	} else {
		ch <- prometheus.MustNewConstMetric(c.campaignEventsRunning, prometheus.GaugeValue, float64(len(runningEvents)))
	}

	// Campaign Events - Finished
	finishedEvents, err := c.client.GetFinishedCampaignEvents()
	if err != nil {
		log.Printf("Error getting finished campaign events: %s", err)
		up = 0
	} else {
		ch <- prometheus.MustNewConstMetric(c.campaignEventsFinished, prometheus.GaugeValue, float64(len(finishedEvents)))
	}

	// Campaign Events - Skipped
	skippedEvents, err := c.client.GetSkippedCampaignEvents()
	if err != nil {
		log.Printf("Error getting skipped campaign events: %s", err)
		up = 0
	} else {
		ch <- prometheus.MustNewConstMetric(c.campaignEventsSkipped, prometheus.GaugeValue, float64(len(skippedEvents)))
	}

	// Campaign Event Details - Simplified approach with basic event info
	// Note: Individual event detail API appears unreliable, so we provide basic info only
	allEventIDs := make(map[string]string) // ID -> State

	for _, event := range scheduledEvents {
		if event.ID != "" && event.State.Value != "" {
			allEventIDs[event.ID] = event.State.Value
		}
	}
	for _, event := range runningEvents {
		if event.ID != "" && event.State.Value != "" {
			allEventIDs[event.ID] = event.State.Value
		}
	}
	for _, event := range finishedEvents {
		if event.ID != "" && event.State.Value != "" {
			allEventIDs[event.ID] = event.State.Value
		}
	}
	for _, event := range skippedEvents {
		if event.ID != "" && event.State.Value != "" {
			allEventIDs[event.ID] = event.State.Value
		}
	}

	// Create basic info metrics for each unique event
	for eventID, state := range allEventIDs {
		ch <- prometheus.MustNewConstMetric(
			c.campaignEventDetails,
			prometheus.GaugeValue,
			1,
			eventID,
			"not_available", // campaign_id - API detail endpoint unreliable
			"not_available", // event_name - API detail endpoint unreliable
			"not_available", // event_type - API detail endpoint unreliable
			state,
		)
	}

	// Campaigns by Type
	systemUpdateCampaigns, err := c.client.GetSystemUpdateCampaigns()
	if err != nil {
		log.Printf("Error getting system-update campaigns: %s", err)
		up = 0
	} else {
		ch <- prometheus.MustNewConstMetric(c.campaignsSystemUpdate, prometheus.GaugeValue, float64(len(systemUpdateCampaigns)))
	}

	softwareUpdateCampaigns, err := c.client.GetSoftwareUpdateCampaigns()
	if err != nil {
		log.Printf("Error getting software-update campaigns: %s", err)
		up = 0
	} else {
		ch <- prometheus.MustNewConstMetric(c.campaignsSoftwareUpdate, prometheus.GaugeValue, float64(len(softwareUpdateCampaigns)))
	}

	// All Campaigns
	allCampaigns, err := c.client.GetAllCampaigns()
	if err != nil {
		log.Printf("Error getting all campaigns: %s", err)
		up = 0
	} else {
		ch <- prometheus.MustNewConstMetric(c.campaignsTotal, prometheus.GaugeValue, float64(len(allCampaigns)))
	}

	// Plugins
	plugins, err := c.client.GetPlugins()
	if err != nil {
		log.Printf("Error getting plugins: %s", err)
		// Don't set up = 0 for plugins error as it may not be available on all instances
		// Set default values for plugin metrics
		ch <- prometheus.MustNewConstMetric(c.pluginsTotal, prometheus.GaugeValue, 0)
		ch <- prometheus.MustNewConstMetric(c.pluginsEnabled, prometheus.GaugeValue, 0)
		ch <- prometheus.MustNewConstMetric(c.pluginsDisabled, prometheus.GaugeValue, 0)
	} else {
		ch <- prometheus.MustNewConstMetric(c.pluginsTotal, prometheus.GaugeValue, float64(len(plugins)))
		
		// Count enabled and disabled plugins
		enabledCount := 0
		disabledCount := 0
		for _, plugin := range plugins {
			if plugin.Enabled {
				enabledCount++
			} else {
				disabledCount++
			}
			
			// Create plugin info metric
			enabledStr := "false"
			if plugin.Enabled {
				enabledStr = "true"
			}
			ch <- prometheus.MustNewConstMetric(
				c.pluginInfo,
				prometheus.GaugeValue,
				1,
				plugin.ID,
				plugin.Name,
				plugin.Version,
				enabledStr,
			)
		}
		
		ch <- prometheus.MustNewConstMetric(c.pluginsEnabled, prometheus.GaugeValue, float64(enabledCount))
		ch <- prometheus.MustNewConstMetric(c.pluginsDisabled, prometheus.GaugeValue, float64(disabledCount))
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
