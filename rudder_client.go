package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// RudderClient is the client for the Rudder API.
type RudderClient struct {
	baseURL    string
	apiToken   string
	httpClient *http.Client
}

// NewRudderClient creates a new RudderClient.
func NewRudderClient(baseURL, apiToken string, insecure bool) *RudderClient {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	return &RudderClient{
		baseURL:    strings.TrimSuffix(baseURL, "/"),
		apiToken:   apiToken,
		httpClient: &http.Client{Timeout: 10 * time.Second, Transport: tr},
	}
}

// Generic API response structure
type ApiResponse struct {
	Action string          `json:"action"`
	Result string          `json:"result"`
	Data   json.RawMessage `json:"data"`
}

func (c *RudderClient) newRequest(method, path string) (*http.Request, error) {
	req, err := http.NewRequest(method, fmt.Sprintf("%s%s", c.baseURL, path), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Token", c.apiToken)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// API Structures
type GlobalCompliance struct {
	Compliance float64 `json:"compliance"`
}

type ComplianceResponse struct {
	GlobalCompliance GlobalCompliance `json:"globalCompliance"`
}

type Node struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
}

type Rule struct {
	ID string `json:"id"`
}

type Directive struct {
	ID string `json:"id"`
}

type NodeCompliance struct {
	ID         string  `json:"id"`
	Hostname   string  `json:"name"`
	Compliance float64 `json:"compliance"`
}

type PendingNode struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
}

type Group struct {
	ID string `json:"id"`
}

type CampaignEvent struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

func (c *RudderClient) get(path string, target interface{}) error {
	req, err := c.newRequest("GET", path)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status code: %d", resp.StatusCode)
	}

	apiResp := &ApiResponse{}
	if err := json.NewDecoder(resp.Body).Decode(apiResp); err != nil {
		return err
	}

	if apiResp.Result != "success" {
		return fmt.Errorf("API returned an error: %s", apiResp.Data)
	}

	return json.Unmarshal(apiResp.Data, target)
}

func (c *RudderClient) GetGlobalCompliance() (*ComplianceResponse, error) {
	var compliance ComplianceResponse
	err := c.get("/compliance", &compliance)
	return &compliance, err
}

func (c *RudderClient) GetNodes() ([]Node, error) {
	var nodes struct {
		Nodes []Node `json:"nodes"`
	}
	err := c.get("/nodes?filter[os.name][eq]=Debian", &nodes) // Example filter to get nodes
	return nodes.Nodes, err
}

func (c *RudderClient) GetRules() ([]Rule, error) {
	var rules struct {
		Rules []Rule `json:"rules"`
	}
	err := c.get("/rules", &rules)
	return rules.Rules, err
}

func (c *RudderClient) GetDirectives() ([]Directive, error) {
	var directives struct {
		Directives []Directive `json:"directives"`
	}
	err := c.get("/directives", &directives)
	return directives.Directives, err
}

func (c *RudderClient) GetNodeCompliance() ([]NodeCompliance, error) {
	var compliance struct {
		Nodes []NodeCompliance `json:"nodes"`
	}
	err := c.get("/compliance/nodes", &compliance)
	return compliance.Nodes, err
}

func (c *RudderClient) GetPendingNodes() ([]PendingNode, error) {
	var pendingNodes struct {
		Nodes []PendingNode `json:"nodes"`
	}
	err := c.get("/nodes/pending", &pendingNodes)
	return pendingNodes.Nodes, err
}

func (c *RudderClient) GetGroups() ([]Group, error) {
	var groups struct {
		Groups []Group `json:"groups"`
	}
	err := c.get("/groups", &groups)
	return groups.Groups, err
}

func (c *RudderClient) GetCampaignEventsByState(state string) ([]CampaignEvent, error) {
	var campaignEvents struct {
		CampaignEvents []CampaignEvent `json:"campaignEvents"`
	}
	path := fmt.Sprintf("/campaigns/events?state=%s", state)
	err := c.get(path, &campaignEvents)
	return campaignEvents.CampaignEvents, err
}

func (c *RudderClient) GetScheduledCampaignEvents() ([]CampaignEvent, error) {
	return c.GetCampaignEventsByState("scheduled")
}

func (c *RudderClient) GetRunningCampaignEvents() ([]CampaignEvent, error) {
	return c.GetCampaignEventsByState("running")
}

func (c *RudderClient) GetFinishedCampaignEvents() ([]CampaignEvent, error) {
	return c.GetCampaignEventsByState("finished")
}

func (c *RudderClient) GetSkippedCampaignEvents() ([]CampaignEvent, error) {
	return c.GetCampaignEventsByState("skipped")
}
