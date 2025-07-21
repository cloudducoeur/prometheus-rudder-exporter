package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
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
	State struct {
		Value string `json:"value"`
	} `json:"state"`
}

type CampaignEventDetail struct {
	ID         string `json:"id"`
	CampaignID string `json:"campaignId"`
	Name       string `json:"name"`
	State      struct {
		Value string `json:"value"`
	} `json:"state"`
	EventType     string `json:"eventType"`
	ScheduledDate string `json:"scheduledDate"`
}

type Campaign struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"campaignType"`
}

type Plugin struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

type CVECheckResponse struct {
	Checks      []CVEData `json:"checks"`
	LastRunDate string    `json:"lastRunDate"`
}

type CVEData struct {
	CVEID string    `json:"cveId"`
	Score CVEScore  `json:"score"`
	Nodes []CVENode `json:"nodes"`
}

type CVEScore struct {
	Value    float64 `json:"value"`
	Severity string  `json:"severity"`
}

type CVENode struct {
	NodeID   string       `json:"nodeId"`
	Packages []CVEPackage `json:"packages"`
}

type CVEPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	FixedIn string `json:"fixedIn"`
}

// Compliance structures for detailed compliance metrics
type DirectiveCompliance struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Compliance float64 `json:"compliance"`
	Mode       string  `json:"mode"`
	PolicyMode string  `json:"policyMode"`
}

type DirectivesComplianceResponse struct {
	Directives []DirectiveCompliance `json:"directives"`
}

type DirectiveDetailCompliance struct {
	ID         string                    `json:"id"`
	Name       string                    `json:"name"`
	Compliance float64                   `json:"compliance"`
	Mode       string                    `json:"mode"`
	PolicyMode string                    `json:"policyMode"`
	Nodes      []NodeDirectiveCompliance `json:"nodes"`
}

type NodeDirectiveCompliance struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Compliance float64 `json:"compliance"`
}

type GroupCompliance struct {
	ID         string                `json:"id"`
	Name       string                `json:"name"`
	Compliance float64               `json:"compliance"`
	Nodes      []NodeGroupCompliance `json:"nodes"`
}

type NodeGroupCompliance struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Compliance float64 `json:"compliance"`
}

type RuleCompliance struct {
	ID         string               `json:"id"`
	Name       string               `json:"name"`
	Compliance float64              `json:"compliance"`
	Mode       string               `json:"mode"`
	Nodes      []NodeRuleCompliance `json:"nodes"`
}

type NodeRuleCompliance struct {
	ID         string                    `json:"id"`
	Name       string                    `json:"name"`
	Compliance float64                   `json:"compliance"`
	Directives []DirectiveRuleCompliance `json:"directives"`
}

type DirectiveRuleCompliance struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Compliance float64 `json:"compliance"`
}

type RulesComplianceResponse struct {
	Rules []RuleCompliance `json:"rules"`
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
	err := c.get("/rudder/api/latest/compliance", &compliance)
	return &compliance, err
}

func (c *RudderClient) GetNodes() ([]Node, error) {
	var nodes struct {
		Nodes []Node `json:"nodes"`
	}
	err := c.get("/rudder/api/latest/nodes", &nodes)
	return nodes.Nodes, err
}

func (c *RudderClient) GetRules() ([]Rule, error) {
	var rules struct {
		Rules []Rule `json:"rules"`
	}
	err := c.get("/rudder/api/latest/rules", &rules)
	return rules.Rules, err
}

func (c *RudderClient) GetDirectives() ([]Directive, error) {
	var directives struct {
		Directives []Directive `json:"directives"`
	}
	err := c.get("/rudder/api/latest/directives", &directives)
	return directives.Directives, err
}

func (c *RudderClient) GetNodeCompliance() ([]NodeCompliance, error) {
	var compliance struct {
		Nodes []NodeCompliance `json:"nodes"`
	}
	err := c.get("/rudder/api/latest/compliance/nodes", &compliance)
	return compliance.Nodes, err
}

func (c *RudderClient) GetPendingNodes() ([]PendingNode, error) {
	var pendingNodes struct {
		Nodes []PendingNode `json:"nodes"`
	}
	err := c.get("/rudder/api/latest/nodes/pending", &pendingNodes)
	return pendingNodes.Nodes, err
}

func (c *RudderClient) GetGroups() ([]Group, error) {
	var groups struct {
		Groups []Group `json:"groups"`
	}
	err := c.get("/rudder/api/latest/groups", &groups)
	return groups.Groups, err
}

func (c *RudderClient) GetCampaignEventsByState(state string) ([]CampaignEvent, error) {
	var campaignEvents struct {
		CampaignEvents []CampaignEvent `json:"campaignEvents"`
	}
	path := fmt.Sprintf("/rudder/api/latest/campaigns/events?state=%s", state)
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

func (c *RudderClient) GetCampaignEventDetail(eventID string) (*CampaignEventDetail, error) {
	var eventDetail CampaignEventDetail
	path := fmt.Sprintf("/rudder/api/latest/campaigns/events/%s", eventID)
	err := c.get(path, &eventDetail)
	return &eventDetail, err
}

func (c *RudderClient) GetAllCampaignEventDetails() ([]CampaignEventDetail, error) {
	// First get all campaign events
	var allEvents struct {
		CampaignEvents []CampaignEvent `json:"campaignEvents"`
	}
	err := c.get("/rudder/api/latest/campaigns/events", &allEvents)
	if err != nil {
		return nil, err
	}

	// Then get details for each event
	var eventDetails []CampaignEventDetail
	for _, event := range allEvents.CampaignEvents {
		detail, err := c.GetCampaignEventDetail(event.ID)
		if err != nil {
			// Log error but continue with other events
			continue
		}
		eventDetails = append(eventDetails, *detail)
	}

	return eventDetails, nil
}

func (c *RudderClient) GetCampaignsByType(campaignType string) ([]Campaign, error) {
	var campaigns struct {
		Campaigns []Campaign `json:"campaigns"`
	}
	path := fmt.Sprintf("/rudder/api/latest/campaigns?campaignType=%s", campaignType)
	err := c.get(path, &campaigns)
	return campaigns.Campaigns, err
}

func (c *RudderClient) GetSystemUpdateCampaigns() ([]Campaign, error) {
	return c.GetCampaignsByType("system-update")
}

func (c *RudderClient) GetSoftwareUpdateCampaigns() ([]Campaign, error) {
	return c.GetCampaignsByType("software-update")
}

func (c *RudderClient) GetAllCampaigns() ([]Campaign, error) {
	var campaigns struct {
		Campaigns []Campaign `json:"campaigns"`
	}
	err := c.get("/rudder/api/latest/campaigns", &campaigns)
	return campaigns.Campaigns, err
}

// GetPlugins returns all plugins information
func (c *RudderClient) GetPlugins() ([]Plugin, error) {
	var plugins struct {
		Plugins []Plugin `json:"plugins"`
	}
	err := c.get("/rudder/api/latest/plugins", &plugins)
	return plugins.Plugins, err
}

// GetLastCVECheck returns the last CVE check information
func (c *RudderClient) GetLastCVECheck() (*CVECheckResponse, error) {
	// Use a more flexible approach to parse the JSON
	var rawResponse map[string]interface{}
	err := c.get("/rudder/api/latest/cve/check/last", &rawResponse)
	if err != nil {
		return nil, err
	}

	// Navigate through the JSON structure manually
	data, ok := rawResponse["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid data structure")
	}

	cveChecks, ok := data["CVEChecks"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid CVEChecks structure")
	}

	// Convert back to our struct
	cveChecksJSON, err := json.Marshal(cveChecks)
	if err != nil {
		return nil, err
	}

	var result CVECheckResponse
	err = json.Unmarshal(cveChecksJSON, &result)
	if err != nil {
		return nil, err
	}

	log.Printf("CVE API Response - Checks count: %d, LastRunDate: %s",
		len(result.Checks), result.LastRunDate)
	return &result, nil
}

// Compliance API methods

// GetDirectivesCompliance returns compliance for all directives
func (c *RudderClient) GetDirectivesCompliance() (*DirectivesComplianceResponse, error) {
	var response DirectivesComplianceResponse
	err := c.get("/rudder/api/latest/compliance/directives", &response)
	return &response, err
}

// GetDirectiveCompliance returns compliance for a specific directive
func (c *RudderClient) GetDirectiveCompliance(directiveID string) (*DirectiveDetailCompliance, error) {
	var response DirectiveDetailCompliance
	path := fmt.Sprintf("/rudder/api/latest/compliance/directives/%s", directiveID)
	err := c.get(path, &response)
	return &response, err
}

// GetNodeGroupCompliance returns compliance for a specific node group (global)
func (c *RudderClient) GetNodeGroupCompliance(groupID string) (*GroupCompliance, error) {
	var response GroupCompliance
	path := fmt.Sprintf("/rudder/api/latest/compliance/nodeGroups/%s", groupID)
	err := c.get(path, &response)
	return &response, err
}

// GetNodeGroupComplianceTarget returns compliance for a specific node group (targeted)
func (c *RudderClient) GetNodeGroupComplianceTarget(groupID string) (*GroupCompliance, error) {
	var response GroupCompliance
	path := fmt.Sprintf("/rudder/api/latest/compliance/nodeGroups/%s/target", groupID)
	err := c.get(path, &response)
	return &response, err
}

// GetRulesCompliance returns compliance for all rules with details
func (c *RudderClient) GetRulesCompliance() (*RulesComplianceResponse, error) {
	var response RulesComplianceResponse
	err := c.get("/rudder/api/latest/compliance/rules", &response)
	return &response, err
}

// GetRuleCompliance returns compliance for a specific rule
func (c *RudderClient) GetRuleCompliance(ruleID string) (*RuleCompliance, error) {
	var response RuleCompliance
	path := fmt.Sprintf("/rudder/api/latest/compliance/rules/%s", ruleID)
	err := c.get(path, &response)
	return &response, err
}
