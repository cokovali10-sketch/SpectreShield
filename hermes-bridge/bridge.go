//go:build linux

package hermesbridge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cokovali10-sketch/SpectreShield/internal/config"
	"github.com/cokovali10-sketch/SpectreShield/internal/logging"
	"github.com/cokovali10-sketch/SpectreShield/internal/types"
)

// Bridge connects SpectreShield to Hermes v5.0 for AI-driven analysis
type Bridge struct {
	cfg     *config.Config
	log     *logging.Logger
	client  *http.Client
	baseURL string
}

// HermesRequest represents a request to Hermes
type HermesRequest struct {
	Prompt    string            `json:"prompt"`
	Context   map[string]string `json:"context,omitempty"`
	Mode      string            `json:"mode"` // "reasoning", "coding", "agent"
	MaxTokens int               `json:"max_tokens,omitempty"`
}

// HermesResponse represents a response from Hermes
type HermesResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
	Error    string `json:"error,omitempty"`
}

// ThreatAnalysis is the AI-generated analysis of a threat
type ThreatAnalysis struct {
	ThreatID      string  `json:"threat_id"`
	Confidence    float64 `json:"confidence"`
	AttackPath    string  `json:"attack_path"`
	Impact        string  `json:"impact"`
	Remediation   string  `json:"remediation"`
	FalsePositive bool    `json:"false_positive"`
	HumanSummary  string  `json:"human_summary"`
}

// RemediationScript is an AI-generated remediation action
type RemediationScript struct {
	ThreatID      string   `json:"threat_id"`
	Actions       []string `json:"actions"`                  // shell commands to execute
	SeccompJSON   string   `json:"seccomp_json,omitempty"`   // seccomp profile
	IptablesRules []string `json:"iptables_rules,omitempty"`
	Description   string   `json:"description"`
	AutoApprove   bool     `json:"auto_approve"`
}

// NewBridge creates a new Hermes bridge
func NewBridge(cfg *config.Config) *Bridge {
	return &Bridge{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Hermes.Timeout,
		},
		baseURL: cfg.Hermes.Endpoint,
	}
}

// IsAvailable checks if Hermes is reachable
func (b *Bridge) IsAvailable() bool {
	resp, err := b.client.Get(b.baseURL + "/api/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// AnalyzeThreat sends threat data to Hermes for AI analysis
func (b *Bridge) AnalyzeThreat(threat *types.Threat, processTree map[uint32]*types.ProcessInfo) (*ThreatAnalysis, error) {
	prompt := fmt.Sprintf(`You are a security analyst AI. Analyze this detected threat and provide:
1. Confidence score (0.0-1.0) that this is a real threat
2. Attack path description
3. Potential impact
4. Recommended remediation
5. Whether this could be a false positive
6. Human-readable summary

THREAT DETECTED:
- Category: %s
- Severity: %d
- PID: %d (PPID: %d)
- Process: %s
- UID: %d
- Description: %s
- Evidence: %s

PROCESS TREE:
%s

Provide your analysis as JSON with keys: confidence, attack_path, impact, remediation, false_positive, human_summary`,
		threat.Category, threat.Severity, threat.PID, threat.PPID,
		threat.Comm, threat.UID, threat.Description, threat.Evidence,
		b.formatProcessTree(processTree),
	)

	resp, err := b.sendRequest(prompt, "reasoning")
	if err != nil {
		return nil, fmt.Errorf("hermes analyze: %w", err)
	}

	var analysis ThreatAnalysis
	if err := json.Unmarshal([]byte(resp), &analysis); err != nil {
		start := bytes.Index([]byte(resp), []byte("{"))
		end := bytes.LastIndex([]byte(resp), []byte("}"))
		if start >= 0 && end > start {
			if err := json.Unmarshal([]byte(resp[start:end+1]), &analysis); err != nil {
				return &ThreatAnalysis{
					ThreatID:     threat.ID,
					Confidence:   0.5,
					HumanSummary: resp,
				}, nil
			}
		} else {
			return &ThreatAnalysis{
				ThreatID:     threat.ID,
				Confidence:   0.5,
				HumanSummary: resp,
			}, nil
		}
	}

	analysis.ThreatID = threat.ID
	return &analysis, nil
}

// GenerateRemediation asks Hermes to generate remediation actions
func (b *Bridge) GenerateRemediation(threat *types.Threat, analysis *ThreatAnalysis) (*RemediationScript, error) {
	prompt := fmt.Sprintf(`You are a Linux security engineer AI. Generate automated remediation for this threat.

THREAT: %s (Category: %s, Severity: %d)
PROCESS: PID %d, %s (UID %d)
ANALYSIS: %s

Generate a JSON response with:
- actions: array of shell commands to contain/remediate
- seccomp_json: optional seccomp profile to apply
- iptables_rules: optional firewall rules
- description: what the remediation does
- auto_approve: false (always require human review for safety)`,
		threat.Description, threat.Category, threat.Severity,
		threat.PID, threat.Comm, threat.UID, analysis.HumanSummary,
	)

	resp, err := b.sendRequest(prompt, "coding")
	if err != nil {
		return nil, fmt.Errorf("hermes remediate: %w", err)
	}

	var script RemediationScript
	if err := json.Unmarshal([]byte(resp), &script); err != nil {
		start := bytes.Index([]byte(resp), []byte("{"))
		end := bytes.LastIndex([]byte(resp), []byte("}"))
		if start >= 0 && end > start {
			json.Unmarshal([]byte(resp[start:end+1]), &script)
		}
	}

	script.ThreatID = threat.ID
	script.AutoApprove = false // Never auto-approve
	return &script, nil
}

// GeneratePostMortem creates a human-readable incident report
func (b *Bridge) GeneratePostMortem(report *types.IncidentReport) (string, error) {
	threatJSON, _ := json.MarshalIndent(report.Threats, "", "  ")

	prompt := fmt.Sprintf(`You are a senior security analyst. Write a professional incident post-mortem for this security event.

INCIDENT ID: %s
HOSTNAME: %s
TIMESTAMP: %s
CONTAINMENT: %s
STATUS: %s

THREATS DETECTED:
%s

ANALYSIS:
%s

Write a clear, professional post-mortem with:
1. Executive Summary (2-3 sentences)
2. Timeline of Events
3. Root Cause Analysis
4. Impact Assessment
5. Containment Actions Taken
6. Recommended Follow-up Actions
7. Lessons Learned`,
		report.ID, report.Hostname, report.Timestamp.Format(time.RFC3339),
		report.ContainmentAction, report.Status,
		string(threatJSON), report.Analysis,
	)

	return b.sendRequest(prompt, "reasoning")
}

// MaintainStateSync syncs behavioral state with Hermes memory
func (b *Bridge) MaintainStateSync(baseline *types.BaselineProfile) error {
	baselineJSON, _ := json.MarshalIndent(baseline, "", "  ")

	prompt := fmt.Sprintf(`You are a security state manager. Store this behavioral baseline in your memory for cross-reboot persistence.

HOSTNAME: %s
LAST UPDATED: %s
SAMPLE COUNT: %d

BASELINE DATA:
%s

Acknowledge that you have stored this baseline. Confirm with a brief summary.`,
		baseline.Hostname, baseline.LastUpdated.Format(time.RFC3339),
		baseline.SampleCount, string(baselineJSON),
	)

	_, err := b.sendRequest(prompt, "agent")
	return err
}

// sendRequest sends a request to Hermes API
func (b *Bridge) sendRequest(prompt string, mode string) (string, error) {
	req := HermesRequest{
		Prompt: prompt,
		Mode:   mode,
	}

	body, _ := json.Marshal(req)
	resp, err := b.client.Post(
		b.baseURL+"/api/chat",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", b.baseURL+"/api/chat", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("hermes returned %d: %s", resp.StatusCode, string(data))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	// Parse SSE response
	lines := bytes.Split(data, []byte("\n"))
	var lastText string
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("data: ")) {
			var msg struct {
				Text string `json:"text"`
				Done bool   `json:"done"`
			}
			if json.Unmarshal(line[6:], &msg) == nil {
				if msg.Text != "" {
					lastText = msg.Text
				}
			}
		}
	}

	if lastText == "" {
		lastText = string(data)
	}

	return lastText, nil
}

func (b *Bridge) formatProcessTree(tree map[uint32]*types.ProcessInfo) string {
	if tree == nil {
		return "(process tree not available)"
	}

	var result string
	for _, info := range tree {
		result += fmt.Sprintf("  PID %d: %s (PPID: %d, UID: %d, Exec: %s)\n",
			info.PID, info.Comm, info.PPID, info.UID, info.ExecPath)
	}
	return result
}
