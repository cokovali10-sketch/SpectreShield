//go:build linux

package sigma

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Rule struct {
	Title         string            `json:"title"`
	ID            string            `json:"id"`
	Status        string            `json:"status"`
	Description   string            `json:"description"`
	References    []string          `json:"references,omitempty"`
	Author        string            `json:"author"`
	Date          string            `json:"date"`
	Modified      string            `json:"modified,omitempty"`
	Tags          []string          `json:"tags"`
	Logsource     Logsource         `json:"logsource"`
	Detection     Detection         `json:"detection"`
	FalsePositives []string         `json:"falsepositives,omitempty"`
	Level         string            `json:"level"`
	MITRE         string            `json:"mitre,omitempty"`
}

type Logsource struct {
	Category string `json:"category"`
	Product  string `json:"product"`
	Service  string `json:"service"`
}

type Detection struct {
	Selection Selection `json:"selection"`
	Condition string    `json:"condition"`
}

type Selection map[string]interface{}

type Match struct {
	Rule      Rule                   `json:"rule"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	Fields    map[string]interface{} `json:"fields"`
}

type Engine struct {
	rules []*Rule
	mu    sync.RWMutex
}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) LoadRules(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
			return e.LoadRuleFile(path)
		}
		return nil
	})
}

func (e *Engine) LoadRuleFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var rule Rule
	if err := json.Unmarshal(data, &rule); err != nil {
		return err
	}
	e.mu.Lock()
	e.rules = append(e.rules, &rule)
	e.mu.Unlock()
	return nil
}

func (e *Engine) Match(event map[string]interface{}) []*Match {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matches []*Match
	for _, rule := range e.rules {
		if e.evaluateRule(rule, event) {
			matches = append(matches, &Match{
				Rule:      *rule,
				Timestamp: time.Now(),
				Fields:    event,
			})
		}
	}
	return matches
}

func (e *Engine) evaluateRule(rule *Rule, event map[string]interface{}) bool {
	for key, val := range rule.Detection.Selection {
		eventVal, ok := event[key]
		if !ok {
			return false
		}
		switch v := val.(type) {
		case string:
			if fmt.Sprintf("%v", eventVal) != v {
				return false
			}
		case []interface{}:
			match := false
			for _, sv := range v {
				if fmt.Sprintf("%v", eventVal) == fmt.Sprintf("%v", sv) {
					match = true
					break
				}
			}
			if !match {
				return false
			}
		}
	}
	return true
}

func (e *Engine) GetRules() []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*Rule, len(e.rules))
	copy(result, e.rules)
	return result
}

// Add built-in Sigma rules for common detection scenarios
func (e *Engine) LoadBuiltinRules() {
	builtins := []*Rule{
		{Title: "Suspicious Process Execution", ID: "sigma-001", Status: "experimental", Description: "Detects suspicious process execution patterns", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"process", "execution"}, Logsource: Logsource{Category: "process_creation"}, Detection: Detection{Selection: Selection{"CommandLine|contains": []interface{}{"cmd.exe /c", "powershell -enc", "bash -c"}}, Condition: "selection"}, Level: "high", MITRE: "T1059"},
		{Title: "Suspicious Network Connection", ID: "sigma-002", Status: "experimental", Description: "Detects suspicious outbound network connections", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"network", "connection"}, Logsource: Logsource{Category: "firewall"}, Detection: Detection{Selection: Selection{"action": "allowed", "dst_port|gte": 4444}, Condition: "selection"}, Level: "high", MITRE: "T1071"},
		{Title: "Credential Access Attempt", ID: "sigma-003", Status: "experimental", Description: "Detects credential access attempts", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"credential", "access"}, Logsource: Logsource{Category: "authentication"}, Detection: Detection{Selection: Selection{"status": "failed", "logon_type|gte": 10}, Condition: "selection"}, Level: "high", MITRE: "T1003"},
		{Title: "Privilege Escalation via Sudo", ID: "sigma-004", Status: "experimental", Description: "Detects privilege escalation via sudo", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"privilege_escalation", "sudo"}, Logsource: Logsource{Category: "process_creation"}, Detection: Detection{Selection: Selection{"user": "root", "command|contains": "sudo"}, Condition: "selection"}, Level: "high", MITRE: "T1548"},
		{Title: "Lateral Movement via SSH", ID: "sigma-005", Status: "experimental", Description: "Detects lateral movement via SSH", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"lateral_movement", "ssh"}, Logsource: Logsource{Category: "authentication"}, Detection: Detection{Selection: Selection{"service": "ssh", "status": "accepted"}, Condition: "selection"}, Level: "medium", MITRE: "T1021.004"},
		{Title: "Malware C2 Communication", ID: "sigma-006", Status: "experimental", Description: "Detects C2 communication patterns", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"malware", "c2"}, Logsource: Logsource{Category: "network"}, Detection: Detection{Selection: Selection{"dst_port": 443, "bytes_out|gte": 1048576}, Condition: "selection"}, Level: "critical", MITRE: "T1071.001"},
		{Title: "Data Exfiltration via DNS", ID: "sigma-007", Status: "experimental", Description: "Detects data exfiltration via DNS tunneling", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"exfiltration", "dns"}, Logsource: Logsource{Category: "dns"}, Detection: Detection{Selection: Selection{"query_length|gte": 50}, Condition: "selection"}, Level: "high", MITRE: "T1048"},
		{Title: "Persistence via Cron Job", ID: "sigma-008", Status: "experimental", Description: "Detects cron-based persistence", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"persistence", "cron"}, Logsource: Logsource{Category: "process_creation"}, Detection: Detection{Selection: Selection{"command|contains": []interface{}{"crontab", "/etc/cron"}}, Condition: "selection"}, Level: "high", MITRE: "T1053.003"},
		{Title: "Defense Evasion via Log Clearing", ID: "sigma-009", Status: "experimental", Description: "Detects log clearing for defense evasion", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"defense_evasion", "logs"}, Logsource: Logsource{Category: "process_creation"}, Detection: Detection{Selection: Selection{"command|contains": []interface{}{"history -c", "truncate -s 0", "echo >"}}, Condition: "selection"}, Level: "high", MITRE: "T1070"},
		{Title: "Suspicious PowerShell Execution", ID: "sigma-010", Status: "experimental", Description: "Detects suspicious PowerShell execution", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"execution", "powershell"}, Logsource: Logsource{Category: "process_creation"}, Detection: Detection{Selection: Selection{"image|endswith": "powershell.exe", "command|contains": []interface{}{"-enc", "-e ", "downloadstring", "invoke-expression"}}, Condition: "selection"}, Level: "critical", MITRE: "T1059.001"},
		{Title: "Container Escape Attempt", ID: "sigma-011", Status: "experimental", Description: "Detects container escape attempts", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"container", "escape"}, Logsource: Logsource{Category: "container"}, Detection: Detection{Selection: Selection{"command|contains": []interface{}{"nsenter", "docker exec", "/var/run/docker.sock"}}, Condition: "selection"}, Level: "critical", MITRE: "T1611"},
		{Title: "Kernel Module Load", ID: "sigma-012", Status: "experimental", Description: "Detects kernel module loading", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"persistence", "kernel"}, Logsource: Logsource{Category: "kernel"}, Detection: Detection{Selection: Selection{"action": "load_module"}, Condition: "selection"}, Level: "high", MITRE: "T1547.006"},
		{Title: "File Permission Change", ID: "sigma-013", Status: "experimental", Description: "Detects suspicious file permission changes", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"persistence", "file"}, Logsource: Logsource{Category: "file_event"}, Detection: Detection{Selection: Selection{"command|contains": []interface{}{"chmod +s", "chmod 777", "chown root"}}, Condition: "selection"}, Level: "high", MITRE: "T1548"},
		{Title: "Suspicious Registry Activity", ID: "sigma-014", Status: "experimental", Description: "Detects suspicious registry modifications", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"persistence", "registry"}, Logsource: Logsource{Category: "registry"}, Detection: Detection{Selection: Selection{"target_object|contains": []interface{}{"RunOnce", "Run", "Services"}}, Condition: "selection"}, Level: "high", MITRE: "T1547.001"},
		{Title: "Network Scan Detected", ID: "sigma-015", Status: "experimental", Description: "Detects network scanning activity", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"discovery", "network"}, Logsource: Logsource{Category: "firewall"}, Detection: Detection{Selection: Selection{"action": "allowed", "dst_port|gte": 1, "dst_port|lte": 65535}, Condition: "selection"}, Level: "medium", MITRE: "T1046"},
		{Title: "Reverse Shell Detected", ID: "sigma-016", Status: "experimental", Description: "Detects reverse shell patterns", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"execution", "reverse_shell"}, Logsource: Logsource{Category: "process_creation"}, Detection: Detection{Selection: Selection{"command|contains": []interface{}{"/dev/tcp/", "bash -i", "nc -e", "ncat -e"}}, Condition: "selection"}, Level: "critical", MITRE: "T1059.004"},
		{Title: "Suspicious Scheduled Task", ID: "sigma-017", Status: "experimental", Description: "Detects suspicious scheduled task creation", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"persistence", "scheduled_task"}, Logsource: Logsource{Category: "process_creation"}, Detection: Detection{Selection: Selection{"command|contains": []interface{}{"schtasks", "at ", "crontab -e"}}, Condition: "selection"}, Level: "high", MITRE: "T1053"},
		{Title: "Suspicious File Download", ID: "sigma-018", Status: "experimental", Description: "Detects suspicious file download patterns", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"execution", "download"}, Logsource: Logsource{Category: "process_creation"}, Detection: Detection{Selection: Selection{"command|contains": []interface{}{"wget ", "curl ", "Invoke-WebRequest"}}, Condition: "selection"}, Level: "medium", MITRE: "T1105"},
		{Title: "Suspicious LDAP Query", ID: "sigma-019", Status: "experimental", Description: "Detects suspicious LDAP queries for recon", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"discovery", "ldap"}, Logsource: Logsource{Category: "network"}, Detection: Detection{Selection: Selection{"dst_port": 389, "query|contains": "objectClass"}, Condition: "selection"}, Level: "medium", MITRE: "T1018"},
		{Title: "Suspicious WMI Activity", ID: "sigma-020", Status: "experimental", Description: "Detects suspicious WMI activity", Author: "SpectreShield", Date: "2024-01-01", Tags: []string{"execution", "wmi"}, Logsource: Logsource{Category: "process_creation"}, Detection: Detection{Selection: Selection{"image|endswith": "wmiprvse.exe", "command|contains": []interface{}{"process call create", "Win32_Process"}}, Condition: "selection"}, Level: "high", MITRE: "T1047"},
	}
	for _, rule := range builtins {
		e.AddRule(rule)
	}
}

// AddRule adds a rule to the engine
func (e *Engine) AddRule(rule *Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// RemoveRule removes a rule by ID
func (e *Engine) RemoveRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, rule := range e.rules {
		if rule.ID == id {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			return true
		}
	}
	return false
}

// GetRule returns a rule by ID
func (e *Engine) GetRule(id string) *Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, rule := range e.rules {
		if rule.ID == id {
			return rule
		}
	}
	return nil
}

// GetRuleCount returns the number of rules
func (e *Engine) GetRuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// MatchBatch matches multiple events against rules
func (e *Engine) MatchBatch(events []map[string]interface{}) []*Match {
	var allMatches []*Match
	for _, event := range events {
		matches := e.Match(event)
		allMatches = append(allMatches, matches...)
	}
	return allMatches
}

// FilterBySeverity returns rules matching the given severity
func (e *Engine) FilterBySeverity(severity string) []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var result []*Rule
	for _, rule := range e.rules {
		if rule.Level == severity {
			result = append(result, rule)
		}
	}
	return result
}

// FilterByTag returns rules matching the given tag
func (e *Engine) FilterByTag(tag string) []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var result []*Rule
	for _, rule := range e.rules {
		for _, t := range rule.Tags {
			if t == tag {
				result = append(result, rule)
				break
			}
		}
	}
	return result
}

// ExportRules exports all rules to JSON
func (e *Engine) ExportRules(path string) error {
	data, err := json.MarshalIndent(e.rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ImportRules imports rules from JSON
func (e *Engine) ImportRules(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var rules []*Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}
	e.mu.Lock()
	e.rules = append(e.rules, rules...)
	e.mu.Unlock()
	return nil
}

// ClearRules removes all rules
func (e *Engine) ClearRules() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = nil
}

// ValidateRule checks if a rule is valid
func (e *Engine) ValidateRule(rule *Rule) error {
	if rule.Title == "" {
		return fmt.Errorf("rule title is required")
	}
	if rule.ID == "" {
		return fmt.Errorf("rule ID is required")
	}
	if rule.Detection.Condition == "" {
		return fmt.Errorf("rule condition is required")
	}
	return nil
}
