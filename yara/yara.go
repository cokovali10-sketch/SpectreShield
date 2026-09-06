//go:build linux

package yara

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Rule represents a YARA-like detection rule
type Rule struct {
	Name        string          `json:"name"`
	Namespace   string          `json:"namespace"`
	Description string          `json:"description"`
	Author      string          `json:"author"`
	Date        string          `json:"date"`
	Severity    string          `json:"severity"`
	Tags        []string        `json:"tags"`
	Strings     []StringPattern `json:"strings"`
	Condition   string          `json:"condition"`
	MITRE       *MITERMapping   `json:"mitre,omitempty"`
	Enabled     bool            `json:"enabled"`
}

// StringPattern represents a pattern to match
type StringPattern struct {
	Name   string `json:"name"`
	Type   string `json:"type"` // "hex", "text", "regex", "wide", "nocase"
	Value  string `json:"value"`
	Offset int    `json:"offset,omitempty"`
	Length int    `json:"length,omitempty"`
	Nocase bool   `json:"nocase,omitempty"`
}

// MITERMapping maps to MITRE ATT&CK
type MITERMapping struct {
	Technique string `json:"technique"`
	Tactic    string `json:"tactic"`
	ID        string `json:"id"`
	URL       string `json:"url"`
}

// Match represents a rule match
type Match struct {
	Rule      Rule      `json:"rule"`
	File      string    `json:"file"`
	Offset    int       `json:"offset"`
	Matched   string    `json:"matched"`
	Timestamp time.Time `json:"timestamp"`
	MD5       string    `json:"md5"`
	SHA256    string    `json:"sha256"`
}

// Engine is the YARA rule matching engine
type Engine struct {
	rules      map[string]*Rule
	compiledRe map[string]*regexp.Regexp
	mu         sync.RWMutex
	log        *log.Logger
}

// NewEngine creates a new YARA engine
func NewEngine() *Engine {
	return &Engine{
		rules:      make(map[string]*Rule),
		compiledRe: make(map[string]*regexp.Regexp),
		log:        log.New(os.Stdout, "[YARA] ", log.LstdFlags),
	}
}

// LoadRules loads rules from a directory
func (e *Engine) LoadRules(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".yar") || strings.HasSuffix(path, ".yara") {
			return e.LoadRuleFile(path)
		}
		return nil
	})
}

// LoadRuleFile loads rules from a single file
func (e *Engine) LoadRuleFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read rule file: %w", err)
	}

	rules := e.parseRuleFile(string(data))
	for _, rule := range rules {
		e.mu.Lock()
		e.rules[rule.Name] = rule
		for _, sp := range rule.Strings {
			if sp.Type == "regex" {
				re, err := regexp.Compile(sp.Value)
				if err == nil {
					e.compiledRe[rule.Name+":"+sp.Name] = re
				}
			}
		}
		e.mu.Unlock()
		e.log.Printf("Loaded rule: %s (%s)", rule.Name, rule.Namespace)
	}
	return nil
}

func (e *Engine) parseRuleFile(content string) []*Rule {
	var rules []*Rule
	lines := strings.Split(content, "\n")
	var current *Rule

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "rule ") {
			name := strings.TrimPrefix(line, "rule ")
			name = strings.TrimSpace(name)
			name = strings.Split(name, " ")[0]
			current = &Rule{
				Name:    name,
				Enabled: true,
			}
			rules = append(rules, current)
		} else if current != nil && strings.HasPrefix(line, "strings:") {
			// Parse string patterns
		} else if current != nil && strings.HasPrefix(line, "condition:") {
			cond := strings.TrimPrefix(line, "condition:")
			current.Condition = strings.TrimSpace(cond)
		}
	}
	return rules
}

// ScanFile scans a file against all rules
func (e *Engine) ScanFile(path string) ([]*Match, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	md5Hash := md5.Sum(data)
	sha256Hash := sha256.Sum256(data)

	var matches []*Match
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		if e.evaluateRule(rule, data) {
			matches = append(matches, &Match{
				Rule:      *rule,
				File:      path,
				Timestamp: time.Now(),
				MD5:       hex.EncodeToString(md5Hash[:]),
				SHA256:    hex.EncodeToString(sha256Hash[:]),
			})
		}
	}
	return matches, nil
}

func (e *Engine) evaluateRule(rule *Rule, data []byte) bool {
	content := string(data)
	matchCount := 0
	requiredCount := 1

	if rule.Condition != "" {
		if strings.Contains(rule.Condition, "2 of them") {
			requiredCount = 2
		} else if strings.Contains(rule.Condition, "3 of them") {
			requiredCount = 3
		} else if strings.Contains(rule.Condition, "4 of them") {
			requiredCount = 4
		} else if strings.Contains(rule.Condition, "5 of them") {
			requiredCount = 5
		}
	}

	for _, sp := range rule.Strings {
		matched := false
		switch sp.Type {
		case "text":
			if sp.Nocase {
				matched = strings.Contains(strings.ToLower(content), strings.ToLower(sp.Value))
			} else {
				matched = strings.Contains(content, sp.Value)
			}
		case "hex":
			hexBytes, err := hex.DecodeString(sp.Value)
			if err == nil {
				matched = strings.Contains(content, string(hexBytes))
			}
		case "regex":
			re, ok := e.compiledRe[rule.Name+":"+sp.Name]
			if ok {
				matched = re.MatchString(content)
			}
		case "wide":
			wide := strings.Join(strings.Split(sp.Value, ""), "\x00")
			matched = strings.Contains(content, wide)
		case "nocase":
			matched = strings.Contains(strings.ToLower(content), strings.ToLower(sp.Value))
		}
		if matched {
			matchCount++
		}
	}

	return matchCount >= requiredCount
}

// ScanBytes scans bytes against all rules
func (e *Engine) ScanBytes(data []byte, name string) []*Match {
	var matches []*Match
	e.mu.RLock()
	defer e.mu.RUnlock()

	md5Hash := md5.Sum(data)
	sha256Hash := sha256.Sum256(data)

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		if e.evaluateRule(rule, data) {
			matches = append(matches, &Match{
				Rule:      *rule,
				File:      name,
				Timestamp: time.Now(),
				MD5:       hex.EncodeToString(md5Hash[:]),
				SHA256:    hex.EncodeToString(sha256Hash[:]),
			})
		}
	}
	return matches
}

// AddRule adds a rule dynamically
func (e *Engine) AddRule(rule *Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules[rule.Name] = rule
	for _, sp := range rule.Strings {
		if sp.Type == "regex" {
			re, err := regexp.Compile(sp.Value)
			if err == nil {
				e.compiledRe[rule.Name+":"+sp.Name] = re
			}
		}
	}
}

// RemoveRule removes a rule
func (e *Engine) RemoveRule(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.rules, name)
	for key := range e.compiledRe {
		if strings.HasPrefix(key, name+":") {
			delete(e.compiledRe, key)
		}
	}
}

// GetRules returns all rules
func (e *Engine) GetRules() []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rules := make([]*Rule, 0, len(e.rules))
	for _, r := range e.rules {
		rules = append(rules, r)
	}
	return rules
}

// GetMatches returns matches for a file
func (e *Engine) GetMatches(filePath string) ([]*Match, error) {
	return e.ScanFile(filePath)
}

// ExportMatches exports matches to JSON
func (e *Engine) ExportMatches(matches []*Match, path string) error {
	data, err := json.MarshalIndent(matches, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadDefaultRules loads built-in detection rules
func (e *Engine) LoadDefaultRules() {
	defaultRules := []*Rule{
		{
			Name:        "reverse_shell_bash",
			Namespace:   "malware",
			Description: "Detects bash reverse shell patterns",
			Severity:    "critical",
			Tags:        []string{"malware", "reverse_shell"},
			Strings: []StringPattern{
				{Name: "s1", Type: "text", Value: "/bin/sh -i"},
				{Name: "s2", Type: "text", Value: "/bin/bash -i"},
				{Name: "s3", Type: "regex", Value: `/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+`},
			},
			Condition: "any of them",
			MITRE: &MITERMapping{
				Technique: "Command and Scripting Interpreter",
				Tactic:    "Execution",
				ID:        "T1059",
				URL:       "https://attack.mitre.org/techniques/T1059/",
			},
		},
		{
			Name:        "crypto_miner",
			Namespace:   "malware",
			Description: "Detects cryptocurrency mining patterns",
			Severity:    "high",
			Tags:        []string{"malware", "cryptominer"},
			Strings: []StringPattern{
				{Name: "s1", Type: "text", Value: "stratum+tcp://"},
				{Name: "s2", Type: "text", Value: "stratum+ssl://"},
				{Name: "s3", Type: "text", Value: "cryptonight"},
				{Name: "s4", Type: "text", Value: "coinhive"},
				{Name: "s5", Type: "text", Value: "xmr"},
			},
			Condition: "2 of them",
			MITRE: &MITERMapping{
				Technique: "Resource Hijacking",
				Tactic:    "Impact",
				ID:        "T1496",
				URL:       "https://attack.mitre.org/techniques/T1496/",
			},
		},
		{
			Name:        "webshell",
			Namespace:   "malware",
			Description: "Detects web shell patterns",
			Severity:    "critical",
			Tags:        []string{"malware", "webshell"},
			Strings: []StringPattern{
				{Name: "s1", Type: "text", Value: "eval($_"},
				{Name: "s2", Type: "text", Value: "system($_"},
				{Name: "s3", Type: "text", Value: "passthru($_"},
				{Name: "s4", Type: "text", Value: "shell_exec($_"},
				{Name: "s5", Type: "text", Value: "exec($_"},
				{Name: "s6", Type: "text", Value: "base64_decode($_"},
			},
			Condition: "2 of them",
			MITRE: &MITERMapping{
				Technique: "Server Software Component",
				Tactic:    "Persistence",
				ID:        "T1505",
				URL:       "https://attack.mitre.org/techniques/T1505/",
			},
		},
		{
			Name:        "ransomware_note",
			Namespace:   "malware",
			Description: "Detects ransomware note patterns",
			Severity:    "critical",
			Tags:        []string{"malware", "ransomware"},
			Strings: []StringPattern{
				{Name: "s1", Type: "text", Value: "your files have been encrypted"},
				{Name: "s2", Type: "text", Value: "bitcoin wallet"},
				{Name: "s3", Type: "text", Value: "decrypt your files"},
				{Name: "s4", Type: "text", Value: "pay the ransom"},
				{Name: "s5", Type: "text", Value: ".onion"},
			},
			Condition: "2 of them",
			MITRE: &MITERMapping{
				Technique: "Data Encrypted for Impact",
				Tactic:    "Impact",
				ID:        "T1486",
				URL:       "https://attack.mitre.org/techniques/T1486/",
			},
		},
		{
			Name:        "credential_dump",
			Namespace:   "credential_access",
			Description: "Detects credential dumping tools",
			Severity:    "critical",
			Tags:        []string{"credential_access", "lsass"},
			Strings: []StringPattern{
				{Name: "s1", Type: "text", Value: "lsass.exe"},
				{Name: "s2", Type: "text", Value: "mimikatz"},
				{Name: "s3", Type: "text", Value: "sekurlsa"},
				{Name: "s4", Type: "text", Value: "kerberos::list"},
				{Name: "s5", Type: "text", Value: "privilege::debug"},
			},
			Condition: "2 of them",
			MITRE: &MITERMapping{
				Technique: "OS Credential Dumping",
				Tactic:    "Credential Access",
				ID:        "T1003",
				URL:       "https://attack.mitre.org/techniques/T1003/",
			},
		},
		{
			Name:        "keylogger",
			Namespace:   "malware",
			Description: "Detects keylogger patterns",
			Severity:    "critical",
			Tags:        []string{"malware", "keylogger"},
			Strings: []StringPattern{
				{Name: "s1", Type: "text", Value: "XGrabKey"},
				{Name: "s2", Type: "text", Value: "XQueryKeymap"},
				{Name: "s3", Type: "text", Value: "GetAsyncKeyState"},
				{Name: "s4", Type: "text", Value: "ReadConsoleInput"},
				{Name: "s5", Type: "regex", Value: `/dev/input/event`},
			},
			Condition: "2 of them",
			MITRE: &MITERMapping{
				Technique: "Input Capture",
				Tactic:    "Collection",
				ID:        "T1056",
				URL:       "https://attack.mitre.org/techniques/T1056/",
			},
		},
		{
			Name:        "privilege_escalation_sudo",
			Namespace:   "privilege_escalation",
			Description: "Detects sudo privilege escalation attempts",
			Severity:    "high",
			Tags:        []string{"privilege_escalation", "sudo"},
			Strings: []StringPattern{
				{Name: "s1", Type: "text", Value: "sudo su"},
				{Name: "s2", Type: "text", Value: "sudo -i"},
				{Name: "s3", Type: "text", Value: "sudo bash"},
				{Name: "s4", Type: "regex", Value: `sudo\s+.*NOPASSWD`},
			},
			Condition: "any of them",
			MITRE: &MITERMapping{
				Technique: "Elevated Execution with Prompt",
				Tactic:    "Privilege Escalation",
				ID:        "T1548",
				URL:       "https://attack.mitre.org/techniques/T1548/",
			},
		},
		{
			Name:        "data_staging",
			Namespace:   "exfiltration",
			Description: "Detects data staging for exfiltration",
			Severity:    "high",
			Tags:        []string{"exfiltration", "staging"},
			Strings: []StringPattern{
				{Name: "s1", Type: "text", Value: "/tmp/.hidden"},
				{Name: "s2", Type: "text", Value: "tar -czf"},
				{Name: "s3", Type: "text", Value: "base64 /etc/passwd"},
				{Name: "s4", Type: "regex", Value: `curl.*-d.*@/etc/`},
			},
			Condition: "2 of them",
			MITRE: &MITERMapping{
				Technique: "Data from Local System",
				Tactic:    "Collection",
				ID:        "T1005",
				URL:       "https://attack.mitre.org/techniques/T1005/",
			},
		},
		{
			Name:        "persistence_cron",
			Namespace:   "persistence",
			Description: "Detects cron-based persistence",
			Severity:    "high",
			Tags:        []string{"persistence", "cron"},
			Strings: []StringPattern{
				{Name: "s1", Type: "text", Value: "crontab -e"},
				{Name: "s2", Type: "text", Value: "/etc/cron.d/"},
				{Name: "s3", Type: "text", Value: "@reboot"},
				{Name: "s4", Type: "regex", Value: `\*\s+\*\s+\*\s+\*\s+.*sh\s+-c`},
			},
			Condition: "2 of them",
			MITRE: &MITERMapping{
				Technique: "Cron",
				Tactic:    "Persistence",
				ID:        "T1053.003",
				URL:       "https://attack.mitre.org/techniques/T1053/003/",
			},
		},
		{
			Name:        "network_tunnel",
			Namespace:   "command_and_control",
			Description: "Detects network tunneling for C2",
			Severity:    "high",
			Tags:        []string{"c2", "tunneling"},
			Strings: []StringPattern{
				{Name: "s1", Type: "text", Value: "ssh -L"},
				{Name: "s2", Type: "text", Value: "ssh -R"},
				{Name: "s3", Type: "text", Value: "ncat --ssl"},
				{Name: "s4", Type: "text", Value: "socat"},
				{Name: "s5", Type: "regex", Value: `tun\d+`},
			},
			Condition: "2 of them",
			MITRE: &MITERMapping{
				Technique: "Protocol Tunneling",
				Tactic:    "Command and Control",
				ID:        "T1572",
				URL:       "https://attack.mitre.org/techniques/T1572/",
			},
		},
		{
			Name:        "anti_forensics",
			Namespace:   "defense_evasion",
			Description: "Detects anti-forensics techniques",
			Severity:    "high",
			Tags:        []string{"defense_evasion", "anti_forensics"},
			Strings: []StringPattern{
				{Name: "s1", Type: "text", Value: "shred -u"},
				{Name: "s2", Type: "text", Value: "wipe"},
				{Name: "s3", Type: "text", Value: "dd if=/dev/zero"},
				{Name: "s4", Type: "text", Value: "history -c"},
				{Name: "s5", Type: "regex", Value: `rm\s+-rf\s+/var/log`},
			},
			Condition: "2 of them",
			MITRE: &MITERMapping{
				Technique: "Indicator Removal on Host",
				Tactic:    "Defense Evasion",
				ID:        "T1070",
				URL:       "https://attack.mitre.org/techniques/T1070/",
			},
		},
		{
			Name:        "supply_chain_backdoor",
			Namespace:   "supply_chain",
			Description: "Detects supply chain backdoor patterns",
			Severity:    "critical",
			Tags:        []string{"supply_chain", "backdoor"},
			Strings: []StringPattern{
				{Name: "s1", Type: "text", Value: "authorized_keys"},
				{Name: "s2", Type: "text", Value: "chmod +s"},
				{Name: "s3", Type: "text", Value: "setuid"},
				{Name: "s4", Type: "regex", Value: `echo.*>>\s*/etc/rc\.local`},
			},
			Condition: "2 of them",
			MITRE: &MITERMapping{
				Technique: "Supply Chain Compromise",
				Tactic:    "Initial Access",
				ID:        "T1195",
				URL:       "https://attack.mitre.org/techniques/T1195/",
			},
		},
		{
			Name:        "container_escape",
			Namespace:   "container_security",
			Description: "Detects container escape techniques",
			Severity:    "critical",
			Tags:        []string{"container", "escape"},
			Strings: []StringPattern{
				{Name: "s1", Type: "text", Value: "docker exec"},
				{Name: "s2", Type: "text", Value: "/var/run/docker.sock"},
				{Name: "s3", Type: "text", Value: "nsenter --target 1"},
				{Name: "s4", Type: "regex", Value: `--privileged`},
			},
			Condition: "2 of them",
			MITRE: &MITERMapping{
				Technique: "Escape to Host",
				Tactic:    "Privilege Escalation",
				ID:        "T1611",
				URL:       "https://attack.mitre.org/techniques/T1611/",
			},
		},
		{
			Name:        "dns_over_https",
			Namespace:   "command_and_control",
			Description: "Detects DNS over HTTPS usage",
			Severity:    "medium",
			Tags:        []string{"c2", "dns", "https"},
			Strings: []StringPattern{
				{Name: "s1", Type: "text", Value: "dns.google"},
				{Name: "s2", Type: "text", Value: "cloudflare-dns.com"},
				{Name: "s3", Type: "text", Value: "1.1.1.1/dns-query"},
				{Name: "s4", Type: "regex", Value: `https://.*dns-query`},
			},
			Condition: "2 of them",
			MITRE: &MITERMapping{
				Technique: "Application Layer Protocol: DNS",
				Tactic:    "Command and Control",
				ID:        "T1071.004",
				URL:       "https://attack.mitre.org/techniques/T1071/004/",
			},
		},
		{
			Name:        "log_tampering",
			Namespace:   "defense_evasion",
			Description: "Detects log tampering activities",
			Severity:    "high",
			Tags:        []string{"defense_evasion", "logs"},
			Strings: []StringPattern{
				{Name: "s1", Type: "text", Value: "truncate -s 0"},
				{Name: "s2", Type: "text", Value: "echo '' >"},
				{Name: "s3", Type: "text", Value: "journalctl --vacuum"},
				{Name: "s4", Type: "regex", Value: `>\s*/var/log/`},
			},
			Condition: "2 of them",
			MITRE: &MITERMapping{
				Technique: "Tampers with System Event Log",
				Tactic:    "Defense Evasion",
				ID:        "T1562.002",
				URL:       "https://attack.mitre.org/techniques/T1562/002/",
			},
		},
		{
			Name:        "malware_persistence_systemd",
			Namespace:   "persistence",
			Description: "Detects systemd-based persistence",
			Severity:    "high",
			Tags:        []string{"persistence", "systemd"},
			Strings: []StringPattern{
				{Name: "s1", Type: "text", Value: "[Service]"},
				{Name: "s2", Type: "text", Value: "ExecStart="},
				{Name: "s3", Type: "text", Value: "systemctl enable"},
				{Name: "s4", Type: "regex", Value: ` WantedBy=multi-user\.target`},
			},
			Condition: "3 of them",
			MITRE: &MITERMapping{
				Technique: "Systemd Service",
				Tactic:    "Persistence",
				ID:        "T1543.002",
				URL:       "https://attack.mitre.org/techniques/T1543/002/",
			},
		},
	}

	for _, rule := range defaultRules {
		e.AddRule(rule)
	}
}

// ScanDirectory scans all files in a directory
func (e *Engine) ScanDirectory(dir string) ([]*Match, error) {
	var allMatches []*Match
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		matches, scanErr := e.ScanFile(path)
		if scanErr != nil {
			e.log.Printf("Error scanning %s: %v", path, scanErr)
			return nil
		}
		allMatches = append(allMatches, matches...)
		return nil
	})
	return allMatches, err
}

// ScanProcessMemory scans a process's memory maps
func (e *Engine) ScanProcessMemory(pid int) ([]*Match, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("read process maps: %w", err)
	}

	var matches []*Match
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 6 {
			mapsFile := parts[5]
			if mapsFile != "" && mapsFile != "[heap]" && mapsFile != "[stack]" {
				fileMatches, err := e.ScanFile(mapsFile)
				if err == nil {
					matches = append(matches, fileMatches...)
				}
			}
		}
	}
	return matches, nil
}

// GetRuleByName returns a rule by name
func (e *Engine) GetRuleByName(name string) *Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rules[name]
}

// EnableRule enables a rule by name
func (e *Engine) EnableRule(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if rule, ok := e.rules[name]; ok {
		rule.Enabled = true
		return true
	}
	return false
}

// DisableRule disables a rule by name
func (e *Engine) DisableRule(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if rule, ok := e.rules[name]; ok {
		rule.Enabled = false
		return true
	}
	return false
}

// GetRuleCount returns the number of loaded rules
func (e *Engine) GetRuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// ClearRules removes all loaded rules
func (e *Engine) ClearRules() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = make(map[string]*Rule)
	e.compiledRe = make(map[string]*regexp.Regexp)
}

// ExportRules exports all rules to a JSON file
func (e *Engine) ExportRules(path string) error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	data, err := json.MarshalIndent(e.rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ImportRules imports rules from a JSON file
func (e *Engine) ImportRules(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read rules file: %w", err)
	}
	var rules map[string]*Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("parse rules file: %w", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for name, rule := range rules {
		e.rules[name] = rule
		for _, sp := range rule.Strings {
			if sp.Type == "regex" {
				re, err := regexp.Compile(sp.Value)
				if err == nil {
					e.compiledRe[name+":"+sp.Name] = re
				}
			}
		}
	}
	return nil
}

// ValidateRule checks if a rule is valid
func (e *Engine) ValidateRule(rule *Rule) error {
	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if rule.Condition == "" {
		return fmt.Errorf("rule condition is required")
	}
	for _, sp := range rule.Strings {
		if sp.Name == "" {
			return fmt.Errorf("string pattern name is required")
		}
		if sp.Value == "" {
			return fmt.Errorf("string pattern value is required for %s", sp.Name)
		}
		if sp.Type == "regex" {
			if _, err := regexp.Compile(sp.Value); err != nil {
				return fmt.Errorf("invalid regex in %s: %w", sp.Name, err)
			}
		}
	}
	return nil
}
