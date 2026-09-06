//go:build linux

package mitre

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Technique represents a MITRE ATT&CK technique
type Technique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tactic      string   `json:"tactic"`
	Platform    []string `json:"platforms"`
	DataSource  []string `json:"data_sources"`
	Detection   string   `json:"detection"`
	URL         string   `json:"url"`
}

// Tactic represents a MITRE ATT&CK tactic
type Tactic struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Shortname   string `json:"shortname"`
	URL         string `json:"url"`
}

// ThreatEvent represents a threat mapped to MITRE
type ThreatEvent struct {
	ID         string     `json:"id"`
	Technique  *Technique `json:"technique"`
	Tactic     *Tactic    `json:"tactic"`
	Timestamp  time.Time  `json:"timestamp"`
	Process    string     `json:"process"`
	PID        uint32     `json:"pid"`
	Evidence   string     `json:"evidence"`
	Confidence float64    `json:"confidence"`
}

// Database holds the MITRE ATT&CK database
type Database struct {
	techniques map[string]*Technique
	tactics    map[string]*Tactic
	events     []*ThreatEvent
	mu         sync.RWMutex
}

// NewDatabase creates a new MITRE database
func NewDatabase() *Database {
	db := &Database{
		techniques: make(map[string]*Technique),
		tactics:    make(map[string]*Tactic),
	}
	db.LoadDefaults()
	return db
}

// LoadDefaults loads default MITRE data
func (db *Database) LoadDefaults() {
	tactics := []*Tactic{
		{ID: "TA0043", Name: "Reconnaissance", Shortname: "reconnaissance", URL: "https://attack.mitre.org/tactics/TA0043/"},
		{ID: "TA0042", Name: "Resource Development", Shortname: "resource-development", URL: "https://attack.mitre.org/tactics/TA0042/"},
		{ID: "TA0001", Name: "Initial Access", Shortname: "initial-access", URL: "https://attack.mitre.org/tactics/TA0001/"},
		{ID: "TA0002", Name: "Execution", Shortname: "execution", URL: "https://attack.mitre.org/tactics/TA0002/"},
		{ID: "TA0003", Name: "Persistence", Shortname: "persistence", URL: "https://attack.mitre.org/tactics/TA0003/"},
		{ID: "TA0004", Name: "Privilege Escalation", Shortname: "privilege-escalation", URL: "https://attack.mitre.org/tactics/TA0004/"},
		{ID: "TA0005", Name: "Defense Evasion", Shortname: "defense-evasion", URL: "https://attack.mitre.org/tactics/TA0005/"},
		{ID: "TA0006", Name: "Credential Access", Shortname: "credential-access", URL: "https://attack.mitre.org/tactics/TA0006/"},
		{ID: "TA0007", Name: "Discovery", Shortname: "discovery", URL: "https://attack.mitre.org/tactics/TA0007/"},
		{ID: "TA0008", Name: "Lateral Movement", Shortname: "lateral-movement", URL: "https://attack.mitre.org/tactics/TA0008/"},
		{ID: "TA0009", Name: "Collection", Shortname: "collection", URL: "https://attack.mitre.org/tactics/TA0009/"},
		{ID: "TA0011", Name: "Command and Control", Shortname: "command-and-control", URL: "https://attack.mitre.org/tactics/TA0011/"},
		{ID: "TA0010", Name: "Exfiltration", Shortname: "exfiltration", URL: "https://attack.mitre.org/tactics/TA0010/"},
		{ID: "TA0040", Name: "Impact", Shortname: "impact", URL: "https://attack.mitre.org/tactics/TA0040/"},
	}
	for _, t := range tactics {
		db.tactics[t.ID] = t
	}

	techniques := []*Technique{
		{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "TA0002", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1059/"},
		{ID: "T1059.004", Name: "Unix Shell", Tactic: "TA0002", Platform: []string{"Linux", "macOS"}, URL: "https://attack.mitre.org/techniques/T1059/004/"},
		{ID: "T1059.006", Name: "Python", Tactic: "TA0002", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1059/006/"},
		{ID: "T1053", Name: "Scheduled Task/Job", Tactic: "TA0003", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1053/"},
		{ID: "T1053.003", Name: "Cron", Tactic: "TA0003", Platform: []string{"Linux", "macOS"}, URL: "https://attack.mitre.org/techniques/T1053/003/"},
		{ID: "T1547", Name: "Boot or Logon Autostart Execution", Tactic: "TA0003", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1547/"},
		{ID: "T1547.006", Name: "Kernel Modules and Extensions", Tactic: "TA0003", Platform: []string{"Linux"}, URL: "https://attack.mitre.org/techniques/T1547/006/"},
		{ID: "T1543.002", Name: "Systemd Service", Tactic: "TA0003", Platform: []string{"Linux"}, URL: "https://attack.mitre.org/techniques/T1543/002/"},
		{ID: "T1014", Name: "Rootkit", Tactic: "TA0005", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1014/"},
		{ID: "T1003", Name: "OS Credential Dumping", Tactic: "TA0006", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1003/"},
		{ID: "T1003.008", Name: "/etc/passwd and /etc/shadow", Tactic: "TA0006", Platform: []string{"Linux", "macOS"}, URL: "https://attack.mitre.org/techniques/T1003/008/"},
		{ID: "T1087", Name: "Account Discovery", Tactic: "TA0007", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1087/"},
		{ID: "T1082", Name: "System Information Discovery", Tactic: "TA0007", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1082/"},
		{ID: "T1046", Name: "Network Service Scanning", Tactic: "TA0007", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1046/"},
		{ID: "T1021", Name: "Remote Services", Tactic: "TA0008", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1021/"},
		{ID: "T1021.004", Name: "SSH", Tactic: "TA0008", Platform: []string{"Linux", "macOS"}, URL: "https://attack.mitre.org/techniques/T1021/004/"},
		{ID: "T1071", Name: "Application Layer Protocol", Tactic: "TA0011", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1071/"},
		{ID: "T1071.001", Name: "Web Protocols", Tactic: "TA0011", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1071/001/"},
		{ID: "T1071.004", Name: "DNS", Tactic: "TA0011", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1071/004/"},
		{ID: "T1572", Name: "Protocol Tunneling", Tactic: "TA0011", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1572/"},
		{ID: "T1048", Name: "Exfiltration Over Alternative Protocol", Tactic: "TA0010", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1048/"},
		{ID: "T1486", Name: "Data Encrypted for Impact", Tactic: "TA0040", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1486/"},
		{ID: "T1496", Name: "Resource Hijacking", Tactic: "TA0040", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1496/"},
		{ID: "T1055", Name: "Process Injection", Tactic: "TA0005", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1055/"},
		{ID: "T1565", Name: "Data Manipulation", Tactic: "TA0005", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1565/"},
		{ID: "T1505.003", Name: "Web Shell", Tactic: "TA0003", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1505/003/"},
		{ID: "T1056", Name: "Input Capture", Tactic: "TA0009", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1056/"},
		{ID: "T1548", Name: "Elevated Execution with Prompt", Tactic: "TA0004", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1548/"},
		{ID: "T1005", Name: "Data from Local System", Tactic: "TA0009", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1005/"},
		{ID: "T1070", Name: "Indicator Removal on Host", Tactic: "TA0005", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1070/"},
		{ID: "T1195", Name: "Supply Chain Compromise", Tactic: "TA0001", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1195/"},
		{ID: "T1611", Name: "Escape to Host", Tactic: "TA0004", Platform: []string{"Linux"}, URL: "https://attack.mitre.org/techniques/T1611/"},
		{ID: "T1562.002", Name: "Tampers with System Event Log", Tactic: "TA0005", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1562/002/"},
		{ID: "T1098", Name: "Account Manipulation", Tactic: "TA0003", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1098/"},
		{ID: "T1136", Name: "Create Account", Tactic: "TA0003", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1136/"},
		{ID: "T1078", Name: "Valid Accounts", Tactic: "TA0001", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1078/"},
		{ID: "T1057", Name: "Process Discovery", Tactic: "TA0007", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1057/"},
		{ID: "T1083", Name: "File and Directory Discovery", Tactic: "TA0007", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1083/"},
		{ID: "T1049", Name: "System Network Connections Discovery", Tactic: "TA0007", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1049/"},
		{ID: "T1018", Name: "Remote System Discovery", Tactic: "TA0007", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1018/"},
		{ID: "T1518", Name: "Software Discovery", Tactic: "TA0007", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1518/"},
		{ID: "T1040", Name: "Network Sniffing", Tactic: "TA0006", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1040/"},
		{ID: "T1557", Name: "Adversary-in-the-Middle", Tactic: "TA0006", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1557/"},
		{ID: "T1560", Name: "Archive Collected Data", Tactic: "TA0009", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1560/"},
		{ID: "T1119", Name: "Automated Collection", Tactic: "TA0009", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1119/"},
		{ID: "T1113", Name: "Screen Capture", Tactic: "TA0009", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1113/"},
		{ID: "T1125", Name: "Video Capture", Tactic: "TA0009", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1125/"},
		{ID: "T1029", Name: "Scheduled Transfer", Tactic: "TA0010", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1029/"},
		{ID: "T1030", Name: "Data Transfer Size Limits", Tactic: "TA0010", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1030/"},
		{ID: "T1567", Name: "Exfiltration Over Web Service", Tactic: "TA0010", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1567/"},
		{ID: "T1499", Name: "Endpoint Denial of Service", Tactic: "TA0040", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1499/"},
		{ID: "T1498", Name: "Network Denial of Service", Tactic: "TA0040", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1498/"},
		{ID: "T1490", Name: "Inhibit System Recovery", Tactic: "TA0040", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1490/"},
		{ID: "T1489", Name: "Service Stop", Tactic: "TA0040", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1489/"},
		{ID: "T1485", Name: "Data Destruction", Tactic: "TA0040", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1485/"},
		{ID: "T1491", Name: "Defacement", Tactic: "TA0040", Platform: []string{"Linux", "Windows", "macOS"}, URL: "https://attack.mitre.org/techniques/T1491/"},
	}
	for _, t := range techniques {
		db.techniques[t.ID] = t
	}
}

// MapThreat maps a threat category to MITRE
func (db *Database) MapThreat(category string) (*Technique, *Tactic) {
	mappings := map[string]string{
		"reverse_shell":        "T1059.004",
		"c2_callback":          "T1071.001",
		"data_exfiltration":    "T1048",
		"privilege_escalation": "T1548",
		"credential_access":    "T1003",
		"lateral_movement":     "T1021.004",
		"persistence":          "T1547",
		"defense_evasion":      "T1014",
		"discovery":            "T1082",
		"impact":               "T1486",
		"cryptominer":          "T1496",
		"webshell":             "T1505.003",
		"rootkit":              "T1014",
		"process_injection":    "T1055",
		"file_tampering":       "T1565",
		"network_scan":         "T1046",
		"port_scan":            "T1046",
		"input_capture":        "T1056",
		"cron_persistence":     "T1053.003",
		"systemd_persistence":  "T1543.002",
		"supply_chain":         "T1195",
		"container_escape":     "T1611",
		"log_tampering":        "T1562.002",
		"account_manipulation": "T1098",
		"account_creation":     "T1136",
		"valid_accounts":       "T1078",
		"process_discovery":    "T1057",
		"file_discovery":       "T1083",
		"network_discovery":    "T1049",
		"remote_discovery":     "T1018",
		"software_discovery":   "T1518",
		"network_sniffing":     "T1040",
		"mitm_attack":          "T1557",
		"data_archive":         "T1560",
		"auto_collection":      "T1119",
		"screen_capture":       "T1113",
		"video_capture":        "T1125",
		"scheduled_transfer":   "T1029",
		"data_size_limits":     "T1030",
		"web_exfiltration":     "T1567",
		"endpoint_dos":         "T1499",
		"network_dos":          "T1498",
		"disable_recovery":     "T1490",
		"service_stop":         "T1489",
		"data_destruction":     "T1485",
		"defacement":           "T1491",
		"kernel_module":        "T1547.006",
		"library_hooking":      "T1014",
		"process_hollowing":    "T1055",
		"hidden_port":          "T1046",
	}

	techID, ok := mappings[category]
	if !ok {
		return nil, nil
	}

	technique := db.techniques[techID]
	if technique == nil {
		return nil, nil
	}

	tactic := db.tactics[technique.Tactic]
	return technique, tactic
}

// RecordEvent records a threat event
func (db *Database) RecordEvent(event *ThreatEvent) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.events = append(db.events, event)
}

// GetEvents returns all recorded events
func (db *Database) GetEvents() []*ThreatEvent {
	db.mu.RLock()
	defer db.mu.RUnlock()
	result := make([]*ThreatEvent, len(db.events))
	copy(result, db.events)
	return result
}

// GetTechnique returns a technique by ID
func (db *Database) GetTechnique(id string) *Technique {
	return db.techniques[id]
}

// GetTactic returns a tactic by ID
func (db *Database) GetTactic(id string) *Tactic {
	return db.tactics[id]
}

// GetTechniquesByTactic returns techniques for a tactic
func (db *Database) GetTechniquesByTactic(tacticID string) []*Technique {
	var result []*Technique
	for _, t := range db.techniques {
		if t.Tactic == tacticID {
			result = append(result, t)
		}
	}
	return result
}

// ExportJSON exports the database to JSON
func (db *Database) ExportJSON(path string) error {
	data := map[string]interface{}{
		"tactics":    db.tactics,
		"techniques": db.techniques,
		"events":     db.events,
	}
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, jsonData, 0o644)
}

// GenerateReport generates a MITRE report
func (db *Database) GenerateReport() string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	report := "# MITRE ATT&CK Report\n\n"
	report += fmt.Sprintf("Generated: %s\n", time.Now().Format(time.RFC3339))
	report += fmt.Sprintf("Total Events: %d\n\n", len(db.events))

	byTactic := make(map[string][]*ThreatEvent)
	for _, event := range db.events {
		if event.Tactic != nil {
			byTactic[event.Tactic.ID] = append(byTactic[event.Tactic.ID], event)
		}
	}

	for tacticID, events := range byTactic {
		tactic := db.tactics[tacticID]
		if tactic != nil {
			report += fmt.Sprintf("## %s (%s)\n", tactic.Name, tacticID)
			for _, event := range events {
				report += fmt.Sprintf("- [%s] %s (PID %d, Confidence: %.0f%%)\n",
					event.Technique.ID, event.Technique.Name, event.PID, event.Confidence*100)
			}
			report += "\n"
		}
	}

	return report
}

// GetTechniques returns all techniques
func (db *Database) GetTechniques() []*Technique {
	db.mu.RLock()
	defer db.mu.RUnlock()
	result := make([]*Technique, 0, len(db.techniques))
	for _, t := range db.techniques {
		result = append(result, t)
	}
	return result
}

// GetTactics returns all tactics
func (db *Database) GetTactics() []*Tactic {
	db.mu.RLock()
	defer db.mu.RUnlock()
	result := make([]*Tactic, 0, len(db.tactics))
	for _, t := range db.tactics {
		result = append(result, t)
	}
	return result
}

// ClearEvents clears all recorded events
func (db *Database) ClearEvents() {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.events = nil
}

// GetEventsByTactic returns events for a specific tactic
func (db *Database) GetEventsByTactic(tacticID string) []*ThreatEvent {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var result []*ThreatEvent
	for _, event := range db.events {
		if event.Tactic != nil && event.Tactic.ID == tacticID {
			result = append(result, event)
		}
	}
	return result
}

// GetEventsByTechnique returns events for a specific technique
func (db *Database) GetEventsByTechnique(techniqueID string) []*ThreatEvent {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var result []*ThreatEvent
	for _, event := range db.events {
		if event.Technique != nil && event.Technique.ID == techniqueID {
			result = append(result, event)
		}
	}
	return result
}

// GetEventsByProcess returns events for a specific process
func (db *Database) GetEventsByProcess(process string) []*ThreatEvent {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var result []*ThreatEvent
	for _, event := range db.events {
		if event.Process == process {
			result = append(result, event)
		}
	}
	return result
}

// GetEventsByTimeRange returns events within a time range
func (db *Database) GetEventsByTimeRange(start, end time.Time) []*ThreatEvent {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var result []*ThreatEvent
	for _, event := range db.events {
		if event.Timestamp.After(start) && event.Timestamp.Before(end) {
			result = append(result, event)
		}
	}
	return result
}

// GetTechniqueCount returns the number of techniques
func (db *Database) GetTechniqueCount() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.techniques)
}

// GetTacticCount returns the number of tactics
func (db *Database) GetTacticCount() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.tactics)
}

// GetEventCount returns the number of events
func (db *Database) GetEventCount() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.events)
}

// SearchTechniques searches techniques by name or ID
func (db *Database) SearchTechniques(query string) []*Technique {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var result []*Technique
	query = strings.ToLower(query)
	for _, t := range db.techniques {
		if strings.Contains(strings.ToLower(t.ID), query) || strings.Contains(strings.ToLower(t.Name), query) {
			result = append(result, t)
		}
	}
	return result
}

// SearchTactics searches tactics by name or ID
func (db *Database) SearchTactics(query string) []*Tactic {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var result []*Tactic
	query = strings.ToLower(query)
	for _, t := range db.tactics {
		if strings.Contains(strings.ToLower(t.ID), query) || strings.Contains(strings.ToLower(t.Name), query) {
			result = append(result, t)
		}
	}
	return result
}

// GetTechniqueWithSubtechniques returns a technique and its subtechniques
func (db *Database) GetTechniqueWithSubtechniques(techniqueID string) []*Technique {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var result []*Technique
	for id, t := range db.techniques {
		if id == techniqueID || strings.HasPrefix(id, techniqueID+".") {
			result = append(result, t)
		}
	}
	return result
}

// GetTacticTechniqueMap returns a map of tactics to their techniques
func (db *Database) GetTacticTechniqueMap() map[string][]*Technique {
	db.mu.RLock()
	defer db.mu.RUnlock()
	result := make(map[string][]*Technique)
	for _, t := range db.techniques {
		result[t.Tactic] = append(result[t.Tactic], t)
	}
	return result
}

// GetMostUsedTechniques returns the most used techniques
func (db *Database) GetMostUsedTechniques(limit int) []*Technique {
	db.mu.RLock()
	defer db.mu.RUnlock()

	counts := make(map[string]int)
	for _, event := range db.events {
		if event.Technique != nil {
			counts[event.Technique.ID]++
		}
	}

	type techniqueCount struct {
		technique *Technique
		count     int
	}
	var sorted []techniqueCount
	for id, count := range counts {
		if t := db.techniques[id]; t != nil {
			sorted = append(sorted, techniqueCount{t, count})
		}
	}

	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].count > sorted[i].count {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	var result []*Technique
	for i := 0; i < limit && i < len(sorted); i++ {
		result = append(result, sorted[i].technique)
	}
	return result
}

// GetMostUsedTactics returns the most used tactics
func (db *Database) GetMostUsedTactics(limit int) []*Tactic {
	db.mu.RLock()
	defer db.mu.RUnlock()

	counts := make(map[string]int)
	for _, event := range db.events {
		if event.Tactic != nil {
			counts[event.Tactic.ID]++
		}
	}

	type tacticCount struct {
		tactic *Tactic
		count  int
	}
	var sorted []tacticCount
	for id, count := range counts {
		if t := db.tactics[id]; t != nil {
			sorted = append(sorted, tacticCount{t, count})
		}
	}

	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].count > sorted[i].count {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	var result []*Tactic
	for i := 0; i < limit && i < len(sorted); i++ {
		result = append(result, sorted[i].tactic)
	}
	return result
}

// ImportJSON imports the database from JSON
func (db *Database) ImportJSON(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read MITRE database file: %w", err)
	}

	var imported struct {
		Techniques map[string]*Technique `json:"techniques"`
		Tactics    map[string]*Tactic    `json:"tactics"`
		Events     []*ThreatEvent        `json:"events"`
	}

	if err := json.Unmarshal(data, &imported); err != nil {
		return fmt.Errorf("parse MITRE database file: %w", err)
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	for id, t := range imported.Techniques {
		db.techniques[id] = t
	}
	for id, t := range imported.Tactics {
		db.tactics[id] = t
	}
	db.events = append(db.events, imported.Events...)

	return nil
}
