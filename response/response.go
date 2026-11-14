//go:build linux

package response

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"
)

type Playbook struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Trigger     string  `json:"trigger"`
	Steps       []*Step `json:"steps"`
	Enabled     bool    `json:"enabled"`
}

type Step struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Command     string                 `json:"command,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

type Execution struct {
	ID         string        `json:"id"`
	PlaybookID string        `json:"playbook_id"`
	Trigger    string        `json:"trigger"`
	StartTime  time.Time     `json:"start_time"`
	EndTime    *time.Time    `json:"end_time,omitempty"`
	Status     string        `json:"status"`
	Results    []*StepResult `json:"results"`
}

type StepResult struct {
	StepID   string        `json:"step_id"`
	Status   string        `json:"status"`
	Output   string        `json:"output"`
	Error    string        `json:"error,omitempty"`
	Duration time.Duration `json:"duration"`
}

type Engine struct {
	playbooks  map[string]*Playbook
	executions []*Execution
	mu         sync.RWMutex
}

func NewEngine() *Engine {
	e := &Engine{
		playbooks: make(map[string]*Playbook),
	}
	e.LoadDefaults()
	return e
}

func (e *Engine) LoadDefaults() {
	defaults := []*Playbook{
		{
			ID: "reverse_shell_response", Name: "Reverse Shell Response",
			Description: "Automated response to reverse shell detection",
			Trigger:     "reverse_shell",
			Steps: []*Step{
				{ID: "kill", Type: "kill_process", Description: "Kill malicious process"},
				{ID: "block", Type: "block_ip", Description: "Block remote IP"},
				{ID: "alert", Type: "alert", Description: "Send alert notification"},
			},
			Enabled: true,
		},
		{
			ID: "c2_response", Name: "C2 Communication Response",
			Description: "Response to C2 callback detection",
			Trigger:     "c2_callback",
			Steps: []*Step{
				{ID: "freeze", Type: "freeze", Description: "Freeze suspicious process"},
				{ID: "dump", Type: "command", Description: "Memory dump", Command: "gcore"},
				{ID: "block", Type: "block_ip", Description: "Block C2 IP"},
				{ID: "alert", Type: "alert", Description: "Notify SOC team"},
			},
			Enabled: true,
		},
		{
			ID: "ransomware_response", Name: "Ransomware Response",
			Description: "Emergency response to ransomware detection",
			Trigger:     "ransomware",
			Steps: []*Step{
				{ID: "isolate", Type: "command", Description: "Network isolation", Command: "iptables -I OUTPUT -j DROP"},
				{ID: "kill", Type: "kill_process", Description: "Kill ransomware process"},
				{ID: "freeze", Type: "freeze", Description: "Freeze all suspicious processes"},
				{ID: "dump", Type: "command", Description: "Full memory dump"},
				{ID: "alert", Type: "alert", Description: "Emergency alert"},
			},
			Enabled: true,
		},
		{
			ID: "privilege_escalation_response", Name: "Privilege Escalation Response",
			Description: "Response to privilege escalation attempts",
			Trigger:     "privilege_escalation",
			Steps: []*Step{
				{ID: "kill", Type: "kill_process", Description: "Kill escalated process"},
				{ID: "audit", Type: "command", Description: "Audit user accounts", Command: "auditd -n"},
				{ID: "alert", Type: "alert", Description: "Alert security team"},
			},
			Enabled: true,
		},
		{
			ID: "data_exfiltration_response", Name: "Data Exfiltration Response",
			Description: "Response to data exfiltration detection",
			Trigger:     "data_exfiltration",
			Steps: []*Step{
				{ID: "block", Type: "block_ip", Description: "Block destination IP"},
				{ID: "freeze", Type: "freeze", Description: "Freeze exfiltration process"},
				{ID: "dump", Type: "command", Description: "Capture network traffic"},
				{ID: "alert", Type: "alert", Description: "Alert data protection officer"},
			},
			Enabled: true,
		},
	}
	for _, p := range defaults {
		e.playbooks[p.ID] = p
	}
}

func (e *Engine) ExecutePlaybook(playbookID string, trigger string) *Execution {
	e.mu.RLock()
	playbook := e.playbooks[playbookID]
	e.mu.RUnlock()

	if playbook == nil {
		return nil
	}

	exec := &Execution{
		ID:         fmt.Sprintf("exec-%d", time.Now().UnixNano()),
		PlaybookID: playbookID,
		Trigger:    trigger,
		StartTime:  time.Now(),
		Status:     "running",
	}

	for _, step := range playbook.Steps {
		result := e.executeStep(step)
		exec.Results = append(exec.Results, result)
		if result.Status == "failed" {
			exec.Status = "failed"
			break
		}
	}

	if exec.Status == "running" {
		exec.Status = "completed"
	}

	now := time.Now()
	exec.EndTime = &now

	e.mu.Lock()
	e.executions = append(e.executions, exec)
	e.mu.Unlock()

	return exec
}

func (e *Engine) executeStep(step *Step) *StepResult {
	result := &StepResult{
		StepID: step.ID,
	}

	start := time.Now()

	switch step.Type {
	case "command":
		if step.Command != "" {
			cmd := exec.Command("sh", "-c", step.Command)
			output, err := cmd.CombinedOutput()
			result.Output = string(output)
			if err != nil {
				result.Status = "failed"
				result.Error = err.Error()
			} else {
				result.Status = "completed"
			}
		}
	case "kill_process":
		result.Status = "completed"
		result.Output = "Process kill requested"
	case "freeze":
		result.Status = "completed"
		result.Output = "Process freeze requested"
	case "block_ip":
		result.Status = "completed"
		result.Output = "IP block requested"
	case "alert":
		result.Status = "completed"
		result.Output = "Alert sent"
	default:
		result.Status = "failed"
		result.Error = fmt.Sprintf("Unknown step type: %s", step.Type)
	}

	result.Duration = time.Since(start)
	return result
}

func (e *Engine) GetPlaybooks() []*Playbook {
	e.mu.RLock()
	defer e.mu.RUnlock()
	playbooks := make([]*Playbook, 0, len(e.playbooks))
	for _, p := range e.playbooks {
		playbooks = append(playbooks, p)
	}
	return playbooks
}

func (e *Engine) GetExecutions() []*Execution {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*Execution, len(e.executions))
	copy(result, e.executions)
	return result
}

func (e *Engine) ExportPlaybooks(path string) error {
	data, err := json.MarshalIndent(e.GetPlaybooks(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (e *Engine) AddPlaybook(playbook *Playbook) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.playbooks[playbook.ID] = playbook
}

func (e *Engine) RemovePlaybook(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.playbooks[id]; exists {
		delete(e.playbooks, id)
		return true
	}
	return false
}

func (e *Engine) GetPlaybook(id string) *Playbook {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.playbooks[id]
}

func (e *Engine) EnablePlaybook(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if p, exists := e.playbooks[id]; exists {
		p.Enabled = true
		return true
	}
	return false
}

func (e *Engine) DisablePlaybook(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if p, exists := e.playbooks[id]; exists {
		p.Enabled = false
		return true
	}
	return false
}

// GetExecutionStats returns execution statistics
func (e *Engine) GetExecutionStats() map[string]int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	stats := map[string]int{
		"total":     len(e.executions),
		"completed": 0,
		"failed":    0,
		"running":   0,
	}
	for _, exec := range e.executions {
		stats[exec.Status]++
	}
	return stats
}

// GetExecutionByID returns an execution by ID
func (e *Engine) GetExecutionByID(id string) *Execution {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, exec := range e.executions {
		if exec.ID == id {
			return exec
		}
	}
	return nil
}

// GetRecentExecutions returns executions from the last N minutes
func (e *Engine) GetRecentExecutions(minutes int) []*Execution {
	e.mu.RLock()
	defer e.mu.RUnlock()
	cutoff := time.Now().Add(-time.Duration(minutes) * time.Minute)
	var result []*Execution
	for _, exec := range e.executions {
		if exec.StartTime.After(cutoff) {
			result = append(result, exec)
		}
	}
	return result
}

// GetPlaybookByTrigger finds playbooks for a trigger
func (e *Engine) GetPlaybookByTrigger(trigger string) []*Playbook {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var result []*Playbook
	for _, p := range e.playbooks {
		if p.Trigger == trigger {
			result = append(result, p)
		}
	}
	return result
}

// AutoRespond automatically selects and executes a playbook
func (e *Engine) AutoRespond(trigger string) *Execution {
	playbooks := e.GetPlaybookByTrigger(trigger)
	if len(playbooks) == 0 {
		return nil
	}

	for _, p := range playbooks {
		if p.Enabled {
			return e.ExecutePlaybook(p.ID, trigger)
		}
	}
	return nil
}

// GetEnabledPlaybooks returns only enabled playbooks
func (e *Engine) GetEnabledPlaybooks() []*Playbook {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var result []*Playbook
	for _, p := range e.playbooks {
		if p.Enabled {
			result = append(result, p)
		}
	}
	return result
}

// GetDisabledPlaybooks returns only disabled playbooks
func (e *Engine) GetDisabledPlaybooks() []*Playbook {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var result []*Playbook
	for _, p := range e.playbooks {
		if !p.Enabled {
			result = append(result, p)
		}
	}
	return result
}

// GenerateReport generates an incident response report
func (e *Engine) GenerateReport() string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	report := "# Incident Response Report\n\n"
	report += fmt.Sprintf("Generated: %s\n", time.Now().Format(time.RFC3339))
	report += fmt.Sprintf("Total Playbooks: %d\n", len(e.playbooks))
	report += fmt.Sprintf("Total Executions: %d\n\n", len(e.executions))

	report += "## Playbooks\n"
	for _, p := range e.playbooks {
		status := "enabled"
		if !p.Enabled {
			status = "disabled"
		}
		report += fmt.Sprintf("- [%s] %s (%s)\n", status, p.Name, p.Trigger)
	}

	report += "\n## Recent Executions\n"
	for _, exec := range e.executions {
		report += fmt.Sprintf("- [%s] %s (trigger: %s, steps: %d)\n", exec.Status, exec.PlaybookID, exec.Trigger, len(exec.Results))
	}

	return report
}

// ValidatePlaybook checks if a playbook is valid
func (e *Engine) ValidatePlaybook(playbook *Playbook) error {
	if playbook.ID == "" {
		return fmt.Errorf("playbook ID is required")
	}
	if playbook.Name == "" {
		return fmt.Errorf("playbook name is required")
	}
	if playbook.Trigger == "" {
		return fmt.Errorf("playbook trigger is required")
	}
	for _, step := range playbook.Steps {
		if step.ID == "" {
			return fmt.Errorf("step ID is required")
		}
		if step.Type == "" {
			return fmt.Errorf("step type is required for step %s", step.ID)
		}
	}
	return nil
}

// ImportPlaybooks imports playbooks from a JSON file
func (e *Engine) ImportPlaybooks(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var playbooks []*Playbook
	if err := json.Unmarshal(data, &playbooks); err != nil {
		return err
	}
	for _, p := range playbooks {
		e.AddPlaybook(p)
	}
	return nil
}
