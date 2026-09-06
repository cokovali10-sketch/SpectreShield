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
