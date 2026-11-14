//go:build linux

package correlation

import (
	"sync"
	"time"
)

type Event struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Type      string            `json:"type"`
	PID       uint32            `json:"pid"`
	PPID      uint32            `json:"ppid"`
	Name      string            `json:"name"`
	Path      string            `json:"path"`
	Details   map[string]string `json:"details"`
	Severity  string            `json:"severity"`
}

type Chain struct {
	ID         string    `json:"id"`
	Events     []Event   `json:"events"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	RootPID    uint32    `json:"root_pid"`
	MaxDepth   int       `json:"max_depth"`
	RiskScore  float64   `json:"risk_score"`
	Duration   float64   `json:"duration"`
	Techniques []string  `json:"techniques"`
}

type Timeline struct {
	Events    []Event `json:"events"`
	Duration  float64 `json:"duration_seconds"`
	EventRate float64 `json:"events_per_second"`
}

type Engine struct {
	mu          sync.RWMutex
	events      []Event
	chains      map[string]*Chain
	maxEvents   int
	maxAge      time.Duration
	processTree map[uint32]uint32
}

func NewEngine() *Engine {
	return &Engine{
		events:      make([]Event, 0, 10000),
		chains:      make(map[string]*Chain),
		maxEvents:   100000,
		maxAge:      24 * time.Hour,
		processTree: make(map[uint32]uint32),
	}
}

func (e *Engine) AddEvent(event Event) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.events = append(e.events, event)

	if event.PPID > 0 {
		e.processTree[event.PID] = event.PPID
	}

	e.evictOldEvents()
	e.updateChains(event)
}

func (e *Engine) GetTimeline(window time.Duration) *Timeline {
	e.mu.RLock()
	defer e.mu.RUnlock()

	cutoff := time.Now().Add(-window)
	var filtered []Event

	for _, ev := range e.events {
		if ev.Timestamp.After(cutoff) {
			filtered = append(filtered, ev)
		}
	}

	if len(filtered) == 0 {
		return &Timeline{}
	}

	duration := filtered[len(filtered)-1].Timestamp.Sub(filtered[0].Timestamp).Seconds()
	if duration == 0 {
		duration = 1
	}

	return &Timeline{
		Events:    filtered,
		Duration:  duration,
		EventRate: float64(len(filtered)) / duration,
	}
}

func (e *Engine) GetChains() []*Chain {
	e.mu.RLock()
	defer e.mu.RUnlock()

	chains := make([]*Chain, 0, len(e.chains))
	for _, c := range e.chains {
		chains = append(chains, c)
	}
	return chains
}

func (e *Engine) GetChainByPID(pid uint32) *Chain {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, c := range e.chains {
		for _, ev := range c.Events {
			if ev.PID == pid {
				return c
			}
		}
	}
	return nil
}

func (e *Engine) GetProcessTree(pid uint32, depth int) map[uint32][]uint32 {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make(map[uint32][]uint32)
	e.buildTree(pid, depth, 0, result)
	return result
}

func (e *Engine) buildTree(pid uint32, maxDepth, currentDepth int, result map[uint32][]uint32) {
	if currentDepth >= maxDepth {
		return
	}

	children := make([]uint32, 0)
	for child, parent := range e.processTree {
		if parent == pid {
			children = append(children, child)
		}
	}

	if len(children) > 0 {
		result[pid] = children
		for _, child := range children {
			e.buildTree(child, maxDepth, currentDepth+1, result)
		}
	}
}

func (e *Engine) evictOldEvents() {
	cutoff := time.Now().Add(-e.maxAge)
	i := 0
	for i < len(e.events) && e.events[i].Timestamp.Before(cutoff) {
		i++
	}
	if i > 0 {
		e.events = e.events[i:]
	}

	if len(e.events) > e.maxEvents {
		e.events = e.events[len(e.events)-e.maxEvents:]
	}
}

func (e *Engine) updateChains(event Event) {
	if event.Type == "process_execution" {
		chainID := e.findOrCreateChain(event)
		c := e.chains[chainID]
		c.Events = append(c.Events, event)
		c.EndTime = event.Timestamp

		if len(c.Events) > 1 {
			c.Duration = c.EndTime.Sub(c.StartTime).Seconds()
		}

		c.RiskScore = e.calculateChainRisk(c)
	}
}

func (e *Engine) findOrCreateChain(event Event) string {
	for id, c := range e.chains {
		for _, ev := range c.Events {
			if ev.PID == event.PPID {
				return id
			}
		}
	}

	chainID := time.Now().Format("chain-20060102150405") + "-" + string(rune(event.PID))
	e.chains[chainID] = &Chain{
		ID:        chainID,
		Events:    []Event{event},
		StartTime: event.Timestamp,
		EndTime:   event.Timestamp,
		RootPID:   event.PID,
	}
	return chainID
}

func (e *Engine) calculateChainRisk(c *Chain) float64 {
	risk := 0.0

	severityWeights := map[string]float64{
		"critical": 1.0,
		"high":     0.8,
		"medium":   0.5,
		"low":      0.3,
		"info":     0.1,
	}

	for _, ev := range c.Events {
		if w, ok := severityWeights[ev.Severity]; ok {
			if w > risk {
				risk = w
			}
		}
	}

	depthFactor := float64(len(c.Events)) * 0.05
	if depthFactor > 0.3 {
		depthFactor = 0.3
	}
	risk += depthFactor

	if risk > 1.0 {
		risk = 1.0
	}

	return risk
}

func (e *Engine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"total_events":  len(e.events),
		"total_chains":  len(e.chains),
		"tracked_pids":  len(e.processTree),
		"memory_events": cap(e.events),
	}
}
