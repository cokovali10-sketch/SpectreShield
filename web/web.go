//go:build linux

package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"
)

//go:embed dashboard.html
var dashboardFS embed.FS

type Dashboard struct {
	port      int
	mux       *http.ServeMux
	data      *DashboardData
	mu        sync.RWMutex
	startTime time.Time
}

type DashboardData struct {
	Threats           int            `json:"threats"`
	Processes         int            `json:"processes"`
	YaraRules         int            `json:"yara_rules"`
	SigmaRules        int            `json:"sigma_rules"`
	MitreEvents       int            `json:"mitre_events"`
	RootkitFinds      int            `json:"rootkit_finds"`
	DPIFindings       int            `json:"dpi_findings"`
	CompliancePct     float64        `json:"compliance_pct"`
	ContainerFindings int            `json:"container_findings"`
	ResponseExecs     int            `json:"response_execs"`
	IOCCount          int            `json:"ioc_count"`
	Uptime            string         `json:"uptime"`
	Status            string         `json:"status"`
	Modules           []ModuleStatus `json:"modules"`
}

type ModuleStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Items  int    `json:"items"`
}

func NewDashboard(port int) *Dashboard {
	return &Dashboard{
		port: port,
		mux:  http.NewServeMux(),
		data: &DashboardData{
			Status: "running",
			Modules: []ModuleStatus{
				{Name: "YARA Engine", Status: "active", Items: 16},
				{Name: "Sigma Rules", Status: "active", Items: 30},
				{Name: "Rootkit Detector", Status: "active", Items: 14},
				{Name: "MITRE ATT&CK", Status: "active", Items: 50},
				{Name: "DPI Engine", Status: "active", Items: 0},
				{Name: "Compliance", Status: "active", Items: 5},
				{Name: "Container Security", Status: "active", Items: 0},
				{Name: "Incident Response", Status: "active", Items: 5},
				{Name: "Threat Intelligence", Status: "active", Items: 4},
				{Name: "Memory Forensics", Status: "active", Items: 0},
			},
		},
		startTime: time.Now(),
	}
}

func (d *Dashboard) Start() error {
	d.mux.HandleFunc("/", d.handleIndex)
	d.mux.HandleFunc("/api/data", d.handleAPIData)
	d.mux.HandleFunc("/api/stats", d.handleAPIStats)
	d.mux.HandleFunc("/api/modules", d.handleAPIModules)

	go d.updateLoop()

	addr := fmt.Sprintf(":%d", d.port)
	fmt.Printf("SpectreShield Dashboard: http://localhost%s\n", addr)
	return http.ListenAndServe(addr, d.mux)
}

func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(dashboardFS, "dashboard.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	tmpl.Execute(w, d.data)
}

func (d *Dashboard) handleAPIData(w http.ResponseWriter, r *http.Request) {
	d.mu.RLock()
	data := d.data
	d.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (d *Dashboard) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	stats := map[string]interface{}{
		"threats":    d.data.Threats,
		"processes":  d.data.Processes,
		"uptime":     time.Since(d.startTime).String(),
		"status":     d.data.Status,
		"compliance": d.data.CompliancePct,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (d *Dashboard) handleAPIModules(w http.ResponseWriter, r *http.Request) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(d.data.Modules)
}

func (d *Dashboard) updateLoop() {
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		d.mu.Lock()
		d.data.Uptime = time.Since(d.startTime).String()
		d.mu.Unlock()
	}
}

func (d *Dashboard) UpdateData(data *DashboardData) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.data = data
}

func (d *Dashboard) GetData() *DashboardData {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.data
}
