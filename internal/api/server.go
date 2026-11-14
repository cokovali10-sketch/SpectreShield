//go:build linux

package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cokovali10-sketch/SpectreShield/compliance"
	"github.com/cokovali10-sketch/SpectreShield/container"
	"github.com/cokovali10-sketch/SpectreShield/correlation"
	"github.com/cokovali10-sketch/SpectreShield/dpi"
	"github.com/cokovali10-sketch/SpectreShield/engine"
	"github.com/cokovali10-sketch/SpectreShield/forensics"
	hermesbridge "github.com/cokovali10-sketch/SpectreShield/hermes-bridge"
	"github.com/cokovali10-sketch/SpectreShield/internal/config"
	"github.com/cokovali10-sketch/SpectreShield/internal/types"
	"github.com/cokovali10-sketch/SpectreShield/memory"
	"github.com/cokovali10-sketch/SpectreShield/mitre"
	"github.com/cokovali10-sketch/SpectreShield/response"
	"github.com/cokovali10-sketch/SpectreShield/rootkit"
	"github.com/cokovali10-sketch/SpectreShield/sandbox"
	import_sigma "github.com/cokovali10-sketch/SpectreShield/sigma"
	"github.com/cokovali10-sketch/SpectreShield/ti"
	import_yara "github.com/cokovali10-sketch/SpectreShield/yara"
)

type Server struct {
	cfg         *config.Config
	engine      *engine.Engine
	forensics   *forensics.ForensicsEngine
	sandbox     *sandbox.Sandbox
	hermes      *hermesbridge.Bridge
	yara        *import_yara.Engine
	sigma       *import_sigma.Engine
	mitre       *mitre.Database
	compliance  *compliance.Engine
	response    *response.Engine
	ti          *ti.Database
	dpi         *dpi.Engine
	container   *container.Monitor
	memory      *memory.Analyzer
	correlation *correlation.Engine
	mux         *http.ServeMux
	auth        *AuthMiddleware
}

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func NewServer(cfg *config.Config, e *engine.Engine, f *forensics.ForensicsEngine, s *sandbox.Sandbox, h *hermesbridge.Bridge) *Server {
	srv := &Server{
		cfg:         cfg,
		engine:      e,
		forensics:   f,
		sandbox:     s,
		hermes:      h,
		yara:        import_yara.NewEngine(),
		sigma:       import_sigma.NewEngine(),
		mitre:       mitre.NewDatabase(),
		compliance:  compliance.NewEngine(),
		response:    response.NewEngine(),
		ti:          ti.NewDatabase(),
		dpi:         dpi.NewEngine(),
		container:   container.NewMonitor(),
		memory:      memory.NewAnalyzer(),
		correlation: correlation.NewEngine(),
		mux:         http.NewServeMux(),
	}

	srv.auth = NewAuthMiddleware(cfg.API.AuthKey, cfg.API.JWTSecret)

	srv.yara.LoadDefaultRules()
	srv.sigma.LoadBuiltinRules()
	srv.ti.LoadDefaults()

	return srv
}

func (s *Server) SetupRoutes() {
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/stats", s.handleStats)
	s.mux.HandleFunc("/api/threats", s.handleThreats)
	s.mux.HandleFunc("/api/processes", s.handleProcesses)
	s.mux.HandleFunc("/api/dumps", s.handleDumps)
	s.mux.HandleFunc("/api/sandbox", s.handleSandbox)
	s.mux.HandleFunc("/api/baseline", s.handleBaseline)
	s.mux.HandleFunc("/api/hermes/analyze", s.handleHermesAnalyze)
	s.mux.HandleFunc("/api/config", s.handleConfig)
	s.mux.HandleFunc("/api/yara/rules", s.handleYaraRules)
	s.mux.HandleFunc("/api/yara/scan", s.handleYaraScan)
	s.mux.HandleFunc("/api/rootkit/scan", s.handleRootkitScan)
	s.mux.HandleFunc("/api/sigma/rules", s.handleSigmaRules)
	s.mux.HandleFunc("/api/mitre/techniques", s.handleMITRETechniques)
	s.mux.HandleFunc("/api/mitre/tactics", s.handleMITRETactics)
	s.mux.HandleFunc("/api/compliance/frameworks", s.handleComplianceFrameworks)
	s.mux.HandleFunc("/api/compliance/run", s.handleComplianceRun)
	s.mux.HandleFunc("/api/response/playbooks", s.handleResponsePlaybooks)
	s.mux.HandleFunc("/api/response/execute", s.handleResponseExecute)
	s.mux.HandleFunc("/api/ti/iocs", s.handleTIIOCs)
	s.mux.HandleFunc("/api/ti/stats", s.handleTIStats)
	s.mux.HandleFunc("/api/dpi/analyze", s.handleDPIAnalyze)
	s.mux.HandleFunc("/api/container/scan", s.handleContainerScan)
	s.mux.HandleFunc("/api/memory/analyze", s.handleMemoryAnalyze)
	s.mux.HandleFunc("/api/correlation/timeline", s.handleCorrelationTimeline)
	s.mux.HandleFunc("/api/correlation/chains", s.handleCorrelationChains)
	s.mux.HandleFunc("/api/correlation/events", s.handleCorrelationAddEvent)
	s.mux.HandleFunc("/api/correlation/tree", s.handleCorrelationTree)
	s.mux.HandleFunc("/api/correlation/stats", s.handleCorrelationStats)
}

func (s *Server) Start() error {
	s.SetupRoutes()
	handler := s.auth.Wrap(s.mux)
	fmt.Printf("SpectreShield API listening on %s\n", s.cfg.API.Addr)
	return http.ListenAndServe(s.cfg.API.Addr, handler)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	hermesOK := false
	if s.hermes != nil {
		hermesOK = s.hermes.IsAvailable()
	}
	jsonRespond(w, 200, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"status":  "healthy",
			"hermes":  hermesOK,
			"version": "1.0.0",
		},
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	tree := s.engine.GetProcessTree()
	jsonRespond(w, 200, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"active_pids": len(tree),
			"uptime":      "running",
		},
	})
}

func (s *Server) handleThreats(w http.ResponseWriter, r *http.Request) {
	anomalies := s.engine.GetAnomalies()
	jsonRespond(w, 200, APIResponse{
		Success: true,
		Data:    anomalies,
	})
}

func (s *Server) handleProcesses(w http.ResponseWriter, r *http.Request) {
	tree := s.engine.GetProcessTree()
	jsonRespond(w, 200, APIResponse{
		Success: true,
		Data:    tree,
	})
}

func (s *Server) handleDumps(w http.ResponseWriter, r *http.Request) {
	dumps := s.forensics.ListDumps()
	jsonRespond(w, 200, APIResponse{
		Success: true,
		Data:    dumps,
	})
}

func (s *Server) handleSandbox(w http.ResponseWriter, r *http.Request) {
	instances := s.sandbox.ListInstances()
	jsonRespond(w, 200, APIResponse{
		Success: true,
		Data:    instances,
	})
}

func (s *Server) handleBaseline(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		if err := s.engine.BuildBaseline(); err != nil {
			jsonError(w, 500, err.Error())
			return
		}
		jsonRespond(w, 200, APIResponse{Success: true, Data: "baseline rebuilt"})
		return
	}
	jsonRespond(w, 200, APIResponse{Success: true, Data: "use POST to rebuild baseline"})
}

func (s *Server) handleHermesAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, 405, "POST required")
		return
	}

	var threat types.Threat
	if err := json.NewDecoder(r.Body).Decode(&threat); err != nil {
		jsonError(w, 400, "invalid request body")
		return
	}

	if s.hermes == nil {
		jsonError(w, 503, "Hermes bridge not configured")
		return
	}

	analysis, err := s.hermes.AnalyzeThreat(&threat, s.engine.GetProcessTree())
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}

	jsonRespond(w, 200, APIResponse{Success: true, Data: analysis})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	jsonRespond(w, 200, APIResponse{Success: true, Data: s.cfg})
}

func (s *Server) handleYaraRules(w http.ResponseWriter, r *http.Request) {
	jsonRespond(w, 200, APIResponse{Success: true, Data: map[string]interface{}{"rule_count": s.yara.GetRuleCount()}})
}
func (s *Server) handleYaraScan(w http.ResponseWriter, r *http.Request) {
	jsonRespond(w, 200, APIResponse{Success: true, Data: map[string]interface{}{"rule_count": s.yara.GetRuleCount(), "message": "YARA engine loaded"}})
}
func (s *Server) handleRootkitScan(w http.ResponseWriter, r *http.Request) {
	d := rootkit.NewDetector()
	findings := d.Scan()
	jsonRespond(w, 200, APIResponse{Success: true, Data: map[string]interface{}{"findings": findings, "count": len(findings)}})
}
func (s *Server) handleSigmaRules(w http.ResponseWriter, r *http.Request) {
	jsonRespond(w, 200, APIResponse{Success: true, Data: map[string]interface{}{"rule_count": s.sigma.GetRuleCount()}})
}
func (s *Server) handleMITRETechniques(w http.ResponseWriter, r *http.Request) {
	jsonRespond(w, 200, APIResponse{Success: true, Data: map[string]interface{}{"technique_count": s.mitre.GetTechniqueCount(), "tactic_count": s.mitre.GetTacticCount()}})
}
func (s *Server) handleMITRETactics(w http.ResponseWriter, r *http.Request) {
	tactics := s.mitre.GetTactics()
	jsonRespond(w, 200, APIResponse{Success: true, Data: tactics})
}
func (s *Server) handleComplianceFrameworks(w http.ResponseWriter, r *http.Request) {
	frameworks := s.compliance.GetFrameworks()
	jsonRespond(w, 200, APIResponse{Success: true, Data: frameworks})
}
func (s *Server) handleComplianceRun(w http.ResponseWriter, r *http.Request) {
	reports := s.compliance.RunFrameworks()
	jsonRespond(w, 200, APIResponse{Success: true, Data: reports})
}
func (s *Server) handleResponsePlaybooks(w http.ResponseWriter, r *http.Request) {
	playbooks := s.response.GetPlaybooks()
	jsonRespond(w, 200, APIResponse{Success: true, Data: playbooks})
}
func (s *Server) handleResponseExecute(w http.ResponseWriter, r *http.Request) {
	playbooks := s.response.GetPlaybooks()
	jsonRespond(w, 200, APIResponse{Success: true, Data: map[string]interface{}{"playbooks": len(playbooks), "message": "Response engine ready"}})
}
func (s *Server) handleTIIOCs(w http.ResponseWriter, r *http.Request) {
	stats := s.ti.GetIOCStats()
	jsonRespond(w, 200, APIResponse{Success: true, Data: stats})
}
func (s *Server) handleTIStats(w http.ResponseWriter, r *http.Request) {
	stats := s.ti.GetIOCStats()
	jsonRespond(w, 200, APIResponse{Success: true, Data: stats})
}
func (s *Server) handleDPIAnalyze(w http.ResponseWriter, r *http.Request) {
	summary := s.dpi.Summary()
	jsonRespond(w, 200, APIResponse{Success: true, Data: summary})
}
func (s *Server) handleContainerScan(w http.ResponseWriter, r *http.Request) {
	findings := s.container.GetFindings()
	jsonRespond(w, 200, APIResponse{Success: true, Data: map[string]interface{}{"findings": findings, "count": len(findings)}})
}
func (s *Server) handleMemoryAnalyze(w http.ResponseWriter, r *http.Request) {
	stats := s.memory.GetDumpStats()
	jsonRespond(w, 200, APIResponse{Success: true, Data: stats})
}

func jsonRespond(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	jsonRespond(w, status, APIResponse{Success: false, Error: msg})
}
