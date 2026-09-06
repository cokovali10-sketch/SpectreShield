//go:build linux

package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cokovali10-sketch/SpectreShield/engine"
	"github.com/cokovali10-sketch/SpectreShield/forensics"
	hermesbridge "github.com/cokovali10-sketch/SpectreShield/hermes-bridge"
	"github.com/cokovali10-sketch/SpectreShield/internal/config"
	"github.com/cokovali10-sketch/SpectreShield/internal/types"
	"github.com/cokovali10-sketch/SpectreShield/sandbox"
)

type Server struct {
	cfg       *config.Config
	engine    *engine.Engine
	forensics *forensics.ForensicsEngine
	sandbox   *sandbox.Sandbox
	hermes    *hermesbridge.Bridge
	mux       *http.ServeMux
}

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func NewServer(cfg *config.Config, e *engine.Engine, f *forensics.ForensicsEngine, s *sandbox.Sandbox, h *hermesbridge.Bridge) *Server {
	return &Server{
		cfg:       cfg,
		engine:    e,
		forensics: f,
		sandbox:   s,
		hermes:    h,
		mux:       http.NewServeMux(),
	}
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
}

func (s *Server) Start() error {
	s.SetupRoutes()
	fmt.Printf("SpectreShield API listening on %s\n", s.cfg.API.Addr)
	return http.ListenAndServe(s.cfg.API.Addr, s.mux)
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

func jsonRespond(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	jsonRespond(w, status, APIResponse{Success: false, Error: msg})
}
