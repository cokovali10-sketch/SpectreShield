//go:build linux

package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/cokovali10-sketch/SpectreShield/correlation"
)

func (s *Server) handleCorrelationTimeline(w http.ResponseWriter, r *http.Request) {
	window := 5 * time.Minute
	if d := r.URL.Query().Get("window"); d != "" {
		if parsed, err := time.ParseDuration(d); err == nil {
			window = parsed
		}
	}

	timeline := s.correlation.GetTimeline(window)
	jsonRespond(w, 200, APIResponse{Success: true, Data: timeline})
}

func (s *Server) handleCorrelationChains(w http.ResponseWriter, r *http.Request) {
	chains := s.correlation.GetChains()
	jsonRespond(w, 200, APIResponse{Success: true, Data: chains})
}

func (s *Server) handleCorrelationAddEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, 405, "POST required")
		return
	}

	var event correlation.Event
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		jsonError(w, 400, "invalid request body")
		return
	}

	event.Timestamp = time.Now()
	s.correlation.AddEvent(event)

	jsonRespond(w, 200, APIResponse{Success: true, Data: map[string]interface{}{
		"event_id": event.ID,
		"status":   "added",
	}})
}

func (s *Server) handleCorrelationTree(w http.ResponseWriter, r *http.Request) {
	pid := uint32(1)
	depth := 5

	if p := r.URL.Query().Get("pid"); p != "" {
		if parsed, err := strconv.ParseUint(p, 10, 32); err == nil {
			pid = uint32(parsed)
		}
	}
	if d := r.URL.Query().Get("depth"); d != "" {
		if parsed, err := strconv.Atoi(d); err == nil {
			depth = parsed
		}
	}

	tree := s.correlation.GetProcessTree(pid, depth)
	jsonRespond(w, 200, APIResponse{Success: true, Data: tree})
}

func (s *Server) handleCorrelationStats(w http.ResponseWriter, r *http.Request) {
	stats := s.correlation.GetStats()
	jsonRespond(w, 200, APIResponse{Success: true, Data: stats})
}
