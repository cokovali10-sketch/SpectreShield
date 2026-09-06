//go:build linux

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/cokovali10-sketch/SpectreShield/internal/logging"
	"github.com/cokovali10-sketch/SpectreShield/internal/types"
)

type WSClient struct {
	ID   string
	Send chan []byte
	Done chan struct{}
}

type WSHub struct {
	clients    map[string]*WSClient
	register   chan *WSClient
	unregister chan *WSClient
	broadcast  chan []byte
	mu         sync.RWMutex
	log        *logging.Logger
}

func NewWSHub() *WSHub {
	return &WSHub{
		clients:    make(map[string]*WSClient),
		register:   make(chan *WSClient, 64),
		unregister: make(chan *WSClient, 64),
		broadcast:  make(chan []byte, 256),
		log:        logging.WithComponent("websocket"),
	}
}

func (h *WSHub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client.ID] = client
			h.mu.Unlock()
			h.log.Info("websocket client connected", "id", client.ID, "total", len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client.ID]; ok {
				delete(h.clients, client.ID)
				close(client.Send)
			}
			h.mu.Unlock()
			h.log.Info("websocket client disconnected", "id", client.ID, "total", len(h.clients))

		case message := <-h.broadcast:
			h.mu.RLock()
			for _, client := range h.clients {
				select {
				case client.Send <- message:
				default:
					close(client.Send)
					delete(h.clients, client.ID)
				}
			}
			h.mu.RUnlock()
		}
	}
}

func (h *WSHub) BroadcastThreat(threat *types.Threat) {
	msg := map[string]interface{}{
		"type":    "threat",
		"payload": threat,
	}
	data, _ := json.Marshal(msg)
	select {
	case h.broadcast <- data:
	default:
	}
}

func (h *WSHub) BroadcastStats(stats *types.DaemonStats) {
	msg := map[string]interface{}{
		"type":    "stats",
		"payload": stats,
	}
	data, _ := json.Marshal(msg)
	select {
	case h.broadcast <- data:
	default:
	}
}

func (h *WSHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	_ = fmt.Sprintf("sse-%d", time.Now().UnixNano())
	done := make(chan struct{})
	defer close(done)

	stats := &types.DaemonStats{
		ActivePIDs: len(s.engine.GetProcessTree()),
	}
	data, _ := json.Marshal(stats)
	fmt.Fprintf(w, "event: stats\ndata: %s\n\n", string(data))
	flusher.Flush()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-r.Context().Done():
			return
		case <-ticker.C:
			stats := &types.DaemonStats{
				ActivePIDs: len(s.engine.GetProcessTree()),
			}
			data, _ := json.Marshal(stats)
			fmt.Fprintf(w, "event: stats\ndata: %s\n\n", string(data))
			flusher.Flush()
		}
	}
}

func (s *Server) getThreatChannel() <-chan []types.Threat {
	ch := make(chan []types.Threat, 1)
	return ch
}
