//go:build linux

package dpi

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Protocol represents a detected protocol
type Protocol struct {
	Name    string `json:"name"`
	Layer   string `json:"layer"`
	Port    uint16 `json:"port"`
	Payload []byte `json:"payload,omitempty"`
}

// Packet represents a parsed network packet
type Packet struct {
	Timestamp   time.Time `json:"timestamp"`
	SrcIP       net.IP    `json:"src_ip"`
	DstIP       net.IP    `json:"dst_ip"`
	SrcPort     uint16    `json:"src_port"`
	DstPort     uint16    `json:"dst_port"`
	Protocol    string    `json:"protocol"`
	Length      int       `json:"length"`
	Flags       string    `json:"flags"`
	Payload     []byte    `json:"payload"`
	Application string    `json:"application"`
	TLSVersion  string    `json:"tls_version,omitempty"`
	SNI         string    `json:"sni,omitempty"`
	HTTPHost    string    `json:"http_host,omitempty"`
	HTTPMethod  string    `json:"http_method,omitempty"`
	HTTPPath    string    `json:"http_path,omitempty"`
	DNSQuery    string    `json:"dns_query,omitempty"`
	DNSResponse string    `json:"dns_response,omitempty"`
}

// Finding represents a DPI finding
type Finding struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Packet      *Packet   `json:"packet"`
	Timestamp   time.Time `json:"timestamp"`
}

// Engine is the DPI engine
type Engine struct {
	findings   []*Finding
	synTracker map[string]int
	mu         sync.RWMutex
}

// NewEngine creates a new DPI engine
func NewEngine() *Engine {
	return &Engine{
		synTracker: make(map[string]int),
	}
}

// AnalyzePacket analyzes a raw packet
func (e *Engine) AnalyzePacket(data []byte) *Packet {
	pkt := &Packet{
		Timestamp: time.Now(),
		Length:    len(data),
	}

	if len(data) < 14 {
		return pkt
	}

	etherType := binary.BigEndian.Uint16(data[12:14])
	offset := 14

	if etherType == 0x0800 {
		if len(data) >= offset+20 {
			ipHeader := data[offset:]
			protocol := ipHeader[9]
			srcIP := net.IP(ipHeader[12:16])
			dstIP := net.IP(ipHeader[16:20])
			pkt.SrcIP = srcIP
			pkt.DstIP = dstIP
			pkt.Protocol = fmt.Sprintf("%d", protocol)

			ipHeaderLen := int(ipHeader[0]&0x0F) * 4
			offset += ipHeaderLen

			if protocol == 6 && len(data) >= offset+20 {
				pkt.SrcPort = binary.BigEndian.Uint16(data[offset : offset+2])
				pkt.DstPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
				tcpHeaderLen := int(data[offset+12]>>4) * 4
				pkt.Flags = e.parseTCPFlags(data[offset+13])
				offset += tcpHeaderLen
				e.analyzePayload(pkt, data[offset:])
			}

			if protocol == 17 && len(data) >= offset+8 {
				pkt.SrcPort = binary.BigEndian.Uint16(data[offset : offset+2])
				pkt.DstPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
				udpLen := binary.BigEndian.Uint16(data[offset+4 : offset+6])
				offset += 8
				if offset+int(udpLen)-8 <= len(data) {
					e.analyzePayload(pkt, data[offset:offset+int(udpLen)-8])
				}
			}
		}
	}

	return pkt
}

func (e *Engine) analyzePayload(pkt *Packet, payload []byte) {
	if len(payload) == 0 {
		return
	}

	pkt.Payload = payload

	if len(payload) >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
		version := binary.BigEndian.Uint16(payload[1:3])
		versions := map[uint16]string{
			0x0301: "TLS 1.0",
			0x0302: "TLS 1.1",
			0x0303: "TLS 1.2",
			0x0304: "TLS 1.3",
		}
		pkt.TLSVersion = versions[version]
		pkt.Application = "TLS"
		if payload[5] == 0x01 {
			e.extractSNI(pkt, payload)
		}
	}

	if len(payload) >= 3 {
		if string(payload[:3]) == "GET" || string(payload[:4]) == "POST" || string(payload[:3]) == "PUT" || string(payload[:4]) == "HTTP" {
			pkt.Application = "HTTP"
			e.parseHTTP(pkt, payload)
		}
	}

	if pkt.DstPort == 53 || pkt.SrcPort == 53 {
		pkt.Application = "DNS"
		e.parseDNS(pkt, payload)
	}

	if len(payload) >= 4 && string(payload[:4]) == "SSH-" {
		pkt.Application = "SSH"
	}

	if len(payload) >= 3 && string(payload[:3]) == "220" {
		pkt.Application = "FTP"
	}

	if len(payload) >= 4 && string(payload[:4]) == "220 " {
		pkt.Application = "SMTP"
	}

	if len(payload) >= 4 && string(payload[:4]) == "EHLO" {
		pkt.Application = "SMTP"
	}

	if len(payload) >= 5 && string(payload[:5]) == "* OK" {
		pkt.Application = "IMAP"
	}
}

func (e *Engine) extractSNI(pkt *Packet, payload []byte) {
	if len(payload) < 43 {
		return
	}

	sessionIDLen := int(payload[43])
	offset := 44 + sessionIDLen

	if offset+2 > len(payload) {
		return
	}

	cipherSuiteLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2 + cipherSuiteLen

	if offset+1 > len(payload) {
		return
	}

	compressionLen := int(payload[offset])
	offset += 1 + compressionLen

	for offset+4 <= len(payload) {
		extType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		if extType == 0x0000 {
			if offset+5 <= len(payload) {
				listLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
				_ = listLen
				nameType := payload[offset+2]
				nameLen := int(binary.BigEndian.Uint16(payload[offset+3 : offset+5]))
				if nameType == 0 && offset+5+nameLen <= len(payload) {
					pkt.SNI = string(payload[offset+5 : offset+5+nameLen])
				}
			}
			break
		}

		offset += extLen
	}
}

func (e *Engine) parseHTTP(pkt *Packet, payload []byte) {
	lines := strings.Split(string(payload), "\r\n")
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			pkt.HTTPMethod = parts[0]
			pkt.HTTPPath = parts[1]
		}
	}

	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "Host:") {
			pkt.HTTPHost = strings.TrimSpace(strings.TrimPrefix(line, "Host:"))
		}
	}
}

func (e *Engine) parseDNS(pkt *Packet, payload []byte) {
	if len(payload) < 12 {
		return
	}

	qdCount := binary.BigEndian.Uint16(payload[4:6])
	if qdCount > 0 && len(payload) > 12 {
		offset := 12
		for i := 0; i < int(qdCount) && offset < len(payload); i++ {
			var name strings.Builder
			for offset < len(payload) {
				labelLen := int(payload[offset])
				if labelLen == 0 {
					offset++
					break
				}
				offset++
				if offset+labelLen <= len(payload) {
					name.WriteString(string(payload[offset : offset+labelLen]))
					name.WriteString(".")
					offset += labelLen
				}
			}
			pkt.DNSQuery = name.String()
			offset += 4
		}
	}
}

func (e *Engine) parseTCPFlags(flags byte) string {
	var result []string
	if flags&0x01 != 0 {
		result = append(result, "FIN")
	}
	if flags&0x02 != 0 {
		result = append(result, "SYN")
	}
	if flags&0x04 != 0 {
		result = append(result, "RST")
	}
	if flags&0x08 != 0 {
		result = append(result, "PSH")
	}
	if flags&0x10 != 0 {
		result = append(result, "ACK")
	}
	if flags&0x20 != 0 {
		result = append(result, "URG")
	}
	return strings.Join(result, ",")
}

// DetectThreats analyzes a packet for threats
func (e *Engine) DetectThreats(pkt *Packet) []*Finding {
	var findings []*Finding

	if pkt.DNSQuery != "" && len(pkt.DNSQuery) > 50 {
		findings = append(findings, &Finding{
			ID:          fmt.Sprintf("dns-tunnel-%d", time.Now().UnixNano()),
			Type:        "dns_tunneling",
			Severity:    "high",
			Title:       "Possible DNS tunneling",
			Description: fmt.Sprintf("Unusually long DNS query: %s", pkt.DNSQuery),
			Packet:      pkt,
			Timestamp:   time.Now(),
		})
	}

	if pkt.HTTPMethod != "" {
		suspiciousPaths := []string{"/etc/passwd", "/etc/shadow", "/cmd.exe", "/shell", "/admin", "/wp-login", "/.env", "/config"}
		for _, path := range suspiciousPaths {
			if strings.Contains(pkt.HTTPPath, path) {
				findings = append(findings, &Finding{
					ID:          fmt.Sprintf("http-suspicious-%d", time.Now().UnixNano()),
					Type:        "suspicious_http",
					Severity:    "high",
					Title:       "Suspicious HTTP request",
					Description: fmt.Sprintf("Access to sensitive path: %s", path),
					Packet:      pkt,
					Timestamp:   time.Now(),
				})
			}
		}
	}

	if pkt.Flags == "SYN" {
		e.mu.Lock()
		srcKey := pkt.SrcIP.String()
		e.synTracker[srcKey]++
		count := e.synTracker[srcKey]
		e.mu.Unlock()

		if count > 100 {
			findings = append(findings, &Finding{
				ID:          fmt.Sprintf("syn-flood-%d", time.Now().UnixNano()),
				Type:        "syn_flood",
				Severity:    "critical",
				Title:       "Possible SYN flood attack",
				Description: fmt.Sprintf("Source %s sent %d SYN packets", srcKey, count),
				Packet:      pkt,
				Timestamp:   time.Now(),
			})
		}
	}

	if pkt.Application == "SSH" && pkt.SrcPort != 22 && pkt.DstPort != 22 {
		findings = append(findings, &Finding{
			ID:          fmt.Sprintf("ssh-nonstandard-%d", time.Now().UnixNano()),
			Type:        "nonstandard_ssh",
			Severity:    "medium",
			Title:       "SSH on non-standard port",
			Description: "SSH connection detected on non-standard port",
			Packet:      pkt,
			Timestamp:   time.Now(),
		})
	}

	if pkt.TLSVersion == "TLS 1.0" || pkt.TLSVersion == "TLS 1.1" {
		findings = append(findings, &Finding{
			ID:          fmt.Sprintf("weak-tls-%d", time.Now().UnixNano()),
			Type:        "weak_tls",
			Severity:    "medium",
			Title:       "Weak TLS version",
			Description: fmt.Sprintf("Connection using %s", pkt.TLSVersion),
			Packet:      pkt,
			Timestamp:   time.Now(),
		})
	}

	return findings
}

// GetFindings returns all findings
func (e *Engine) GetFindings() []*Finding {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*Finding, len(e.findings))
	copy(result, e.findings)
	return result
}

// AddFinding adds a finding to the engine
func (e *Engine) AddFinding(f *Finding) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.findings = append(e.findings, f)
}

// ClearFindings clears all findings
func (e *Engine) ClearFindings() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.findings = nil
}

// Summary returns a summary of findings by severity
func (e *Engine) Summary() map[string]int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	summary := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}
	for _, f := range e.findings {
		summary[f.Severity]++
	}
	return summary
}

// FilterBySeverity returns findings matching the given severity
func (e *Engine) FilterBySeverity(severity string) []*Finding {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var result []*Finding
	for _, f := range e.findings {
		if f.Severity == severity {
			result = append(result, f)
		}
	}
	return result
}

// FilterByType returns findings matching the given type
func (e *Engine) FilterByType(fType string) []*Finding {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var result []*Finding
	for _, f := range e.findings {
		if f.Type == fType {
			result = append(result, f)
		}
	}
	return result
}

// ResetSYNTracker resets the SYN flood tracker
func (e *Engine) ResetSYNTracker() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.synTracker = make(map[string]int)
}

// FindingCount returns the number of findings
func (e *Engine) FindingCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.findings)
}
