//go:build linux

package netforensics

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type Flow struct {
	ID        string        `json:"id"`
	SrcIP     net.IP        `json:"src_ip"`
	DstIP     net.IP        `json:"dst_ip"`
	SrcPort   uint16        `json:"src_port"`
	DstPort   uint16        `json:"dst_port"`
	Protocol  string        `json:"protocol"`
	BytesIn   uint64        `json:"bytes_in"`
	BytesOut  uint64        `json:"bytes_out"`
	Packets   uint64        `json:"packets"`
	Duration  time.Duration `json:"duration"`
	FirstSeen time.Time     `json:"first_seen"`
	LastSeen  time.Time     `json:"last_seen"`
}

type DNSRecord struct {
	Query     string    `json:"query"`
	Response  string    `json:"response"`
	Type      string    `json:"type"`
	TTL       uint32    `json:"ttl"`
	Timestamp time.Time `json:"timestamp"`
}

type Analyzer struct {
	flows map[string]*Flow
	dns   []*DNSRecord
	mu    sync.RWMutex
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		flows: make(map[string]*Flow),
	}
}

func (a *Analyzer) ParsePCAP(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	header := make([]byte, 24)
	if _, err := file.Read(header); err != nil {
		return err
	}

	magic := binary.LittleEndian.Uint32(header[0:4])
	if magic != 0xa1b2c3d4 && magic != 0xd4c3b2a1 {
		return fmt.Errorf("not a valid PCAP file")
	}

	for {
		pktHeader := make([]byte, 16)
		if _, err := file.Read(pktHeader); err != nil {
			break
		}

		inclLen := binary.LittleEndian.Uint32(pktHeader[8:12])
		pktData := make([]byte, inclLen)
		if _, err := file.Read(pktData); err != nil {
			break
		}

		a.parsePacket(pktData)
	}

	return nil
}

func (a *Analyzer) parsePacket(data []byte) {
	if len(data) < 14 {
		return
	}

	etherType := binary.BigEndian.Uint16(data[12:14])
	offset := 14

	if etherType == 0x0800 && len(data) >= offset+20 {
		ipHeader := data[offset:]
		protocol := ipHeader[9]
		srcIP := net.IP(ipHeader[12:16])
		dstIP := net.IP(ipHeader[16:20])

		ipHeaderLen := int(ipHeader[0]&0x0F) * 4
		offset += ipHeaderLen

		var srcPort, dstPort uint16
		proto := "unknown"

		if protocol == 6 && len(data) >= offset+4 {
			srcPort = binary.BigEndian.Uint16(data[offset : offset+2])
			dstPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
			proto = "tcp"
		} else if protocol == 17 && len(data) >= offset+4 {
			srcPort = binary.BigEndian.Uint16(data[offset : offset+2])
			dstPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
			proto = "udp"
		}

		key := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
		a.mu.Lock()
		if flow, ok := a.flows[key]; ok {
			flow.BytesOut += uint64(len(data))
			flow.Packets++
			flow.LastSeen = time.Now()
		} else {
			a.flows[key] = &Flow{
				ID:        key,
				SrcIP:     srcIP,
				DstIP:     dstIP,
				SrcPort:   srcPort,
				DstPort:   dstPort,
				Protocol:  proto,
				BytesOut:  uint64(len(data)),
				Packets:   1,
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
			}
		}
		a.mu.Unlock()
	}
}

func (a *Analyzer) GetFlows() []*Flow {
	a.mu.RLock()
	defer a.mu.RUnlock()
	flows := make([]*Flow, 0, len(a.flows))
	for _, f := range a.flows {
		flows = append(flows, f)
	}
	return flows
}

func (a *Analyzer) DetectAnomalies() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var anomalies []string

	for _, flow := range a.flows {
		if flow.BytesOut > 100*1024*1024 {
			anomalies = append(anomalies, fmt.Sprintf("Large transfer: %s sent %d bytes", flow.SrcIP, flow.BytesOut))
		}
	}

	srcPorts := make(map[string]map[uint16]bool)
	for _, flow := range a.flows {
		if srcPorts[flow.SrcIP.String()] == nil {
			srcPorts[flow.SrcIP.String()] = make(map[uint16]bool)
		}
		srcPorts[flow.SrcIP.String()][flow.DstPort] = true
	}

	for ip, ports := range srcPorts {
		if len(ports) > 100 {
			anomalies = append(anomalies, fmt.Sprintf("Port scan from %s: %d ports", ip, len(ports)))
		}
	}

	return anomalies
}

func (a *Analyzer) GetFlowStats() map[string]uint64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	stats := map[string]uint64{
		"total_flows":   uint64(len(a.flows)),
		"total_bytes":   0,
		"total_packets": 0,
	}
	for _, f := range a.flows {
		stats["total_bytes"] += f.BytesOut + f.BytesIn
		stats["total_packets"] += f.Packets
	}
	return stats
}

func (a *Analyzer) FilterByIP(ip string) []*Flow {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var flows []*Flow
	for _, f := range a.flows {
		if f.SrcIP.String() == ip || f.DstIP.String() == ip {
			flows = append(flows, f)
		}
	}
	return flows
}

func (a *Analyzer) FilterByPort(port uint16) []*Flow {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var flows []*Flow
	for _, f := range a.flows {
		if f.SrcPort == port || f.DstPort == port {
			flows = append(flows, f)
		}
	}
	return flows
}

func (a *Analyzer) ExportFlows(path string) error {
	data, err := json.MarshalIndent(a.GetFlows(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// AnalyzeFlowPatterns analyzes network flow patterns for anomalies
func (a *Analyzer) AnalyzeFlowPatterns() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var anomalies []string

	flowTimes := make(map[string][]time.Time)
	for _, flow := range a.flows {
		key := flow.DstIP.String()
		flowTimes[key] = append(flowTimes[key], flow.FirstSeen)
	}

	for ip, times := range flowTimes {
		if len(times) >= 5 {
			intervals := make([]time.Duration, len(times)-1)
			for i := 1; i < len(times); i++ {
				intervals[i-1] = times[i].Sub(times[i-1])
			}
			if len(intervals) >= 2 {
				avg := intervals[0]
				for _, iv := range intervals[1:] {
					avg += iv
				}
				avg /= time.Duration(len(intervals))

				variance := 0.0
				for _, iv := range intervals {
					diff := float64(iv - avg)
					variance += diff * diff
				}
				variance /= float64(len(intervals))

				if variance < float64(avg)*0.1 {
					anomalies = append(anomalies, fmt.Sprintf("Possible beaconing to %s (regular intervals, avg %v)", ip, avg))
				}
			}
		}
	}

	for _, flow := range a.flows {
		if flow.BytesOut > 10*1024*1024 && flow.Duration < time.Minute {
			anomalies = append(anomalies, fmt.Sprintf("Possible data exfiltration: %s sent %d bytes in %v", flow.SrcIP, flow.BytesOut, flow.Duration))
		}
	}

	return anomalies
}

// GetTopTalkers returns the top source/destination IPs by volume
func (a *Analyzer) GetTopTalkers(limit int) map[string][]string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	srcVolumes := make(map[string]uint64)
	dstVolumes := make(map[string]uint64)

	for _, flow := range a.flows {
		src := flow.SrcIP.String()
		dst := flow.DstIP.String()
		srcVolumes[src] += flow.BytesOut
		dstVolumes[dst] += flow.BytesIn
	}

	result := map[string][]string{
		"top_sources":      make([]string, 0, limit),
		"top_destinations": make([]string, 0, limit),
	}

	type kv struct {
		key   string
		value uint64
	}
	var srcSorted []kv
	for k, v := range srcVolumes {
		srcSorted = append(srcSorted, kv{k, v})
	}
	for i := 0; i < len(srcSorted)-1; i++ {
		for j := i + 1; j < len(srcSorted); j++ {
			if srcSorted[j].value > srcSorted[i].value {
				srcSorted[i], srcSorted[j] = srcSorted[j], srcSorted[i]
			}
		}
	}
	for i := 0; i < limit && i < len(srcSorted); i++ {
		result["top_sources"] = append(result["top_sources"], srcSorted[i].key)
	}

	var dstSorted []kv
	for k, v := range dstVolumes {
		dstSorted = append(dstSorted, kv{k, v})
	}
	for i := 0; i < len(dstSorted)-1; i++ {
		for j := i + 1; j < len(dstSorted); j++ {
			if dstSorted[j].value > dstSorted[i].value {
				dstSorted[i], dstSorted[j] = dstSorted[j], dstSorted[i]
			}
		}
	}
	for i := 0; i < limit && i < len(dstSorted); i++ {
		result["top_destinations"] = append(result["top_destinations"], dstSorted[i].key)
	}

	return result
}

// GetProtocolDistribution returns protocol usage distribution
func (a *Analyzer) GetProtocolDistribution() map[string]int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	dist := make(map[string]int)
	for _, flow := range a.flows {
		dist[flow.Protocol]++
	}
	return dist
}

// GetPortScanSources returns IPs that may be scanning
func (a *Analyzer) GetPortScanSources() map[string]int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	srcPorts := make(map[string]map[uint16]bool)
	for _, flow := range a.flows {
		if srcPorts[flow.SrcIP.String()] == nil {
			srcPorts[flow.SrcIP.String()] = make(map[uint16]bool)
		}
		srcPorts[flow.SrcIP.String()][flow.DstPort] = true
	}

	scanners := make(map[string]int)
	for ip, ports := range srcPorts {
		if len(ports) > 50 {
			scanners[ip] = len(ports)
		}
	}
	return scanners
}

// DetectDNSAnomalies detects DNS-based anomalies
func (a *Analyzer) DetectDNSAnomalies() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var anomalies []string
	for _, record := range a.dns {
		if len(record.Query) > 50 {
			anomalies = append(anomalies, fmt.Sprintf("Long DNS query: %s", record.Query))
		}

		if len(record.Query) > 20 {
			entropy := 0.0
			freq := make(map[rune]int)
			for _, c := range record.Query {
				freq[c]++
			}
			size := float64(len(record.Query))
			for _, count := range freq {
				p := float64(count) / size
				if p > 0 {
					entropy -= p * logFloat(p)
				}
			}
			if entropy > 3.5 {
				anomalies = append(anomalies, fmt.Sprintf("High-entropy DNS query: %s (entropy: %.2f)", record.Query, entropy))
			}
		}
	}
	return anomalies
}

func logFloat(x float64) float64 {
	if x <= 0 {
		return 0
	}
	result := 0.0
	for x >= 2 {
		x /= 2
		result++
	}
	return result
}

// GenerateReport generates a network forensics report
func (a *Analyzer) GenerateReport() string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	report := "# Network Forensics Report\n\n"
	report += fmt.Sprintf("Generated: %s\n", time.Now().Format(time.RFC3339))
	report += fmt.Sprintf("Total Flows: %d\n", len(a.flows))
	report += fmt.Sprintf("Total DNS Records: %d\n\n", len(a.dns))

	protocolDist := a.GetProtocolDistribution()
	report += "## Protocol Distribution\n"
	for proto, count := range protocolDist {
		report += fmt.Sprintf("- %s: %d\n", proto, count)
	}

	return report
}
