//go:build linux

package netforensics

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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
		"total_flows":  uint64(len(a.flows)),
		"total_bytes":  0,
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
