//go:build linux

package memory

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Dump struct {
	ID        string          `json:"id"`
	PID       uint32          `json:"pid"`
	Path      string          `json:"path"`
	Size      int64           `json:"size"`
	Timestamp time.Time       `json:"timestamp"`
	Regions   []*MemoryRegion `json:"regions"`
}

type MemoryRegion struct {
	Start   uint64 `json:"start"`
	End     uint64 `json:"end"`
	Perms   string `json:"perms"`
	Path    string `json:"path"`
	Content []byte `json:"-"`
}

type Artifact struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Offset  uint64 `json:"offset"`
	Context string `json:"context"`
}

type Analyzer struct {
	dumps []*Dump
	mu    sync.RWMutex
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) ParseMaps(pid uint32) ([]*MemoryRegion, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return nil, err
	}

	var regions []*MemoryRegion
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		addrRange := strings.Split(parts[0], "-")
		if len(addrRange) != 2 {
			continue
		}

		start, _ := strconv.ParseUint(addrRange[0], 16, 64)
		end, _ := strconv.ParseUint(addrRange[1], 16, 64)

		regions = append(regions, &MemoryRegion{
			Start: start,
			End:   end,
			Perms: parts[1],
			Path:  parts[len(parts)-1],
		})
	}

	return regions, nil
}

func (a *Analyzer) ExtractStrings(data []byte, minLen int) []string {
	var stringsList []string
	var current strings.Builder

	for _, b := range data {
		if b >= 32 && b <= 126 {
			current.WriteByte(b)
		} else {
			if current.Len() >= minLen {
				stringsList = append(stringsList, current.String())
			}
			current.Reset()
		}
	}

	return stringsList
}

func (a *Analyzer) FindIPs(data []byte) []string {
	var ips []string
	for i := 0; i < len(data)-4; i++ {
		if data[i] >= 1 && data[i] <= 255 &&
			data[i+1] >= 0 && data[i+1] <= 255 &&
			data[i+2] >= 0 && data[i+2] <= 255 &&
			data[i+3] >= 1 && data[i+3] <= 255 {
			ip := fmt.Sprintf("%d.%d.%d.%d", data[i], data[i+1], data[i+2], data[i+3])
			if net.ParseIP(ip) != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

func (a *Analyzer) FindURLs(data []byte) []string {
	content := string(data)
	var urls []string

	schemes := []string{"http://", "https://", "ftp://"}
	for _, scheme := range schemes {
		idx := 0
		for {
			pos := strings.Index(content[idx:], scheme)
			if pos < 0 {
				break
			}
			start := idx + pos
			end := start
			for end < len(content) && content[end] != ' ' && content[end] != '\n' && content[end] != '\r' && content[end] != 0 {
				end++
			}
			urls = append(urls, content[start:end])
			idx = end
		}
	}

	return urls
}

func (a *Analyzer) AnalyzeDump(path string) (*Dump, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	stat, _ := os.Stat(path)

	dump := &Dump{
		ID:        fmt.Sprintf("dump-%d", time.Now().UnixNano()),
		Path:      path,
		Size:      stat.Size(),
		Timestamp: time.Now(),
	}

	strings := a.ExtractStrings(data, 6)
	ips := a.FindIPs(data)
	urls := a.FindURLs(data)

	_ = strings
	_ = ips
	_ = urls

	return dump, nil
}

func (a *Analyzer) ScanForPatterns(data []byte) []*Artifact {
	var artifacts []*Artifact
	content := string(data)

	suspiciousStrings := []string{
		"/bin/sh", "/bin/bash", "nc -e", "ncat",
		"python -c", "perl -e", "ruby -e",
		"/etc/passwd", "/etc/shadow",
		"base64", "openssl",
	}

	for _, s := range suspiciousStrings {
		idx := strings.Index(content, s)
		if idx >= 0 {
			start := idx - 32
			if start < 0 {
				start = 0
			}
			end := idx + len(s) + 32
			if end > len(content) {
				end = len(content)
			}
			artifacts = append(artifacts, &Artifact{
				Type:    "suspicious_string",
				Value:   s,
				Offset:  uint64(idx),
				Context: content[start:end],
			})
		}
	}

	return artifacts
}

func (a *Analyzer) DetectShellcode(data []byte) []uint64 {
	var offsets []uint64
	nopSled := byte(0x90)
	count := 0
	startOffset := uint64(0)

	for i, b := range data {
		if b == nopSled {
			if count == 0 {
				startOffset = uint64(i)
			}
			count++
		} else {
			if count >= 16 {
				offsets = append(offsets, startOffset)
			}
			count = 0
		}
	}

	return offsets
}

func (a *Analyzer) ExtractPaths(data []byte) []string {
	var paths []string
	content := string(data)
	schemes := []string{"/usr/", "/etc/", "/var/", "/tmp/", "/home/", "/proc/"}

	for _, scheme := range schemes {
		idx := 0
		for {
			pos := strings.Index(content[idx:], scheme)
			if pos < 0 {
				break
			}
			start := idx + pos
			end := start
			for end < len(content) && content[end] != ' ' && content[end] != '\n' && content[end] != '\r' && content[end] != 0 {
				end++
			}
			path := content[start:end]
			if len(path) < 256 {
				paths = append(paths, path)
			}
			idx = end
		}
	}

	return paths
}

func (a *Analyzer) SaveDump(dump *Dump) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.dumps = append(a.dumps, dump)
	return nil
}

func (a *Analyzer) GetDumps() []*Dump {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]*Dump, len(a.dumps))
	copy(result, a.dumps)
	return result
}

// DetectProcessHollowing detects process hollowing in memory
func (a *Analyzer) DetectProcessHollowing(pid uint32) []*Artifact {
	var artifacts []*Artifact
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return artifacts
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.Contains(line, "(deleted)") && strings.Contains(line, "r-xp") {
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				artifacts = append(artifacts, &Artifact{
					Type:    "process_hollowing",
					Value:   parts[len(parts)-1],
					Offset:  0,
					Context: "Deleted executable mapped as executable - possible process hollowing",
				})
			}
		}
	}
	return artifacts
}

// ScanForShellcodePatterns scans for common shellcode patterns
func (a *Analyzer) ScanForShellcodePatterns(data []byte) []*Artifact {
	var artifacts []*Artifact

	windowsAPIs := []string{
		"VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
		"CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread",
		"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
	}

	content := string(data)
	for _, api := range windowsAPIs {
		idx := strings.Index(content, api)
		if idx >= 0 {
			artifacts = append(artifacts, &Artifact{
				Type:    "shellcode_api",
				Value:   api,
				Offset:  uint64(idx),
				Context: fmt.Sprintf("Shellcode API call detected: %s", api),
			})
		}
	}

	nopSled := byte(0x90)
	count := 0
	startOffset := uint64(0)
	for i, b := range data {
		if b == nopSled {
			if count == 0 {
				startOffset = uint64(i)
			}
			count++
		} else {
			if count >= 32 {
				artifacts = append(artifacts, &Artifact{
					Type:    "nop_sled",
					Value:   fmt.Sprintf("NOP sled of %d bytes", count),
					Offset:  startOffset,
					Context: "Large NOP sled detected - possible shellcode",
				})
			}
			count = 0
		}
	}

	return artifacts
}

// DetectShellcodePatterns is a convenience alias for ScanForShellcodePatterns
func (a *Analyzer) DetectShellcodePatterns(data []byte) []*Artifact {
	return a.ScanForShellcodePatterns(data)
}

// ExtractEnvironmentVariables extracts environment variables from memory
func (a *Analyzer) ExtractEnvironmentVariables(data []byte) []string {
	var envVars []string
	content := string(data)

	envPrefixes := []string{"PATH=", "HOME=", "USER=", "SHELL=", "LANG=", "TERM=", "PWD=", "LD_LIBRARY_PATH=", "PYTHONPATH="}

	for _, prefix := range envPrefixes {
		idx := 0
		for {
			pos := strings.Index(content[idx:], prefix)
			if pos < 0 {
				break
			}
			start := idx + pos
			end := start
			for end < len(content) && content[end] != 0 && content[end] != '\n' && content[end] != '\r' {
				end++
			}
			envVars = append(envVars, content[start:end])
			idx = end
		}
	}

	return envVars
}

// AnalyzeBinaryForMalware analyzes a binary for malware indicators
func (a *Analyzer) AnalyzeBinaryForMalware(path string) map[string]interface{} {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	result := map[string]interface{}{
		"file_size": len(data),
		"strings":   a.ExtractStrings(data, 6),
		"ips":       a.FindIPs(data),
		"urls":      a.FindURLs(data),
		"paths":     a.ExtractPaths(data),
		"shellcode": a.DetectShellcodePatterns(data),
		"artifacts": a.ScanForPatterns(data),
	}

	entropy := a.CalculateEntropy(data)
	result["entropy"] = entropy

	if entropy > 7.5 {
		result["packed"] = true
		result["suspicious"] = true
	} else {
		result["packed"] = false
	}

	return result
}

// CalculateEntropy calculates Shannon entropy of data
func (a *Analyzer) CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	size := float64(len(data))
	for _, count := range freq {
		p := float64(count) / size
		if p > 0 {
			entropy -= p * (log2(p))
		}
	}
	return entropy
}

func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	return math.Log(x) / math.Log(2)
}

// GetDumpStats returns statistics about all dumps
func (a *Analyzer) GetDumpStats() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	totalSize := int64(0)
	for _, dump := range a.dumps {
		totalSize += dump.Size
	}

	return map[string]interface{}{
		"total_dumps": len(a.dumps),
		"total_size":  totalSize,
	}
}

// SaveArtifacts saves extracted artifacts to a file
func (a *Analyzer) SaveArtifacts(artifacts []*Artifact, path string) error {
	data, err := json.MarshalIndent(artifacts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
