//go:build linux

package analyzer

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cokovali10-sketch/SpectreShield/internal/config"
	"github.com/cokovali10-sketch/SpectreShield/internal/logging"
)

// Analyzer performs static heuristic analysis on binaries
type Analyzer struct {
	cfg *config.Config
	log *logging.Logger
	mu  sync.Mutex
}

// AnalysisResult contains the full analysis result
type AnalysisResult struct {
	ID          string    `json:"id"`
	FilePath    string    `json:"file_path"`
	FileName    string    `json:"file_name"`
	FileSize    int64     `json:"file_size"`
	MD5         string    `json:"md5"`
	SHA256      string    `json:"sha256"`
	Entropy     float64   `json:"entropy"`
	IsPacked    bool      `json:"is_packed"`
	IsEncrypted bool      `json:"is_encrypted"`
	Verdict     string    `json:"verdict"` // "clean", "suspicious", "malicious"
	Confidence  float64   `json:"confidence"`
	RiskScore   float64   `json:"risk_score"`
	Findings    []Finding `json:"findings"`
	Strings     []string  `json:"suspicious_strings,omitempty"`
	IPs         []string  `json:"embedded_ips,omitempty"`
	Ports       []uint16  `json:"embedded_ports,omitempty"`
	ExeInfo     *ExeInfo  `json:"exe_info,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// Finding represents a single finding
type Finding struct {
	Category    string  `json:"category"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"` // "info", "low", "medium", "high", "critical"
	Confidence  float64 `json:"confidence"`
	Evidence    string  `json:"evidence"`
}

// ExeInfo contains executable format information
type ExeInfo struct {
	Format      string   `json:"format"` // "elf", "pe", "macho", "unknown"
	Arch        string   `json:"arch"`
	Sections    []string `json:"sections,omitempty"`
	EntryPoint  string   `json:"entry_point,omitempty"`
	Interpreter string   `json:"interpreter,omitempty"`
	Libraries   []string `json:"libraries,omitempty"`
}

// Known malicious strings
var maliciousStrings = []struct {
	Pattern  string
	Category string
	Severity string
}{
	{`/bin/sh`, "shell_execution", "high"},
	{`/bin/bash`, "shell_execution", "high"},
	{`curl.*\|.*sh`, "download_execute", "critical"},
	{`wget.*\|.*sh`, "download_execute", "critical"},
	{`python.*-c.*socket`, "reverse_shell", "critical"},
	{`python.*-c.*subprocess`, "command_execution", "high"},
	{`nc.*-e`, "netcat_shell", "critical"},
	{`ncat.*-e`, "netcat_shell", "critical"},
	{`/dev/tcp/`, "bash_reverse_shell", "critical"},
	{`chmod.*777`, "permission_abuse", "medium"},
	{`chown.*root`, "privilege_escalation", "high"},
	{`rm.*-rf.*\/`, "destructive", "critical"},
	{`dd.*if=\/dev\/zero`, "destructive", "high"},
	{`mkfs`, "destructive", "high"},
	{`/etc/passwd`, "sensitive_file", "medium"},
	{`/etc/shadow`, "sensitive_file", "high"},
	{`/etc/sudoers`, "sensitive_file", "high"},
	{`/root/.ssh`, "ssh_keys", "high"},
	{`authorized_keys`, "ssh_keys", "high"},
	{`id_rsa`, "ssh_keys", "high"},
	{`/proc/self/mem`, "process_injection", "high"},
	{`/dev/mem`, "kernel_access", "critical"},
	{`/dev/kmem`, "kernel_access", "critical"},
	{`ptrace`, "anti_debug", "medium"},
	{`PTRACE_ATTACH`, "anti_debug", "medium"},
	{`LD_PRELOAD`, "hooking", "high"},
	{`/etc/ld.so.preload`, "hooking", "high"},
	{`dlopen`, "dynamic_loading", "low"},
	{`mprotect`, "memory_protection", "low"},
	{`mmap`, "memory_mapping", "info"},
	{`fork`, "process_creation", "info"},
	{`execve`, "process_execution", "info"},
	{`setuid`, "privilege_change", "high"},
	{`setgid`, "privilege_change", "high"},
	{`chroot`, "sandbox_escape", "high"},
	{`mount`, "filesystem_modification", "medium"},
	{`umount`, "filesystem_modification", "medium"},
	{`init_module`, "kernel_module", "critical"},
	{`finit_module`, "kernel_module", "critical"},
	{`delete_module`, "kernel_module", "critical"},
	{`keyctl`, "kernel_keyring", "high"},
	{`request_key`, "kernel_keyring", "high"},
	{`bpf`, "ebpf_usage", "medium"},
	{`AF_INET`, "network", "info"},
	{`SOCK_STREAM`, "network", "info"},
	{`SOCK_DGRAM`, "network", "info"},
	{`gethostbyname`, "dns_resolution", "info"},
	{`inet_addr`, "network", "info"},
	{`connect`, "network", "info"},
	{`bind`, "network", "info"},
	{`listen`, "network", "info"},
	{`accept`, "network", "info"},
	{`send`, "network", "info"},
	{`recv`, "network", "info"},
	{`socket`, "network", "info"},
}

// Known suspicious IPs (placeholder - in production, use threat intel feeds)
var knownMaliciousIPs = map[string]string{
	"1.2.3.4":   "known_c2",
	"5.6.7.8":   "known_c2",
	"10.0.0.1":  "internal_network",
	"192.168.1": "internal_network",
}

// NewAnalyzer creates a new binary analyzer
func NewAnalyzer(cfg *config.Config) *Analyzer {
	return &Analyzer{
		cfg: cfg,
		log: logging.WithComponent("analyzer"),
	}
}

// Analyze performs full static analysis on a binary
func (a *Analyzer) Analyze(filePath string) (*AnalysisResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	// Read file contents
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	result := &AnalysisResult{
		ID:        fmt.Sprintf("analysis-%d", time.Now().UnixNano()),
		FilePath:  filePath,
		FileName:  filepath.Base(filePath),
		FileSize:  stat.Size(),
		Timestamp: time.Now(),
	}

	// Calculate hashes
	md5Hash := md5.Sum(data)
	sha256Hash := sha256.Sum256(data)
	result.MD5 = hex.EncodeToString(md5Hash[:])
	result.SHA256 = hex.EncodeToString(sha256Hash[:])

	// Calculate entropy
	result.Entropy = CalculateEntropy(data)
	result.IsPacked = result.Entropy > 7.5
	result.IsEncrypted = result.Entropy > 7.9

	// Detect executable format
	result.ExeInfo = DetectFormat(data)

	// Extract and analyze strings
	suspiciousStrings := ExtractSuspiciousStrings(data)
	result.Strings = suspiciousStrings

	// Extract embedded IPs
	ips := ExtractIPs(data)
	result.IPs = ips

	// Extract embedded ports
	ports := ExtractPorts(data)
	result.Ports = ports

	// Perform heuristic analysis
	findings := a.performHeuristics(result, data)
	result.Findings = findings

	// Calculate risk score
	result.RiskScore = a.calculateRiskScore(result)
	result.Confidence = a.calculateConfidence(result)

	// Determine verdict
	switch {
	case result.RiskScore > 0.7:
		result.Verdict = "malicious"
	case result.RiskScore > 0.4:
		result.Verdict = "suspicious"
	default:
		result.Verdict = "clean"
	}

	a.log.Info("analysis complete",
		"file", result.FileName,
		"verdict", result.Verdict,
		"risk_score", result.RiskScore,
		"findings", len(findings),
	)

	return result, nil
}

// CalculateEntropy calculates Shannon entropy of data
func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make([]float64, 256)
	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	size := float64(len(data))
	for _, f := range freq {
		if f > 0 {
			p := f / size
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// ExtractSuspiciousStrings extracts suspicious strings from binary
func ExtractSuspiciousStrings(data []byte) []string {
	var result []string
	seen := make(map[string]bool)

	// Extract ASCII strings (minimum 4 chars)
	for i := 0; i < len(data)-4; i++ {
		start := i
		for i < len(data) && data[i] >= 32 && data[i] <= 126 {
			i++
		}
		if i-start >= 4 {
			str := string(data[start:i])
			if !seen[str] {
				seen[str] = true
				// Check if string matches any suspicious pattern
				for _, ms := range maliciousStrings {
					if matched, _ := regexp.MatchString(ms.Pattern, str); matched {
						result = append(result, str)
						break
					}
				}
			}
		}
	}

	return result
}

// ExtractIPs extracts embedded IP addresses
func ExtractIPs(data []byte) []string {
	var ips []string
	seen := make(map[string]bool)

	// Regex for IPv4
	ipv4Regex := regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	matches := ipv4Regex.FindAll(data, -1)

	for _, match := range matches {
		ip := string(match)
		if !seen[ip] {
			seen[ip] = true
			// Validate IP
			if parsed := net.ParseIP(ip); parsed != nil {
				// Skip localhost and broadcast
				if !parsed.IsLoopback() && !parsed.IsUnspecified() {
					ips = append(ips, ip)
				}
			}
		}
	}

	return ips
}

// ExtractPorts extracts embedded port numbers
func ExtractPorts(data []byte) []uint16 {
	var ports []uint16
	seen := make(map[uint16]bool)

	// Look for common port patterns
	portPatterns := []struct {
		pattern *regexp.Regexp
		port    uint16
	}{
		{regexp.MustCompile(`:22\b`), 22},
		{regexp.MustCompile(`:80\b`), 80},
		{regexp.MustCompile(`:443\b`), 443},
		{regexp.MustCompile(`:4444\b`), 4444},
		{regexp.MustCompile(`:5555\b`), 5555},
		{regexp.MustCompile(`:6666\b`), 6666},
		{regexp.MustCompile(`:8888\b`), 8888},
		{regexp.MustCompile(`:31337\b`), 31337},
		{regexp.MustCompile(`:1234\b`), 1234},
		{regexp.MustCompile(`:12345\b`), 12345},
		{regexp.MustCompile(`:54321\b`), 54321},
	}

	for _, pp := range portPatterns {
		if pp.pattern.Match(data) && !seen[pp.port] {
			seen[pp.port] = true
			ports = append(ports, pp.port)
		}
	}

	return ports
}

// DetectFormat detects the executable format
func DetectFormat(data []byte) *ExeInfo {
	if len(data) < 4 {
		return &ExeInfo{Format: "unknown"}
	}

	// ELF magic: 0x7f 'E' 'L' 'F'
	if data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		return detectELF(data)
	}

	// PE magic: 'M' 'Z'
	if data[0] == 'M' && data[1] == 'Z' {
		return &ExeInfo{Format: "pe", Arch: "x86/x64"}
	}

	// Mach-O magic
	if (data[0] == 0xfe && data[1] == 0xed && data[2] == 0xfa) ||
		(data[0] == 0xfe && data[1] == 0xed && data[2] == 0xce) ||
		(data[0] == 0xcf && data[1] == 0xfa && data[2] == 0xed) {
		return &ExeInfo{Format: "macho", Arch: "arm64/x86_64"}
	}

	// Shell script
	if data[0] == '#' && data[1] == '!' {
		return &ExeInfo{Format: "script", Arch: "interpreted"}
	}

	// Python
	if data[0] == 'P' && data[1] == 'Y' {
		return &ExeInfo{Format: "python", Arch: "interpreted"}
	}

	return &ExeInfo{Format: "unknown"}
}

func detectELF(data []byte) *ExeInfo {
	info := &ExeInfo{Format: "elf"}

	if len(data) < 20 {
		return info
	}

	// ELF class (32/64 bit)
	if data[4] == 1 {
		info.Arch = "x86"
	} else if data[4] == 2 {
		info.Arch = "x86_64"
	}

	// Extract interpreter
	for i := 0; i < len(data)-4; i++ {
		if string(data[i:i+4]) == "/lib" {
			end := i
			for end < len(data) && data[end] != 0 {
				end++
			}
			if end > i {
				info.Interpreter = string(data[i:end])
			}
			break
		}
	}

	// Extract shared libraries
	libRegex := regexp.MustCompile(`lib[\w\-]+\.so[\.\d]*`)
	libs := libRegex.FindAll(data, -1)
	seen := make(map[string]bool)
	for _, lib := range libs {
		s := string(lib)
		if !seen[s] {
			seen[s] = true
			info.Libraries = append(info.Libraries, s)
		}
	}

	return info
}

func (a *Analyzer) performHeuristics(result *AnalysisResult, data []byte) []Finding {
	var findings []Finding

	// High entropy detection
	if result.Entropy > 7.5 {
		findings = append(findings, Finding{
			Category:    "obfuscation",
			Description: "High entropy detected - possible packed/encrypted binary",
			Severity:    "high",
			Confidence:  0.8,
			Evidence:    fmt.Sprintf("Entropy: %.2f/8.0", result.Entropy),
		})
	}

	// Suspicious strings
	for _, str := range result.Strings {
		for _, ms := range maliciousStrings {
			if matched, _ := regexp.MatchString(ms.Pattern, str); matched {
				findings = append(findings, Finding{
					Category:    ms.Category,
					Description: fmt.Sprintf("Suspicious string found: %s", str),
					Severity:    ms.Severity,
					Confidence:  0.9,
					Evidence:    str,
				})
				break
			}
		}
	}

	// Embedded IPs
	for _, ip := range result.IPs {
		if reason, ok := knownMaliciousIPs[ip]; ok {
			findings = append(findings, Finding{
				Category:    "c2_communication",
				Description: fmt.Sprintf("Known malicious IP embedded: %s", ip),
				Severity:    "critical",
				Confidence:  0.95,
				Evidence:    fmt.Sprintf("IP: %s (%s)", ip, reason),
			})
		}
	}

	// Suspicious ports
	suspiciousPorts := map[uint16]string{
		4444:  "metasploit_default",
		5555:  "adb_debug",
		6666:  "irc_backdoor",
		31337: "elite_backdoor",
		1234:  "trojan_common",
		12345: "netbus",
		54321: "back_orifice",
	}
	for _, port := range result.Ports {
		if reason, ok := suspiciousPorts[port]; ok {
			findings = append(findings, Finding{
				Category:    "suspicious_port",
				Description: fmt.Sprintf("Suspicious port found: %d", port),
				Severity:    "high",
				Confidence:  0.85,
				Evidence:    fmt.Sprintf("Port: %d (%s)", port, reason),
			})
		}
	}

	// ELF specific checks
	if result.ExeInfo != nil && result.ExeInfo.Format == "elf" {
		// Check for lack of sections (packed)
		if len(result.ExeInfo.Sections) == 0 && result.Entropy > 7.0 {
			findings = append(findings, Finding{
				Category:    "obfuscation",
				Description: "ELF binary has no readable sections - possible packing",
				Severity:    "high",
				Confidence:  0.7,
				Evidence:    "No ELF sections detected",
			})
		}

		// Check for LD_PRELOAD
		for _, lib := range result.ExeInfo.Libraries {
			if strings.Contains(lib, "preload") {
				findings = append(findings, Finding{
					Category:    "hooking",
					Description: "Binary uses LD_PRELOAD hooking",
					Severity:    "high",
					Confidence:  0.9,
					Evidence:    fmt.Sprintf("Library: %s", lib),
				})
			}
		}
	}

	// File size anomalies
	if result.FileSize < 100 && result.Entropy > 7.0 {
		findings = append(findings, Finding{
			Category:    "shellcode",
			Description: "Very small high-entropy file - possible shellcode",
			Severity:    "critical",
			Confidence:  0.85,
			Evidence:    fmt.Sprintf("Size: %d bytes, Entropy: %.2f", result.FileSize, result.Entropy),
		})
	}

	// Check for crypto mining patterns
	miningStrings := []string{"stratum+tcp", "stratum+ssl", "xmr", "monero", "coinhive", "cryptonight"}
	for _, str := range miningStrings {
		for _, dataStr := range result.Strings {
			if strings.Contains(strings.ToLower(dataStr), str) {
				findings = append(findings, Finding{
					Category:    "cryptominer",
					Description: "Cryptocurrency mining indicators detected",
					Severity:    "high",
					Confidence:  0.9,
					Evidence:    fmt.Sprintf("Pattern: %s", str),
				})
				break
			}
		}
	}

	return findings
}

func (a *Analyzer) calculateRiskScore(result *AnalysisResult) float64 {
	score := 0.0

	// Entropy contribution
	if result.Entropy > 7.5 {
		score += 0.2
	}
	if result.Entropy > 7.9 {
		score += 0.1
	}

	// Findings contribution
	for _, f := range result.Findings {
		switch f.Severity {
		case "critical":
			score += 0.3
		case "high":
			score += 0.2
		case "medium":
			score += 0.1
		case "low":
			score += 0.05
		}
	}

	// IP contribution
	score += float64(len(result.IPs)) * 0.05

	// Port contribution
	score += float64(len(result.Ports)) * 0.03

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (a *Analyzer) calculateConfidence(result *AnalysisResult) float64 {
	if len(result.Findings) == 0 {
		return 0.5
	}

	totalConfidence := 0.0
	for _, f := range result.Findings {
		totalConfidence += f.Confidence
	}

	return totalConfidence / float64(len(result.Findings))
}

// SaveResult saves analysis result to disk
func (a *Analyzer) SaveResult(result *AnalysisResult, dir string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}

	path := filepath.Join(dir, result.ID+".json")
	return os.WriteFile(path, data, 0o644)
}

// AnalyzeDirectory analyzes all files in a directory
func (a *Analyzer) AnalyzeDirectory(dir string) ([]*AnalysisResult, error) {
	var results []*AnalysisResult

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		// Skip very large files
		if info.Size() > 100*1024*1024 {
			return nil
		}

		result, err := a.Analyze(path)
		if err != nil {
			a.log.Warn("failed to analyze", "path", path, "error", err)
			return nil
		}

		if result.Verdict != "clean" {
			results = append(results, result)
		}

		return nil
	})

	return results, err
}
