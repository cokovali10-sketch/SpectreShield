//go:build linux

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/cokovali10-sketch/SpectreShield/analyzer"
	"github.com/cokovali10-sketch/SpectreShield/internal/config"
	"github.com/cokovali10-sketch/SpectreShield/internal/types"
)

// PrintThreat formats and prints a threat
func PrintThreat(t *types.Threat) {
	severityColors := map[types.Severity]string{
		0: "\033[37m", // white - info
		1: "\033[36m", // cyan - low
		2: "\033[33m", // yellow - medium
		3: "\033[91m", // bright red - high
		4: "\033[31m", // red - critical
	}
	reset := "\033[0m"
	color := severityColors[t.Severity]

	fmt.Printf("%s[THREAT]%s %s (Severity: %d)\n", color, reset, t.Category, t.Severity)
	fmt.Printf("  ID:          %s\n", t.ID)
	fmt.Printf("  Time:        %s\n", t.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("  PID:         %d (PPID: %d, UID: %d)\n", t.PID, t.PPID, t.UID)
	fmt.Printf("  Process:     %s\n", t.Comm)
	fmt.Printf("  Description: %s\n", t.Description)
	fmt.Printf("  Evidence:    %s\n", t.Evidence)
	if t.Contained {
		fmt.Printf("  Status:      \033[32mCONTAINED\033[0m\n")
	}
	fmt.Println()
}

// PrintIncidentReport formats and prints an incident report
func PrintIncidentReport(report *types.IncidentReport) {
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("  INCIDENT REPORT: %s\n", report.ID)
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("  Host:      %s\n", report.Hostname)
	fmt.Printf("  Time:      %s\n", report.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Threats:   %d\n", len(report.Threats))
	fmt.Printf("  Contain:   %s\n", report.ContainmentAction)
	fmt.Printf("  Status:    %s\n", report.Status)
	fmt.Println("───────────────────────────────────────────────────────────")

	for _, t := range report.Threats {
		PrintThreat(&t)
	}

	if report.Analysis != "" {
		fmt.Println("ANALYSIS:")
		fmt.Println(report.Analysis)
	}
	fmt.Println("═══════════════════════════════════════════════════════════")
}

// PrintStats formats and prints daemon statistics
func PrintStats(stats *types.DaemonStats) {
	fmt.Println("───────────────────────────────────────────────────────────")
	fmt.Println("  SPECTRESHIELD STATUS")
	fmt.Println("───────────────────────────────────────────────────────────")
	fmt.Printf("  Uptime:              %s\n", stats.Uptime.Truncate(time.Second))
	fmt.Printf("  Events Processed:    %d\n", stats.EventsProcessed)
	fmt.Printf("  Threats Detected:    %d\n", stats.ThreatsDetected)
	fmt.Printf("  Processes Contained: %d\n", stats.ProcessesContained)
	fmt.Printf("  Hermes Queries:      %d\n", stats.HermesQueries)
	fmt.Printf("  Active PIDs:         %d\n", stats.ActivePIDs)
	fmt.Printf("  Ring Buffer Usage:   %.1f%%\n", stats.RingBufferUsage)
	fmt.Printf("  Memory Usage:        %.1f MB\n", stats.MemoryUsageMB)
	fmt.Printf("  CPU Usage:           %.1f%%\n", stats.CPUUsagePercent)
	fmt.Println("───────────────────────────────────────────────────────────")
}

// PrintProcessTree formats and prints a process tree
func PrintProcessTree(tree map[uint32]*types.ProcessInfo) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PID\tCOMM\tPPID\tUID\tEXEC PATH")
	fmt.Fprintln(w, "---\t----\t----\t---\t---------")
	for _, info := range tree {
		fmt.Fprintf(w, "%d\t%s\t%d\t%d\t%s\n",
			info.PID, info.Comm, info.PPID, info.UID, info.ExecPath)
	}
	w.Flush()
}

// PrintJSON prints any value as formatted JSON
func PrintJSON(v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "JSON error: %v\n", err)
		return
	}
	fmt.Println(string(data))
}

// PrintBanner prints the SpectreShield banner
func PrintBanner() {
	fmt.Print(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ███╗   ██╗███████╗████████╗███████╗ █████╗ ██╗         ║
║   ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██║         ║
║   ██╔██╗ ██║█████╗     ██║   █████╗  ███████║██║         ║
║   ██║╚██╗██║██╔══╝     ██║   ██╔══╝  ██╔══██║██║         ║
║   ██║ ╚████║███████╗   ██║   ███████╗██║  ██║███████╗    ║
║   ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝  ║
║                                                           ║
║   eBPF-powered EDR & Behavioral Threat Intelligence       ║
║   v1.0.0                                                  ║
╚═══════════════════════════════════════════════════════════╝
`)
}

// PrintConfig prints the current configuration
func PrintConfig(cfg *config.Config) {
	fmt.Println("───────────────────────────────────────────────────────────")
	fmt.Println("  SPECTRESHIELD CONFIGURATION")
	fmt.Println("───────────────────────────────────────────────────────────")
	fmt.Printf("  Data Dir:    %s\n", cfg.Daemon.DataDir)
	fmt.Printf("  Log Dir:     %s\n", cfg.Daemon.LogDir)
	fmt.Printf("  Log Level:   %s\n", cfg.Daemon.LogLevel)
	fmt.Printf("  Hermes:      %s (enabled: %v)\n", cfg.Hermes.Endpoint, cfg.Hermes.Enabled)
	fmt.Printf("  API:         %s (enabled: %v)\n", cfg.API.Addr, cfg.API.Enabled)
	fmt.Printf("  Sandbox:     (enabled: %v, timeout: %s)\n", cfg.Sandbox.Enabled, cfg.Sandbox.Timeout)
	fmt.Printf("  Forensics:   dump_dir=%s, freeze=%v\n", cfg.Forensics.DumpDir, cfg.Forensics.FreezeOnDetect)
	fmt.Printf("  Suspicious Ports: %v\n", cfg.Engine.SuspiciousPorts)
	fmt.Printf("  Watched Paths:    %v\n", cfg.Engine.WatchedPaths)
	fmt.Println("───────────────────────────────────────────────────────────")
}

// PrintAnalysisResult prints binary analysis results
func PrintAnalysisResult(result *analyzer.AnalysisResult) {
	severityColors := map[string]string{
		"critical": "\033[31m",
		"high":     "\033[91m",
		"medium":   "\033[33m",
		"low":      "\033[36m",
		"info":     "\033[37m",
	}
	reset := "\033[0m"

	verdictColors := map[string]string{
		"malicious":  "\033[31m",
		"suspicious": "\033[33m",
		"clean":      "\033[32m",
	}

	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("  BINARY ANALYSIS: %s\n", result.FileName)
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("  File:      %s\n", result.FilePath)
	fmt.Printf("  Size:      %d bytes\n", result.FileSize)
	fmt.Printf("  MD5:       %s\n", result.MD5)
	fmt.Printf("  SHA256:    %s\n", result.SHA256)
	fmt.Printf("  Entropy:   %.2f/8.0\n", result.Entropy)
	fmt.Printf("  Packed:    %v\n", result.IsPacked)
	fmt.Printf("  Encrypted: %v\n", result.IsEncrypted)

	if result.ExeInfo != nil {
		fmt.Printf("  Format:    %s (%s)\n", result.ExeInfo.Format, result.ExeInfo.Arch)
		if result.ExeInfo.Interpreter != "" {
			fmt.Printf("  Interpreter: %s\n", result.ExeInfo.Interpreter)
		}
	}

	fmt.Println("───────────────────────────────────────────────────────────")

	// Verdict
	vColor := verdictColors[result.Verdict]
	fmt.Printf("  VERDICT:   %s%s%s\n", vColor, result.Verdict, reset)
	fmt.Printf("  Risk Score: %.2f/1.00\n", result.RiskScore)
	fmt.Printf("  Confidence: %.0f%%\n", result.Confidence*100)
	fmt.Println("───────────────────────────────────────────────────────────")

	// Findings
	if len(result.Findings) > 0 {
		fmt.Printf("  FINDINGS (%d):\n", len(result.Findings))
		for _, f := range result.Findings {
			color := severityColors[f.Severity]
			fmt.Printf("    %s[%s]%s %s: %s\n", color, f.Severity, reset, f.Category, f.Description)
			fmt.Printf("      Evidence: %s\n", f.Evidence)
		}
		fmt.Println("───────────────────────────────────────────────────────────")
	}

	// Embedded IPs
	if len(result.IPs) > 0 {
		fmt.Printf("  EMBEDDED IPs: %v\n", result.IPs)
	}

	// Embedded Ports
	if len(result.Ports) > 0 {
		fmt.Printf("  EMBEDDED PORTS: %v\n", result.Ports)
	}

	// Suspicious strings (first 10)
	if len(result.Strings) > 0 {
		fmt.Printf("  SUSPICIOUS STRINGS (%d total):\n", len(result.Strings))
		limit := 10
		if len(result.Strings) < limit {
			limit = len(result.Strings)
		}
		for i := 0; i < limit; i++ {
			fmt.Printf("    - %s\n", result.Strings[i])
		}
		if len(result.Strings) > 10 {
			fmt.Printf("    ... and %d more\n", len(result.Strings)-10)
		}
	}

	fmt.Println("═══════════════════════════════════════════════════════════")
}
