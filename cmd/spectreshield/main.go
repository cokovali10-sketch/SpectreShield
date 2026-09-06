//go:build linux

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cokovali10-sketch/SpectreShield/cli"
	"github.com/cokovali10-sketch/SpectreShield/engine"
	"github.com/cokovali10-sketch/SpectreShield/forensics"
	hermesbridge "github.com/cokovali10-sketch/SpectreShield/hermes-bridge"
	"github.com/cokovali10-sketch/SpectreShield/internal/api"
	"github.com/cokovali10-sketch/SpectreShield/internal/config"
	"github.com/cokovali10-sketch/SpectreShield/internal/logging"
	"github.com/cokovali10-sketch/SpectreShield/internal/types"
	"github.com/cokovali10-sketch/SpectreShield/sandbox"
)

var (
	version   = "1.0.0"
	buildTime = "unknown"
	gitCommit = "unknown"
)

type Daemon struct {
	cfg       *config.Config
	log       *logging.Logger
	engine    *engine.Engine
	forensics *forensics.ForensicsEngine
	sandbox   *sandbox.Sandbox
	hermes    *hermesbridge.Bridge
	api       *api.Server
	stats     *types.DaemonStats
	startTime time.Time
	running   bool
	mu        sync.RWMutex
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	os.Args = append(os.Args[:1], os.Args[2:]...)

	switch cmd {
	case "start":
		cmdStart()
	case "stop":
		cmdStop()
	case "status":
		cmdStatus()
	case "audit":
		cmdAudit()
	case "logs":
		cmdLogs()
	case "baseline":
		cmdBaseline()
	case "config":
		cmdConfig()
	case "version":
		fmt.Printf("SpectreShield v%s (commit: %s, built: %s, go: %s)\n", version, gitCommit, buildTime, runtime.Version())
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func cmdStart() {
	cfgPath := flag.String("config", "", "Path to config file")
	foreground := flag.Bool("foreground", false, "Run in foreground (no daemonize)")
	logLevel := flag.String("log-level", "", "Log level (debug, info, warn, error)")
	flag.Parse()

	var cfg *config.Config
	if *cfgPath != "" {
		var err error
		cfg, err = config.Load(*cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
			os.Exit(1)
		}
	} else {
		cfg = config.Get()
	}
	if *logLevel != "" {
		cfg.Daemon.LogLevel = *logLevel
	}

	logFile := cfg.Daemon.LogDir + "/spectreshield.log"
	logging.Init(cfg.Daemon.LogLevel, logFile)
	log := logging.WithComponent("daemon")

	cli.PrintBanner()
	log.Info("starting SpectreShield", "version", version, "pid", os.Getpid(), "foreground", *foreground)

	if os.Getuid() != 0 {
		log.Error("SpectreShield requires root privileges for eBPF")
		fmt.Fprintf(os.Stderr, "Error: SpectreShield must run as root\n")
		os.Exit(1)
	}

	d := &Daemon{
		cfg:       cfg,
		log:       log,
		startTime: time.Now(),
		stats:     &types.DaemonStats{},
	}

	d.engine = engine.NewEngine(cfg)
	if err := d.engine.LoadBaseline(); err != nil {
		log.Warn("no baseline loaded, building fresh", "error", err)
	}

	d.forensics = forensics.NewForensicsEngine(cfg)
	d.sandbox = sandbox.NewSandbox(cfg)
	d.hermes = hermesbridge.NewBridge(cfg)

	if cfg.Hermes.Enabled {
		if d.hermes.IsAvailable() {
			log.Info("Hermes bridge connected", "endpoint", cfg.Hermes.Endpoint)
		} else {
			log.Warn("Hermes not reachable, running without AI analysis", "endpoint", cfg.Hermes.Endpoint)
		}
	}

	if cfg.API.Enabled {
		d.api = api.NewServer(cfg, d.engine, d.forensics, d.sandbox, d.hermes)
		go func() {
			if err := d.api.Start(); err != nil {
				log.Error("API server failed", "error", err)
			}
		}()
	}

	os.MkdirAll(cfg.Daemon.DataDir, 0o755)
	os.WriteFile(cfg.Daemon.PIDFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0o644)

	go d.collectStats()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	d.running = true
	log.Info("SpectreShield daemon started", "api", cfg.API.Addr, "hermes", cfg.Hermes.Enabled)

	for d.running {
		select {
		case sig := <-sigChan:
			switch sig {
			case syscall.SIGTERM, syscall.SIGINT:
				log.Info("shutting down", "signal", sig)
				d.shutdown()
				return
			case syscall.SIGHUP:
				log.Info("reloading config")
			}
		case <-time.After(cfg.Daemon.StatsInterval):
			d.collectStats()
		}
	}
}

func cmdStop() {
	cfg := config.Get()
	data, err := os.ReadFile(cfg.Daemon.PIDFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "PID file not found. Is SpectreShield running?\n")
		os.Exit(1)
	}
	var pid int
	fmt.Sscanf(string(data), "%d", &pid)
	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Process %d not found\n", pid)
		os.Exit(1)
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to stop: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("SpectreShield (PID %d) stopped.\n", pid)
	os.Remove(cfg.Daemon.PIDFile)
}

func cmdStatus() {
	cfg := config.Get()
	data, err := os.ReadFile(cfg.Daemon.PIDFile)
	if err != nil {
		fmt.Println("SpectreShield is NOT running.")
		return
	}
	var pid int
	fmt.Sscanf(string(data), "%d", &pid)
	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Println("SpectreShield is NOT running (stale PID file).")
		return
	}
	err = process.Signal(syscall.Signal(0))
	if err != nil {
		fmt.Println("SpectreShield is NOT running (stale PID file).")
		return
	}
	fmt.Printf("SpectreShield is RUNNING (PID %d).\n", pid)
	if cfg.API.Enabled {
		fmt.Printf("API endpoint: http://localhost%s\n", cfg.API.Addr)
	}
}

func cmdAudit() {
	cfg := config.Get()
	logging.Init(cfg.Daemon.LogLevel, "")
	e := engine.NewEngine(cfg)
	if err := e.LoadBaseline(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load baseline: %v\n", err)
	}
	if err := e.BuildBaseline(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build baseline: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Baseline audit complete.")
	tree := e.GetProcessTree()
	cli.PrintProcessTree(tree)
}

func cmdLogs() {
	cfg := config.Get()
	logFile := cfg.Daemon.LogDir + "/spectreshield.log"
	data, err := os.ReadFile(logFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "No log file found at %s\n", logFile)
		return
	}
	fmt.Print(string(data))
}

func cmdBaseline() {
	cfg := config.Get()
	e := engine.NewEngine(cfg)
	if err := e.LoadBaseline(); err != nil {
		fmt.Fprintf(os.Stderr, "No existing baseline, creating new one.\n")
	}
	if err := e.BuildBaseline(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build baseline: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Behavioral baseline built and saved successfully.")
}

func cmdConfig() {
	cfg := config.Get()
	cli.PrintConfig(cfg)
}

func (d *Daemon) collectStats() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stats.Uptime = time.Since(d.startTime)
	d.stats.ActivePIDs = len(d.engine.GetProcessTree())
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "VmRSS:") {
				var rssKB int
				fmt.Sscanf(strings.TrimPrefix(line, "VmRSS:"), "%d kB", &rssKB)
				d.stats.MemoryUsageMB = float64(rssKB) / 1024.0
			}
		}
	}
}

func (d *Daemon) shutdown() {
	d.mu.Lock()
	d.running = false
	d.mu.Unlock()
	d.log.Info("cleaning up")
	os.Remove(d.cfg.Daemon.PIDFile)
	if err := d.engine.SaveBaseline(); err != nil {
		d.log.Error("failed to save baseline", "error", err)
	}
	d.log.Info("SpectreShield stopped")
}

func printUsage() {
	fmt.Println(`SpectreShield — eBPF-powered EDR & Behavioral Threat Intelligence

Usage:
  spectreshield <command> [options]

Commands:
  start       Start the SpectreShield daemon
  stop        Stop the SpectreShield daemon
  status      Check if SpectreShield is running
  audit       Build/update behavioral baseline
  logs        Show daemon logs
  baseline    Build behavioral baseline
  config      Show current configuration
  version     Show version info
  help        Show this help message

Start Options:
  --config <path>     Path to config file
  --foreground        Run in foreground (don't daemonize)
  --log-level <level> Log level (debug, info, warn, error)

Examples:
  spectreshield start --foreground --log-level debug
  spectreshield status
  spectreshield audit
  spectreshield stop`)

	_ = json.Marshal
}
