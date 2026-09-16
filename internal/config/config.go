//go:build linux

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Config struct {
	Daemon    DaemonConfig    `json:"daemon"`
	EBPF      EBPFConfig      `json:"ebpf"`
	Engine    EngineConfig    `json:"engine"`
	Forensics ForensicsConfig `json:"forensics"`
	Sandbox   SandboxConfig   `json:"sandbox"`
	Hermes    HermesConfig    `json:"hermes"`
	API       APIConfig       `json:"api"`
}

type DaemonConfig struct {
	DataDir       string        `json:"data_dir"`
	LogDir        string        `json:"log_dir"`
	LogLevel      string        `json:"log_level"`
	PIDFile       string        `json:"pid_file"`
	StatsInterval time.Duration `json:"stats_interval"`
}

type EBPFConfig struct {
	ProcessMonitorPath string `json:"process_monitor_path"`
	NetworkMonitorPath string `json:"network_monitor_path"`
	FileMonitorPath    string `json:"file_monitor_path"`
	RingBufferSize     int    `json:"ring_buffer_size"`
}

type EngineConfig struct {
	BaselinePath        string        `json:"baseline_path"`
	AnomalyThreshold    float64       `json:"anomaly_threshold"`
	MaxProcessTreeDepth int           `json:"max_process_tree_depth"`
	SuspiciousPorts     []uint32      `json:"suspicious_ports"`
	WatchedPaths        []string      `json:"watched_paths"`
	AnalysisWindow      time.Duration `json:"analysis_window"`
}

type ForensicsConfig struct {
	DumpDir           string `json:"dump_dir"`
	MaxDumpSizeMB     int    `json:"max_dump_size_mb"`
	AutoExtractBinary bool   `json:"auto_extract_binary"`
	FreezeOnDetect    bool   `json:"freeze_on_detect"`
}

type SandboxConfig struct {
	Enabled       bool          `json:"enabled"`
	SandboxDir    string        `json:"sandbox_dir"`
	Timeout       time.Duration `json:"timeout"`
	MaxMemory     int64         `json:"max_memory"`
	NetworkPolicy string        `json:"network_policy"`
}

type HermesConfig struct {
	Enabled       bool          `json:"enabled"`
	Endpoint      string        `json:"endpoint"`
	APIKey        string        `json:"api_key"`
	Timeout       time.Duration `json:"timeout"`
	AutoRemediate bool          `json:"auto_remediate"`
	MaxRetries    int           `json:"max_retries"`
}

type APIConfig struct {
	Enabled   bool   `json:"enabled"`
	Addr      string `json:"addr"`
	AuthKey   string `json:"auth_key"`
	JWTSecret string `json:"jwt_secret"`
}

var (
	globalConfig *Config
	configOnce   sync.Once
)

func DefaultConfig() *Config {
	return &Config{
		Daemon: DaemonConfig{
			DataDir:       "/var/lib/spectreshield",
			LogDir:        "/var/log/spectreshield",
			LogLevel:      "info",
			PIDFile:       "/var/run/spectreshield.pid",
			StatsInterval: 10 * time.Second,
		},
		EBPF: EBPFConfig{
			ProcessMonitorPath: "/usr/lib/spectreshield/bpf/process_monitor.o",
			NetworkMonitorPath: "/usr/lib/spectreshield/bpf/network_monitor.o",
			FileMonitorPath:    "/usr/lib/spectreshield/bpf/file_monitor.o",
			RingBufferSize:     16 * 1024 * 1024,
		},
		Engine: EngineConfig{
			BaselinePath:        "/var/lib/spectreshield/baseline.json",
			AnomalyThreshold:    0.7,
			MaxProcessTreeDepth: 8,
			SuspiciousPorts:     []uint32{4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337, 12345, 54321},
			WatchedPaths: []string{
				"/etc/passwd", "/etc/shadow", "/etc/sudoers",
				"/root/.ssh", "/etc/ssh/sshd_config",
				"/proc/sys", "/sys/kernel", "/dev/mem",
			},
			AnalysisWindow: 5 * time.Minute,
		},
		Forensics: ForensicsConfig{
			DumpDir:           "/var/lib/spectreshield/dumps",
			MaxDumpSizeMB:     256,
			AutoExtractBinary: true,
			FreezeOnDetect:    true,
		},
		Sandbox: SandboxConfig{
			Enabled:       true,
			SandboxDir:    "/var/lib/spectreshield/sandbox",
			Timeout:       30 * time.Second,
			MaxMemory:     256 * 1024 * 1024,
			NetworkPolicy: "none",
		},
		Hermes: HermesConfig{
			Enabled:       true,
			Endpoint:      "http://127.0.0.1:8765",
			Timeout:       60 * time.Second,
			AutoRemediate: false,
			MaxRetries:    3,
		},
		API: APIConfig{
			Enabled: true,
			Addr:    ":9090",
		},
	}
}

func Get() *Config {
	configOnce.Do(func() {
		globalConfig = DefaultConfig()
		if cfgPath := os.Getenv("SPECTRESHIELD_CONFIG"); cfgPath != "" {
			if data, err := os.ReadFile(cfgPath); err == nil {
				json.Unmarshal(data, globalConfig)
			}
		}
		globalConfig.ensureDirs()
	})
	return globalConfig
}

func (c *Config) ensureDirs() {
	dirs := []string{
		c.Daemon.DataDir, c.Daemon.LogDir,
		c.Forensics.DumpDir, c.Sandbox.SandboxDir,
		filepath.Dir(c.Engine.BaselinePath),
	}
	for _, d := range dirs {
		os.MkdirAll(d, 0o755)
	}
}

func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
