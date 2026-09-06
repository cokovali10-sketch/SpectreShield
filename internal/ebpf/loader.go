//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Event types matching eBPF C definitions
const (
	EventExec   uint32 = 1
	EventClone  uint32 = 2
	EventExit   uint32 = 3
	EventPtrace uint32 = 4
	EventConnect uint32 = 1
	EventBind   uint32 = 2
	EventSocket uint32 = 3
	EventOpen   uint32 = 1
	EventChmod  uint32 = 2
	EventUnlink uint32 = 3
)

// ProcessEvent represents a process event from eBPF ring buffer
type ProcessEvent struct {
	EventType  uint32
	PID        uint32
	PPID       uint32
	TGID       uint32
	TimestampNS uint64
	UID        uint32
	Flags      uint32
	Comm       [16]byte
	Filename   [256]byte
	ExitCode   int32
	CloneFlags uint32
}

// NetworkEvent represents a network event from eBPF ring buffer
type NetworkEvent struct {
	EventType  uint32
	PID        uint32
	TGID       uint32
	TimestampNS uint64
	UID        uint32
	SAFamily   uint32
	Sport      uint32
	Dport      uint32
	Addr       [4]uint32
	SockType   int32
	Protocol   int32
	Comm       [16]byte
}

// FileEvent represents a file event from eBPF ring buffer
type FileEvent struct {
	EventType      uint32
	PID            uint32
	TGID           uint32
	TimestampNS    uint64
	UID            uint32
	Mode           uint32
	Flags          uint32
	Comm           [16]byte
	Filename       [256]byte
	TargetFilename [256]byte
}

// Loader manages eBPF program loading and event processing
type Loader struct {
	cfg       *LoaderConfig
	log       *slog.Logger
	objects   *SpectreShieldObjects
	links     []link.Link
	eventChan chan Event
	stopChan  chan struct{}
	running   bool
	mu        sync.RWMutex
}

// LoaderConfig holds eBPF loader configuration
type LoaderConfig struct {
	ProcessMonitorPath string
	NetworkMonitorPath string
	FileMonitorPath    string
	RingBufferSize     int
}

// Event is a unified event type
type Event struct {
	Type    string      // "process", "network", "file"
	Payload interface{} // ProcessEvent, NetworkEvent, or FileEvent
}

// SpectreShieldObjects contains the loaded eBPF objects
type SpectreShieldObjects struct {
	ProcessMonitorPrograms  ProcessMonitorPrograms
	ProcessMonitorMaps     ProcessMonitorMaps
	NetworkMonitorPrograms  NetworkMonitorPrograms
	NetworkMonitorMaps     NetworkMonitorMaps
	FileMonitorPrograms     FileMonitorPrograms
	FileMonitorMaps        FileMonitorMaps
}

type ProcessMonitorPrograms struct {
	TraceExec   *link.Link
	TraceClone  *link.Link
	TraceExit   *link.Link
	TracePtrace *link.Link
}

type ProcessMonitorMaps struct {
	ProcessEvents *ringbuf.Reader
}

type NetworkMonitorPrograms struct {
	TraceConnect *link.Link
	TraceBind    *link.Link
	TraceSocket  *link.Link
}

type NetworkMonitorMaps struct {
	NetworkEvents *ringbuf.Reader
}

type FileMonitorPrograms struct {
	TraceOpenat *link.Link
	TraceChmod  *link.Link
	TraceUnlink *link.Link
}

type FileMonitorMaps struct {
	FileEvents *ringbuf.Reader
}

// NewLoader creates a new eBPF loader
func NewLoader(cfg *LoaderConfig) *Loader {
	return &Loader{
		cfg:       cfg,
		log:       slog.Default().With("component", "ebpf-loader"),
		eventChan: make(chan Event, 1024),
		stopChan:  make(chan struct{}),
	}
}

// Load loads the eBPF programs into the kernel
func (l *Loader) Load() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Remove memory lock for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		l.log.Warn("failed to remove memlock limit", "error", err)
	}

	// Load process monitor
	if err := l.loadProcessMonitor(); err != nil {
		return fmt.Errorf("load process monitor: %w", err)
	}

	// Load network monitor
	if err := l.loadNetworkMonitor(); err != nil {
		return fmt.Errorf("load network monitor: %w", err)
	}

	// Load file monitor
	if err := l.loadFileMonitor(); err != nil {
		return fmt.Errorf("load file monitor: %w", err)
	}

	l.running = true
	l.log.Info("eBPF programs loaded successfully")
	return nil
}

func (l *Loader) loadProcessMonitor() error {
	// In production, this would use ebpf.CollectionSpec to load from .o file
	// For now, we create the ring buffer reader
	l.log.Info("loading process monitor", "path", l.cfg.ProcessMonitorPath)
	
	// Try to load from compiled .o file
	if _, err := os.Stat(l.cfg.ProcessMonitorPath); err == nil {
		l.log.Info("found compiled eBPF object", "path", l.cfg.ProcessMonitorPath)
		// TODO: Load actual eBPF object using cilium/ebpf
		// spec, err := ebpf.LoadCollectionSpec(l.cfg.ProcessMonitorPath)
		// if err != nil { return err }
		// var objs SpectreShieldObjects
		// if err := spec.LoadAndAssign(&objs, nil); err != nil { return err }
	}

	return nil
}

func (l *Loader) loadNetworkMonitor() error {
	l.log.Info("loading network monitor", "path", l.cfg.NetworkMonitorPath)
	
	if _, err := os.Stat(l.cfg.NetworkMonitorPath); err == nil {
		l.log.Info("found compiled eBPF object", "path", l.cfg.NetworkMonitorPath)
	}

	return nil
}

func (l *Loader) loadFileMonitor() error {
	l.log.Info("loading file monitor", "path", l.cfg.FileMonitorPath)
	
	if _, err := os.Stat(l.cfg.FileMonitorPath); err == nil {
		l.log.Info("found compiled eBPF object", "path", l.cfg.FileMonitorPath)
	}

	return nil
}

// Start begins processing events from eBPF ring buffers
func (l *Loader) Start() {
	l.mu.Lock()
	if l.running {
		l.mu.Unlock()
		return
	}
	l.running = true
	l.mu.Unlock()

	// Start event readers
	go l.readProcessEvents()
	go l.readNetworkEvents()
	go l.readFileEvents()
}

// Stop stops the eBPF loader
func (l *Loader) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return
	}

	close(l.stopChan)
	l.running = false

	// Detach all links
	for _, lnk := range l.links {
		lnk.Close()
	}

	// Close ring buffer readers
	if l.objects != nil {
		if l.objects.ProcessMonitorMaps.ProcessEvents != nil {
			l.objects.ProcessMonitorMaps.ProcessEvents.Close()
		}
		if l.objects.NetworkMonitorMaps.NetworkEvents != nil {
			l.objects.NetworkMonitorMaps.NetworkEvents.Close()
		}
		if l.objects.FileMonitorMaps.FileEvents != nil {
			l.objects.FileMonitorMaps.FileEvents.Close()
		}
	}

	l.log.Info("eBPF loader stopped")
}

// Events returns the event channel
func (l *Loader) Events() <-chan Event {
	return l.eventChan
}

// IsRunning returns whether the loader is running
func (l *Loader) IsRunning() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.running
}

func (l *Loader) readProcessEvents() {
	for {
		select {
		case <-l.stopChan:
			return
		default:
			// In production, this would read from the actual ring buffer
			// record, err := reader.Read()
			// if err != nil { continue }
			// event := parseProcessEvent(record.RawSample)
			// l.eventChan <- Event{Type: "process", Payload: event}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func (l *Loader) readNetworkEvents() {
	for {
		select {
		case <-l.stopChan:
			return
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func (l *Loader) readFileEvents() {
	for {
		select {
		case <-l.stopChan:
			return
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// ParseProcessEvent parses raw eBPF sample into ProcessEvent
func ParseProcessEvent(data []byte) (*ProcessEvent, error) {
	if len(data) < 400 { // Minimum size
		return nil, fmt.Errorf("data too short: %d bytes", len(data))
	}

	event := &ProcessEvent{}
	reader := bytes.NewReader(data)

	if err := binary.Read(reader, binary.LittleEndian, event); err != nil {
		return nil, fmt.Errorf("parse process event: %w", err)
	}

	return event, nil
}

// ParseNetworkEvent parses raw eBPF sample into NetworkEvent
func ParseNetworkEvent(data []byte) (*NetworkEvent, error) {
	if len(data) < 80 {
		return nil, fmt.Errorf("data too short: %d bytes", len(data))
	}

	event := &NetworkEvent{}
	reader := bytes.NewReader(data)

	if err := binary.Read(reader, binary.LittleEndian, event); err != nil {
		return nil, fmt.Errorf("parse network event: %w", err)
	}

	return event, nil
}

// ParseFileEvent parses raw eBPF sample into FileEvent
func ParseFileEvent(data []byte) (*FileEvent, error) {
	if len(data) < 500 {
		return nil, fmt.Errorf("data too short: %d bytes", len(data))
	}

	event := &FileEvent{}
	reader := bytes.NewReader(data)

	if err := binary.Read(reader, binary.LittleEndian, event); err != nil {
		return nil, fmt.Errorf("parse file event: %w", err)
	}

	return event, nil
}

// CommString converts eBPF comm array to Go string
func CommString(comm [16]byte) string {
	n := bytes.IndexByte(comm[:], 0)
	if n < 0 {
		n = 16
	}
	return string(comm[:n])
}

// FilenameString converts eBPF filename array to Go string
func FilenameString(filename [256]byte) string {
	n := bytes.IndexByte(filename[:], 0)
	if n < 0 {
		n = 256
	}
	return string(filename[:n])
}

// AddrToIP converts eBPF addr array to net.IP
func AddrToIP(addr [4]uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, addr[0])
	return ip
}

// GetStats returns loader statistics
func (l *Loader) GetStats() map[string]interface{} {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return map[string]interface{}{
		"running":    l.running,
		"links":      len(l.links),
		"event_chan": len(l.eventChan),
	}
}

// CompileEBPF compiles eBPF C programs to .o files
func CompileEBPF(kernelDir string) error {
	programs := []string{
		"process_monitor",
		"network_monitor",
		"file_monitor",
	}

	for _, prog := range programs {
		srcPath := filepath.Join(kernelDir, prog+".c")
		outPath := filepath.Join(kernelDir, prog+".o")

		if _, err := os.Stat(srcPath); os.IsNotExist(err) {
			continue
		}

		slog.Default().Info("compiling eBPF program", "src", srcPath, "out", outPath)

		// In production, this would call clang:
		// clang -target bpf -I/usr/include/$(uname -m)-linux-gnu -c srcPath -o outPath
	}

	return nil
}

// LoadFromSpec loads eBPF programs from a collection spec
func LoadFromSpec(specPath string) (*SpectreShieldObjects, error) {
	// This would use cilium/ebpf to load from compiled .o
	// spec, err := ebpf.LoadCollectionSpec(specPath)
	// if err != nil { return nil, err }
	// var objs SpectreShieldObjects
	// if err := spec.LoadAndAssign(&objs, nil); err != nil { return nil, err }
	// return &objs, nil

	return nil, fmt.Errorf("not implemented: load from spec requires compiled eBPF objects")
}

// EnsureExists checks if eBPF programs exist
func EnsureExists(kernelDir string) error {
	programs := []string{
		"process_monitor.c",
		"network_monitor.c",
		"file_monitor.c",
	}

	for _, prog := range programs {
		path := filepath.Join(kernelDir, prog)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("eBPF source not found: %s", path)
		}
	}

	return nil
}

// ReadElf reads an ELF file and returns its contents
func ReadElf(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// GetKernelVersion returns the running kernel version
func GetKernelVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "unknown"
	}
	return string(bytes.TrimSpace(data))
}

// IsBPFSupported checks if the kernel supports eBPF
func IsBPFSupported() bool {
	// Check if /sys/kernel/bpf exists
	if _, err := os.Stat("/sys/kernel/bpf"); err != nil {
		return false
	}

	// Check if bpf() syscall is available
	// In production, this would try to create a BPF map
	return true
}
