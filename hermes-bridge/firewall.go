//go:build linux

package hermesbridge

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/cokovali10-sketch/SpectreShield/internal/config"
	"github.com/cokovali10-sketch/SpectreShield/internal/logging"
)

type FirewallGenerator struct {
	cfg       *config.Config
	log       *logging.Logger
	mu        sync.Mutex
	ruleChain string
}

type FirewallRule struct {
	Chain     string `json:"chain"`
	Table     string `json:"table"`
	Protocol  string `json:"protocol"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   string `json:"src_port"`
	DstPort   string `json:"dst_port"`
	Interface string `json:"interface"`
	Action    string `json:"action"`
	Comment   string `json:"comment"`
	State     string `json:"state"`
	Extra     string `json:"extra"`
}

func NewFirewallGenerator(cfg *config.Config) *FirewallGenerator {
	return &FirewallGenerator{
		cfg:       cfg,
		log:       logging.WithComponent("firewall"),
		ruleChain: "SPECTRESHIELD",
	}
}

func (fg *FirewallGenerator) GenerateBlockIPRules(ip string, reason string) []FirewallRule {
	rules := []FirewallRule{
		{
			Chain:   fg.ruleChain,
			Table:   "filter",
			SrcIP:   ip,
			Action:  "DROP",
			Comment: fmt.Sprintf("SpectreShield: block %s (%s)", ip, reason),
		},
		{
			Chain:   fg.ruleChain,
			Table:   "filter",
			DstIP:   ip,
			Action:  "DROP",
			Comment: fmt.Sprintf("SpectreShield: block outbound to %s (%s)", ip, reason),
		},
	}
	return rules
}

func (fg *FirewallGenerator) GenerateBlockPortRules(port uint16, protocol string, reason string) []FirewallRule {
	if protocol == "" {
		protocol = "tcp"
	}
	return []FirewallRule{
		{
			Chain:    fg.ruleChain,
			Table:    "filter",
			Protocol: protocol,
			DstPort:  fmt.Sprintf("%d", port),
			Action:   "DROP",
			Comment:  fmt.Sprintf("SpectreShield: block port %d/%s (%s)", port, protocol, reason),
		},
	}
}

func (fg *FirewallGenerator) GenerateBlockProcessRules(pid uint32, comm string) []FirewallRule {
	return []FirewallRule{
		{
			Chain:   fg.ruleChain,
			Table:   "filter",
			Extra:   fmt.Sprintf("-m owner --pid-owner %d", pid),
			Action:  "DROP",
			Comment: fmt.Sprintf("SpectreShield: block PID %d (%s)", pid, comm),
		},
	}
}

func (fg *FirewallGenerator) GenerateIsolationRules(reason string) []FirewallRule {
	return []FirewallRule{
		{
			Chain:   fg.ruleChain,
			Table:   "filter",
			Action:  "DROP",
			Comment: fmt.Sprintf("SpectreShield: network isolation (%s)", reason),
		},
	}
}

func (fg *FirewallGenerator) GenerateReverseShellRules(pid uint32, remoteIP string, remotePort uint16) []FirewallRule {
	rules := []FirewallRule{}

	rules = append(rules, FirewallRule{
		Chain:   fg.ruleChain,
		Table:   "filter",
		DstIP:   remoteIP,
		Action:  "DROP",
		Comment: fmt.Sprintf("SpectreShield: block reverse shell to %s:%d (PID %d)", remoteIP, remotePort, pid),
	})

	rules = append(rules, FirewallRule{
		Chain:    fg.ruleChain,
		Table:    "filter",
		Protocol: "tcp",
		DstPort:  fmt.Sprintf("%d", remotePort),
		State:    "NEW",
		Action:   "DROP",
		Comment:  fmt.Sprintf("SpectreShield: block reverse shell port %d (PID %d)", remotePort, pid),
	})

	return rules
}

func (fg *FirewallGenerator) GenerateC2BlockRules(ip string, ports []uint16) []FirewallRule {
	rules := []FirewallRule{}
	for _, port := range ports {
		rules = append(rules, FirewallRule{
			Chain:    fg.ruleChain,
			Table:    "filter",
			DstIP:    ip,
			Protocol: "tcp",
			DstPort:  fmt.Sprintf("%d", port),
			Action:   "DROP",
			Comment:  fmt.Sprintf("SpectreShield: block C2 %s:%d", ip, port),
		})
	}
	return rules
}

func (fg *FirewallGenerator) ApplyRules(rules []FirewallRule) error {
	fg.mu.Lock()
	defer fg.mu.Unlock()

	if err := fg.ensureChain(); err != nil {
		return fmt.Errorf("ensure chain: %w", err)
	}

	for _, rule := range rules {
		cmd := fg.buildIptablesCmd(rule)
		fg.log.Info("applying firewall rule", "rule", cmd)

		parts := strings.Fields(cmd)
		if len(parts) < 2 {
			continue
		}

		execCmd := exec.Command(parts[0], parts[1:]...)
		if output, err := execCmd.CombinedOutput(); err != nil {
			fg.log.Error("failed to apply rule", "rule", cmd, "output", string(output), "error", err)
			return fmt.Errorf("apply rule %q: %w", cmd, err)
		}
	}

	return nil
}

func (fg *FirewallGenerator) RemoveRules() error {
	fg.mu.Lock()
	defer fg.mu.Unlock()

	cmd := exec.Command("iptables", "-F", fg.ruleChain)
	if output, err := cmd.CombinedOutput(); err != nil {
		fg.log.Error("failed to flush chain", "output", string(output), "error", err)
	}

	cmd = exec.Command("iptables", "-D", "INPUT", "-j", fg.ruleChain)
	cmd.Run()

	cmd = exec.Command("iptables", "-D", "OUTPUT", "-j", fg.ruleChain)
	cmd.Run()

	cmd = exec.Command("iptables", "-X", fg.ruleChain)
	if output, err := cmd.CombinedOutput(); err != nil {
		fg.log.Error("failed to delete chain", "output", string(output), "error", err)
	}

	return nil
}

func (fg *FirewallGenerator) ListRules() ([]string, error) {
	cmd := exec.Command("iptables", "-L", fg.ruleChain, "-n", "-v", "--line-numbers")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	return strings.Split(string(output), "\n"), nil
}

func (fg *FirewallGenerator) ensureChain() error {
	cmd := exec.Command("iptables", "-L", fg.ruleChain, "-n")
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("iptables", "-N", fg.ruleChain)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("create chain: %w: %s", err, string(output))
		}

		cmd = exec.Command("iptables", "-I", "INPUT", "1", "-j", fg.ruleChain)
		cmd.Run()
		cmd = exec.Command("iptables", "-I", "OUTPUT", "1", "-j", fg.ruleChain)
		cmd.Run()

		fg.log.Info("created iptables chain", "chain", fg.ruleChain)
	}
	return nil
}

func (fg *FirewallGenerator) buildIptablesCmd(rule FirewallRule) string {
	parts := []string{"iptables", "-A", rule.Chain}

	if rule.Table != "" && rule.Table != "filter" {
		parts = []string{"iptables", "-t", rule.Table, "-A", rule.Chain}
	}

	if rule.SrcIP != "" {
		parts = append(parts, "-s", rule.SrcIP)
	}
	if rule.DstIP != "" {
		parts = append(parts, "-d", rule.DstIP)
	}
	if rule.Protocol != "" {
		parts = append(parts, "-p", rule.Protocol)
	}
	if rule.SrcPort != "" {
		parts = append(parts, "--sport", rule.SrcPort)
	}
	if rule.DstPort != "" {
		parts = append(parts, "--dport", rule.DstPort)
	}
	if rule.Interface != "" {
		parts = append(parts, "-i", rule.Interface)
	}
	if rule.Extra != "" {
		parts = append(parts, strings.Fields(rule.Extra)...)
	}
	if rule.State != "" {
		parts = append(parts, "-m", "state", "--state", rule.State)
	}
	if rule.Comment != "" {
		parts = append(parts, "-m", "comment", "--comment", fmt.Sprintf("%q", rule.Comment))
	}
	parts = append(parts, "-j", rule.Action)

	return strings.Join(parts, " ")
}
