//go:build linux

package compliance

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Framework represents a compliance framework
type Framework struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Version     string     `json:"version"`
	Controls    []*Control `json:"controls"`
}

// Control represents a single compliance control
type Control struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Check       string   `json:"check"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references,omitempty"`
}

// Result represents a check result
type Result struct {
	ControlID string    `json:"control_id"`
	Status    string    `json:"status"`
	Details   string    `json:"details"`
	Timestamp time.Time `json:"timestamp"`
}

// Report represents a compliance report
type Report struct {
	Framework string    `json:"framework"`
	Hostname  string    `json:"hostname"`
	Timestamp time.Time `json:"timestamp"`
	Results   []*Result `json:"results"`
	Passed    int       `json:"passed"`
	Failed    int       `json:"failed"`
	Errors    int       `json:"errors"`
	Score     float64   `json:"score"`
}

// Engine is the compliance engine
type Engine struct {
	frameworks map[string]*Framework
	mu         sync.RWMutex
}

// NewEngine creates a new compliance engine
func NewEngine() *Engine {
	e := &Engine{
		frameworks: make(map[string]*Framework),
	}
	e.LoadDefaults()
	return e
}

// LoadDefaults loads default compliance frameworks
func (e *Engine) LoadDefaults() {
	cis := &Framework{
		ID:          "cis",
		Name:        "CIS Benchmark",
		Description: "Center for Internet Security Benchmark",
		Version:     "3.0",
		Controls: []*Control{
			{ID: "1.1.1", Title: "Disable unused filesystems", Severity: "medium",
				Check: "lsmod | grep -E 'cramfs|freevxfs|jffs2|hfs|squashfs|udf'", Remediation: "Add to /etc/modprobe.d/disable.conf"},
			{ID: "1.1.2", Title: "Ensure /tmp is separate partition", Severity: "medium",
				Check: "mount | grep 'on /tmp '", Remediation: "Create separate /tmp partition"},
			{ID: "1.1.3", Title: "Ensure /var is separate partition", Severity: "medium",
				Check: "mount | grep 'on /var '", Remediation: "Create separate /var partition"},
			{ID: "1.1.4", Title: "Ensure /var/tmp is separate partition", Severity: "medium",
				Check: "mount | grep 'on /var/tmp '", Remediation: "Create separate /var/tmp partition"},
			{ID: "1.1.5", Title: "Ensure /home is separate partition", Severity: "medium",
				Check: "mount | grep 'on /home '", Remediation: "Create separate /home partition"},
			{ID: "1.3.1", Title: "Ensure AIDE is installed", Severity: "medium",
				Check: "dpkg -s aide || rpm -q aide", Remediation: "apt-get install aide"},
			{ID: "1.4.1", Title: "Ensure permissions on bootloader config", Severity: "high",
				Check: "stat -L -c '%a %u %g' /boot/grub/grub.cfg", Remediation: "chmod 600 /boot/grub/grub.cfg"},
			{ID: "1.5.1", Title: "Ensure /tmp has noexec option", Severity: "medium",
				Check: "mount | grep 'on /tmp '", Remediation: "Add noexec to /tmp mount options"},
			{ID: "2.1.1", Title: "Ensure NTP is configured", Severity: "medium",
				Check: "systemctl is-enabled chronyd || systemctl is-enabled ntpd", Remediation: "systemctl enable chronyd"},
			{ID: "2.2.1", Title: "Ensure time synchronization is configured", Severity: "low",
				Check: "timedatectl | grep 'NTP synchronized'", Remediation: "timedatectl set-ntp true"},
			{ID: "3.1.1", Title: "Ensure IP forwarding is disabled", Severity: "medium",
				Check: "sysctl net.ipv4.ip_forward", Remediation: "sysctl -w net.ipv4.ip_forward=0"},
			{ID: "3.2.1", Title: "Ensure source routed packets are rejected", Severity: "medium",
				Check: "sysctl net.ipv4.conf.all.accept_source_route", Remediation: "sysctl -w net.ipv4.conf.all.accept_source_route=0"},
			{ID: "3.2.2", Title: "Ensure ICMP redirects are not accepted", Severity: "medium",
				Check: "sysctl net.ipv4.conf.all.accept_redirects", Remediation: "sysctl -w net.ipv4.conf.all.accept_redirects=0"},
			{ID: "4.1.1", Title: "Ensure auditd is installed", Severity: "medium",
				Check: "dpkg -s auditd || rpm -q auditd", Remediation: "apt-get install auditd"},
			{ID: "4.1.2", Title: "Ensure auditd is running", Severity: "medium",
				Check: "systemctl is-enabled auditd", Remediation: "systemctl enable auditd"},
			{ID: "5.1.1", Title: "Ensure cron daemon is enabled", Severity: "medium",
				Check: "systemctl is-enabled cron", Remediation: "systemctl enable cron"},
			{ID: "5.2.1", Title: "Ensure permissions on /etc/passwd", Severity: "high",
				Check: "stat -L -c '%a %u %g' /etc/passwd", Remediation: "chmod 644 /etc/passwd"},
			{ID: "5.2.2", Title: "Ensure permissions on /etc/shadow", Severity: "high",
				Check: "stat -L -c '%a %u %g' /etc/shadow", Remediation: "chmod 640 /etc/shadow"},
			{ID: "5.2.3", Title: "Ensure permissions on /etc/group", Severity: "high",
				Check: "stat -L -c '%a %u %g' /etc/group", Remediation: "chmod 644 /etc/group"},
			{ID: "5.2.4", Title: "Ensure permissions on /etc/gshadow", Severity: "high",
				Check: "stat -L -c '%a %u %g' /etc/gshadow", Remediation: "chmod 640 /etc/gshadow"},
			{ID: "5.3.1", Title: "Ensure password creation requirements", Severity: "medium",
				Check: "grep -E '^minlen|^minclass' /etc/security/pwquality.conf", Remediation: "Configure pwquality.conf"},
			{ID: "5.3.2", Title: "Ensure lockout for failed password attempts", Severity: "medium",
				Check: "grep -E 'deny|unlock_time' /etc/pam.d/common-auth", Remediation: "Configure pam_faillock"},
			{ID: "5.4.1", Title: "Ensure password expiration is less than 365 days", Severity: "medium",
				Check: "grep -E '^PASS_MAX_DAYS' /etc/login.defs", Remediation: "Set PASS_MAX_DAYS 365"},
			{ID: "5.4.2", Title: "Ensure minimum days between password changes", Severity: "medium",
				Check: "grep -E '^PASS_MIN_DAYS' /etc/login.defs", Remediation: "Set PASS_MIN_DAYS 7"},
			{ID: "5.4.3", Title: "Ensure password expiration warning days", Severity: "low",
				Check: "grep -E '^PASS_WARN_AGE' /etc/login.defs", Remediation: "Set PASS_WARN_AGE 7"},
			{ID: "6.1.1", Title: "Ensure permissions on /etc/passwd are configured", Severity: "high",
				Check: "stat -L -c '%a %u %g' /etc/passwd", Remediation: "chmod 644 /etc/passwd"},
			{ID: "6.1.2", Title: "Ensure permissions on /etc/shadow are configured", Severity: "high",
				Check: "stat -L -c '%a %u %g' /etc/shadow", Remediation: "chmod 640 /etc/shadow"},
			{ID: "6.2.1", Title: "Ensure root is the only UID 0 account", Severity: "high",
				Check: "awk -F: '($3 == 0) { print $1 }' /etc/passwd", Remediation: "Remove non-root UID 0 accounts"},
			{ID: "6.2.2", Title: "Ensure root PATH contains only local directories", Severity: "high",
				Check: "echo $PATH | grep -E '::|:.:|:$'", Remediation: "Remove . from root PATH"},
		},
	}
	e.frameworks["cis"] = cis

	pci := &Framework{
		ID:          "pci-dss",
		Name:        "PCI DSS",
		Description: "Payment Card Industry Data Security Standard",
		Version:     "4.0",
		Controls: []*Control{
			{ID: "PCI-1.1", Title: "Install and maintain network security controls", Severity: "high",
				Check: "iptables -L -n | head -20", Remediation: "Configure firewall rules"},
			{ID: "PCI-2.1", Title: "Change vendor-supplied defaults", Severity: "high",
				Check: "grep -E '^(root|admin)' /etc/shadow", Remediation: "Change default passwords"},
			{ID: "PCI-3.1", Title: "Protect stored account data", Severity: "critical",
				Check: "grep -r 'password' /etc/", Remediation: "Encrypt stored credentials"},
			{ID: "PCI-4.1", Title: "Encrypt transmission of cardholder data", Severity: "high",
				Check: "ss -tlnp | grep -E ':443|:8443'", Remediation: "Use TLS for all connections"},
			{ID: "PCI-5.1", Title: "Protect all systems from malware", Severity: "high",
				Check: "systemctl is-enabled antivirus || true", Remediation: "Install antivirus software"},
			{ID: "PCI-6.1", Title: "Identify and manage security vulnerabilities", Severity: "high",
				Check: "apt list --upgradable 2>/dev/null | wc -l", Remediation: "Apply security patches"},
			{ID: "PCI-7.1", Title: "Restrict access to system components", Severity: "high",
				Check: "grep -E '^(root|admin):' /etc/passwd | wc -l", Remediation: "Implement least privilege"},
			{ID: "PCI-8.1", Title: "Identify users and authenticate access", Severity: "high",
				Check: "systemctl is-enabled sshd", Remediation: "Implement strong authentication"},
			{ID: "PCI-9.1", Title: "Restrict physical access to cardholder data", Severity: "medium",
				Check: "echo 'Physical access controls required'", Remediation: "Implement physical security"},
			{ID: "PCI-10.1", Title: "Log and monitor all access", Severity: "high",
				Check: "systemctl is-enabled auditd", Remediation: "Enable audit logging"},
			{ID: "PCI-11.1", Title: "Test security systems regularly", Severity: "medium",
				Check: "echo 'Regular penetration testing required'", Remediation: "Conduct regular tests"},
			{ID: "PCI-12.1", Title: "Support information security with policies", Severity: "low",
				Check: "echo 'Security policies required'", Remediation: "Develop security policies"},
		},
	}
	e.frameworks["pci-dss"] = pci

	hipaa := &Framework{
		ID:          "hipaa",
		Name:        "HIPAA",
		Description: "Health Insurance Portability and Accountability Act",
		Version:     "2023",
		Controls: []*Control{
			{ID: "HIPAA-164.312.a", Title: "Access control", Severity: "high",
				Check: "grep -E '^PermitRootLogin' /etc/ssh/sshd_config", Remediation: "Implement access controls"},
			{ID: "HIPAA-164.312.b", Title: "Audit controls", Severity: "high",
				Check: "systemctl is-enabled auditd", Remediation: "Enable audit logging"},
			{ID: "HIPAA-164.312.c", Title: "Integrity controls", Severity: "high",
				Check: "dpkg -s aide || rpm -q aide", Remediation: "Install file integrity monitoring"},
			{ID: "HIPAA-164.312.d", Title: "Person or entity authentication", Severity: "high",
				Check: "grep -E '^PasswordAuthentication' /etc/ssh/sshd_config", Remediation: "Implement MFA"},
			{ID: "HIPAA-164.312.e", Title: "Transmission security", Severity: "high",
				Check: "ss -tlnp | grep -E ':443|:8443'", Remediation: "Encrypt all transmissions"},
		},
	}
	e.frameworks["hipaa"] = hipaa

	nist := &Framework{
		ID:          "nist-800-53",
		Name:        "NIST 800-53",
		Description: "NIST Special Publication 800-53",
		Version:     "5.0",
		Controls: []*Control{
			{ID: "AC-2", Title: "Account Management", Severity: "high",
				Check: "awk -F: '$3 >= 1000 {print $1}' /etc/passwd | wc -l", Remediation: "Review and manage accounts"},
			{ID: "AC-3", Title: "Access Enforcement", Severity: "high",
				Check: "ls -la /etc/ssh/sshd_config", Remediation: "Enforce access controls"},
			{ID: "AC-6", Title: "Least Privilege", Severity: "high",
				Check: "grep -E '^PermitRootLogin' /etc/ssh/sshd_config", Remediation: "Implement least privilege"},
			{ID: "AU-2", Title: "Audit Events", Severity: "high",
				Check: "systemctl is-enabled auditd", Remediation: "Enable audit logging"},
			{ID: "AU-3", Title: "Content of Audit Records", Severity: "medium",
				Check: "cat /etc/audit/auditd.conf | grep log_file", Remediation: "Configure audit logging"},
			{ID: "CA-7", Title: "Continuous Monitoring", Severity: "medium",
				Check: "echo 'Continuous monitoring required'", Remediation: "Implement monitoring"},
			{ID: "CM-2", Title: "Baseline Configuration", Severity: "medium",
				Check: "echo 'Baseline configuration required'", Remediation: "Establish baselines"},
			{ID: "CM-6", Title: "Configuration Settings", Severity: "medium",
				Check: "sysctl net.ipv4.ip_forward", Remediation: "Apply secure configurations"},
			{ID: "IA-2", Title: "Identification and Authentication", Severity: "high",
				Check: "grep -E '^PasswordAuthentication' /etc/ssh/sshd_config", Remediation: "Implement strong auth"},
			{ID: "IA-5", Title: "Authenticator Management", Severity: "high",
				Check: "grep -E '^PASS_MAX_DAYS' /etc/login.defs", Remediation: "Manage authenticators"},
			{ID: "SC-7", Title: "Boundary Protection", Severity: "high",
				Check: "iptables -L -n | wc -l", Remediation: "Implement boundary protection"},
			{ID: "SC-8", Title: "Transmission Confidentiality", Severity: "high",
				Check: "ss -tlnp | grep -E ':443|:8443'", Remediation: "Encrypt transmissions"},
			{ID: "SI-2", Title: "Flaw Remediation", Severity: "high",
				Check: "apt list --upgradable 2>/dev/null | wc -l", Remediation: "Apply security patches"},
			{ID: "SI-4", Title: "System Monitoring", Severity: "medium",
				Check: "systemctl is-enabled auditd", Remediation: "Enable system monitoring"},
		},
	}
	e.frameworks["nist-800-53"] = nist

	cisDocker := &Framework{
		ID:          "cis-docker",
		Name:        "CIS Docker Benchmark",
		Description: "Center for Internet Security Docker Benchmark",
		Version:     "1.6",
		Controls: []*Control{
			{ID: "2.1", Title: "Ensure network traffic is restricted", Severity: "high",
				Check: "docker network ls --quiet | xargs -I {} docker network inspect {} -f '{{.Name}} {{.Driver}}'", Remediation: "Configure network isolation"},
			{ID: "2.2", Title: "Ensure the container host has been hardened", Severity: "high",
				Check: "cat /etc/docker/daemon.json", Remediation: "Harden container host"},
			{ID: "2.3", Title: "Ensure Docker daemon configuration file ownership", Severity: "medium",
				Check: "stat -c '%U:%G' /etc/docker/daemon.json", Remediation: "Set proper ownership"},
			{ID: "2.4", Title: "Ensure Docker daemon configuration file permissions", Severity: "medium",
				Check: "stat -c '%a' /etc/docker/daemon.json", Remediation: "Set proper permissions"},
			{ID: "2.5", Title: "Ensure TLS authentication for Docker daemon", Severity: "high",
				Check: "grep -E '^--tlsverify' /etc/docker/daemon.json || true", Remediation: "Enable TLS authentication"},
			{ID: "2.6", Title: "Ensure default ulimit is configured", Severity: "medium",
				Check: "grep -E 'default-ulimits' /etc/docker/daemon.json || true", Remediation: "Configure default ulimits"},
			{ID: "2.7", Title: "Ensure enable aufs is disabled", Severity: "medium",
				Check: "grep -E 'storage-driver' /etc/docker/daemon.json || true", Remediation: "Disable aufs storage driver"},
			{ID: "2.8", Title: "Ensure TLS authentication for Docker daemon is configured", Severity: "high",
				Check: "ls /etc/docker/certs.d/", Remediation: "Configure TLS certificates"},
			{ID: "2.9", Title: "Ensure default ulimit is configured", Severity: "medium",
				Check: "docker info | grep -i 'ulimit'", Remediation: "Configure default ulimits"},
			{ID: "2.10", Title: "Ensure set userland-proxy is set to false", Severity: "medium",
				Check: "grep -E 'userland-proxy' /etc/docker/daemon.json || true", Remediation: "Disable userland proxy"},
			{ID: "2.11", Title: "Ensure encrypted communication is used", Severity: "high",
				Check: "docker info | grep -i 'tls'", Remediation: "Enable encrypted communication"},
			{ID: "2.12", Title: "Ensure live restore is enabled", Severity: "medium",
				Check: "docker info | grep -i 'live restore'", Remediation: "Enable live restore"},
			{ID: "2.13", Title: "Ensure userland proxy is set to false", Severity: "medium",
				Check: "grep -E 'userland-proxy' /etc/docker/daemon.json || true", Remediation: "Disable userland proxy"},
			{ID: "2.14", Title: "Ensure daemon-wide custom seccomp profile is used", Severity: "medium",
				Check: "grep -E 'seccomp-profile' /etc/docker/daemon.json || true", Remediation: "Apply custom seccomp profile"},
			{ID: "2.15", Title: "Ensure only trusted registries are allowed", Severity: "high",
				Check: "cat /etc/docker/daemon.json", Remediation: "Configure trusted registries"},
			{ID: "2.16", Title: "Ensure aufs storage driver is not used", Severity: "medium",
				Check: "docker info | grep -i 'storage driver'", Remediation: "Use overlay2 storage driver"},
			{ID: "2.17", Title: "Ensure commands are not run within running containers", Severity: "medium",
				Check: "docker ps --quiet | wc -l", Remediation: "Avoid exec into containers"},
			{ID: "2.18", Title: "Ensure security profile is set to docker/default", Severity: "medium",
				Check: "docker info | grep -i 'security options'", Remediation: "Use default security profile"},
			{ID: "2.19", Title: "Ensure container health is checked at runtime", Severity: "low",
				Check: "docker ps --quiet | wc -l", Remediation: "Enable health checks"},
			{ID: "2.20", Title: "Ensure container's default gateway is set", Severity: "medium",
				Check: "docker network inspect bridge -f '{{.IPAM.Config}}'", Remediation: "Configure default gateway"},
		},
	}
	e.frameworks["cis-docker"] = cisDocker

	k8s := &Framework{
		ID:          "kubernetes",
		Name:        "Kubernetes CIS Benchmark",
		Description: "Center for Internet Security Kubernetes Benchmark",
		Version:     "1.8",
		Controls: []*Control{
			{ID: "4.1.1", Title: "Ensure that the --anonymous-auth argument is set to false", Severity: "high",
				Check: "grep -E '--anonymous-auth' /etc/kubernetes/manifests/kube-apiserver.yaml || true", Remediation: "Set --anonymous-auth=false"},
			{ID: "4.1.2", Title: "Ensure that the --basic-auth-file argument is not set", Severity: "high",
				Check: "grep -E '--basic-auth-file' /etc/kubernetes/manifests/kube-apiserver.yaml || true", Remediation: "Remove --basic-auth-file argument"},
			{ID: "4.1.3", Title: "Ensure that the --token-auth-file argument is not set", Severity: "high",
				Check: "grep -E '--token-auth-file' /etc/kubernetes/manifests/kube-apiserver.yaml || true", Remediation: "Remove --token-auth-file argument"},
			{ID: "4.1.4", Title: "Ensure that the --kubelet-https argument is set to true", Severity: "medium",
				Check: "grep -E '--kubelet-https' /etc/kubernetes/manifests/kube-apiserver.yaml || true", Remediation: "Set --kubelet-https=true"},
			{ID: "4.1.5", Title: "Ensure that the --kubelet-client-certificate argument is set", Severity: "high",
				Check: "grep -E '--kubelet-client-certificate' /etc/kubernetes/manifests/kube-apiserver.yaml || true", Remediation: "Set --kubelet-client-certificate"},
			{ID: "4.1.6", Title: "Ensure that the --kubelet-client-key argument is set", Severity: "high",
				Check: "grep -E '--kubelet-client-key' /etc/kubernetes/manifests/kube-apiserver.yaml || true", Remediation: "Set --kubelet-client-key"},
			{ID: "4.1.7", Title: "Ensure that the --enable-admission-plugins argument is set", Severity: "high",
				Check: "grep -E '--enable-admission-plugins' /etc/kubernetes/manifests/kube-apiserver.yaml || true", Remediation: "Enable required admission plugins"},
			{ID: "4.1.8", Title: "Ensure that the --audit-log-path argument is set", Severity: "high",
				Check: "grep -E '--audit-log-path' /etc/kubernetes/manifests/kube-apiserver.yaml || true", Remediation: "Set --audit-log-path"},
			{ID: "4.1.9", Title: "Ensure that the --audit-log-maxage argument is set", Severity: "medium",
				Check: "grep -E '--audit-log-maxage' /etc/kubernetes/manifests/kube-apiserver.yaml || true", Remediation: "Set --audit-log-maxage"},
			{ID: "4.1.10", Title: "Ensure that the --audit-log-maxbackup argument is set", Severity: "medium",
				Check: "grep -E '--audit-log-maxbackup' /etc/kubernetes/manifests/kube-apiserver.yaml || true", Remediation: "Set --audit-log-maxbackup"},
			{ID: "4.1.11", Title: "Ensure that the --audit-log-maxsize argument is set", Severity: "medium",
				Check: "grep -E '--audit-log-maxsize' /etc/kubernetes/manifests/kube-apiserver.yaml || true", Remediation: "Set --audit-log-maxsize"},
			{ID: "4.1.12", Title: "Ensure that the --request-timeout argument is set", Severity: "medium",
				Check: "grep -E '--request-timeout' /etc/kubernetes/manifests/kube-apiserver.yaml || true", Remediation: "Set --request-timeout"},
			{ID: "4.1.13", Title: "Ensure that the --service-account-lookup argument is set to true", Severity: "high",
				Check: "grep -E '--service-account-lookup' /etc/kubernetes/manifests/kube-apiserver.yaml || true", Remediation: "Set --service-account-lookup=true"},
			{ID: "4.1.14", Title: "Ensure that the --service-account-key-file argument is set", Severity: "high",
				Check: "grep -E '--service-account-key-file' /etc/kubernetes/manifests/kube-apiserver.yaml || true", Remediation: "Set --service-account-key-file"},
			{ID: "4.1.15", Title: "Ensure that the --etunnel-cert-file argument is set", Severity: "high",
				Check: "grep -E '--etcd-certfile' /etc/kubernetes/manifests/kube-apiserver.yaml || true", Remediation: "Set --etcd-certfile"},
			{ID: "4.1.16", Title: "Ensure that the --etcd-keyfile argument is set", Severity: "high",
				Check: "grep -E '--etcd-keyfile' /etc/kubernetes/manifests/kube-apiserver.yaml || true", Remediation: "Set --etcd-keyfile"},
			{ID: "4.2.1", Title: "Ensure that the --profiling argument is set to false", Severity: "medium",
				Check: "grep -E '--profiling' /etc/kubernetes/manifests/kube-controller-manager.yaml || true", Remediation: "Set --profiling=false"},
			{ID: "4.2.2", Title: "Ensure that the --use-service-account-credentials argument is set to true", Severity: "high",
				Check: "grep -E '--use-service-account-credentials' /etc/kubernetes/manifests/kube-controller-manager.yaml || true", Remediation: "Set --use-service-account-credentials=true"},
			{ID: "4.2.3", Title: "Ensure that the --service-account-private-key-file argument is set", Severity: "high",
				Check: "grep -E '--service-account-private-key-file' /etc/kubernetes/manifests/kube-controller-manager.yaml || true", Remediation: "Set --service-account-private-key-file"},
			{ID: "4.2.4", Title: "Ensure that the --root-ca-file argument is set", Severity: "high",
				Check: "grep -E '--root-ca-file' /etc/kubernetes/manifests/kube-controller-manager.yaml || true", Remediation: "Set --root-ca-file"},
			{ID: "4.2.5", Title: "Ensure that the RotateKubeletServerCertificate argument is set to true", Severity: "high",
				Check: "grep -E 'RotateKubeletServerCertificate' /etc/kubernetes/manifests/kube-controller-manager.yaml || true", Remediation: "Enable RotateKubeletServerCertificate"},
			{ID: "4.2.6", Title: "Ensure that the --bind-address argument is set to 127.0.0.1", Severity: "medium",
				Check: "grep -E '--bind-address' /etc/kubernetes/manifests/kube-controller-manager.yaml || true", Remediation: "Set --bind-address=127.0.0.1"},
		},
	}
	e.frameworks["kubernetes"] = k8s
}

// RunCheck runs a single check
func (e *Engine) RunCheck(control *Control) *Result {
	result := &Result{
		ControlID: control.ID,
		Timestamp: time.Now(),
	}

	parts := strings.Fields(control.Check)
	if len(parts) == 0 {
		result.Status = "error"
		result.Details = "No check command specified"
		return result
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		result.Status = "fail"
		result.Details = fmt.Sprintf("Check failed: %v", err)
	} else {
		outputStr := strings.TrimSpace(string(output))
		if outputStr == "" {
			result.Status = "pass"
			result.Details = "Check passed"
		} else {
			result.Status = "fail"
			result.Details = outputStr
		}
	}

	return result
}

// RunFramework runs all checks for a framework
func (e *Engine) RunFramework(frameworkID string) *Report {
	e.mu.RLock()
	framework := e.frameworks[frameworkID]
	e.mu.RUnlock()

	if framework == nil {
		return nil
	}

	hostname, _ := os.Hostname()
	report := &Report{
		Framework: frameworkID,
		Hostname:  hostname,
		Timestamp: time.Now(),
	}

	for _, control := range framework.Controls {
		result := e.RunCheck(control)
		report.Results = append(report.Results, result)

		switch result.Status {
		case "pass":
			report.Passed++
		case "fail":
			report.Failed++
		case "error":
			report.Errors++
		}
	}

	total := report.Passed + report.Failed + report.Errors
	if total > 0 {
		report.Score = float64(report.Passed) / float64(total) * 100
	}

	return report
}

// RunFrameworks runs all frameworks
func (e *Engine) RunFrameworks() map[string]*Report {
	e.mu.RLock()
	ids := make([]string, 0, len(e.frameworks))
	for id := range e.frameworks {
		ids = append(ids, id)
	}
	e.mu.RUnlock()

	reports := make(map[string]*Report)
	for _, id := range ids {
		reports[id] = e.RunFramework(id)
	}
	return reports
}

// GetFrameworks returns all frameworks
func (e *Engine) GetFrameworks() []*Framework {
	e.mu.RLock()
	defer e.mu.RUnlock()
	frameworks := make([]*Framework, 0, len(e.frameworks))
	for _, f := range e.frameworks {
		frameworks = append(frameworks, f)
	}
	return frameworks
}

// GetFramework returns a specific framework
func (e *Engine) GetFramework(id string) *Framework {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.frameworks[id]
}

// ExportReport exports a report to JSON
func (e *Engine) ExportReport(report *Report, path string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ExportReports exports multiple reports to JSON
func (e *Engine) ExportReports(reports map[string]*Report, path string) error {
	data, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// Summary returns a summary of results by status
func (e *Engine) Summary(report *Report) map[string]int {
	summary := map[string]int{
		"pass":  0,
		"fail":  0,
		"error": 0,
	}
	for _, r := range report.Results {
		summary[r.Status]++
	}
	return summary
}

// FilterBySeverity returns results matching the given severity
func (e *Engine) FilterBySeverity(report *Report, severity string) []*Result {
	e.mu.RLock()
	defer e.mu.RUnlock()
	framework := e.frameworks[report.Framework]
	if framework == nil {
		return nil
	}
	controlMap := make(map[string]*Control)
	for _, c := range framework.Controls {
		controlMap[c.ID] = c
	}
	var result []*Result
	for _, r := range report.Results {
		if ctrl, ok := controlMap[r.ControlID]; ok && ctrl.Severity == severity {
			result = append(result, r)
		}
	}
	return result
}

// FilterByStatus returns results matching the given status
func (e *Engine) FilterByStatus(report *Report, status string) []*Result {
	var result []*Result
	for _, r := range report.Results {
		if r.Status == status {
			result = append(result, r)
		}
	}
	return result
}

// ScoreToGrade converts a numeric score to a letter grade
func ScoreToGrade(score float64) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// GenerateSummary generates a human-readable summary
func GenerateSummary(report *Report) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Compliance Report: %s\n", report.Framework))
	sb.WriteString(fmt.Sprintf("Hostname: %s\n", report.Hostname))
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", report.Timestamp.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Score: %.1f%% (%s)\n", report.Score, ScoreToGrade(report.Score)))
	sb.WriteString(fmt.Sprintf("Passed: %d\n", report.Passed))
	sb.WriteString(fmt.Sprintf("Failed: %d\n", report.Failed))
	sb.WriteString(fmt.Sprintf("Errors: %d\n", report.Errors))
	sb.WriteString(fmt.Sprintf("Total: %d\n", report.Passed+report.Failed+report.Errors))
	return sb.String()
}

// GenerateRemediation generates a remediation report
func GenerateRemediation(report *Report, framework *Framework) string {
	var sb strings.Builder
	sb.WriteString("Remediation Steps:\n")
	sb.WriteString("==================\n\n")

	controlMap := make(map[string]*Control)
	for _, c := range framework.Controls {
		controlMap[c.ID] = c
	}

	for _, r := range report.Results {
		if r.Status == "fail" {
			if ctrl, ok := controlMap[r.ControlID]; ok {
				sb.WriteString(fmt.Sprintf("[%s] %s\n", ctrl.ID, ctrl.Title))
				sb.WriteString(fmt.Sprintf("  Severity: %s\n", ctrl.Severity))
				sb.WriteString(fmt.Sprintf("  Issue: %s\n", r.Details))
				sb.WriteString(fmt.Sprintf("  Remediation: %s\n\n", ctrl.Remediation))
			}
		}
	}
	return sb.String()
}
