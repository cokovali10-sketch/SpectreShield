//go:build linux

package hermesbridge

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/cokovali10-sketch/SpectreShield/internal/config"
	"github.com/cokovali10-sketch/SpectreShield/internal/logging"
)

type SeccompGenerator struct {
	cfg *config.Config
	log *logging.Logger
	mu  sync.Mutex

	syscallMap map[string]int
}

type SeccompProfile struct {
	DefaultAction string           `json:"defaultAction"`
	Architectures []string         `json:"architectures"`
	Syscalls      []SeccompSyscall `json:"syscalls"`
}

type SeccompSyscall struct {
	Names  []string     `json:"names"`
	Action string       `json:"action"`
	Args   []SeccompArg `json:"args,omitempty"`
}

type SeccompArg struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"value_two,omitempty"`
	Op       string `json:"op"`
}

func NewSeccompGenerator(cfg *config.Config) *SeccompGenerator {
	sg := &SeccompGenerator{
		cfg: cfg,
		log: logging.WithComponent("seccomp"),
	}
	sg.initSyscallMap()
	return sg
}

func (sg *SeccompGenerator) GenerateProfile(threatType string, allowedSyscalls []string) *SeccompProfile {
	sg.mu.Lock()
	defer sg.mu.Unlock()

	profile := &SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"},
	}

	alwaysAllow := []string{
		"read", "write", "open", "close", "stat", "fstat", "lstat",
		"poll", "lseek", "mmap", "mprotect", "munmap", "brk",
		"rt_sigaction", "rt_sigprocmask", "ioctl", "access",
		"pipe", "select", "sched_yield", "mremap", "msync",
		"mincore", "madvise", "shmget", "shmat", "shmctl",
		"dup", "dup2", "nanosleep", "getpid", "socket",
		"connect", "clone", "fork", "vfork", "execve",
		"exit", "wait4", "kill", "uname", "semget", "semop",
		"semctl", "shmdt", "msgget", "msgsnd", "msgrcv",
		"msgctl", "fcntl", "flock", "fsync", "fdatasync",
		"truncate", "ftruncate", "getdents", "getcwd",
		"chdir", "fchdir", "rename", "mkdir", "rmdir",
		"creat", "link", "unlink", "symlink", "readlink",
		"chmod", "fchmod", "chown", "fchown", "lchown",
		"umask", "gettimeofday", "getuid", "getgid",
		"geteuid", "getegid", "getppid", "getpgrp",
		"setpgid", "getgroups", "setgroups", "sigaltstack",
		"rt_sigaction", "rt_sigprocmask", "prctl",
		"arch_prctl", "getrlimit", "setrlimit",
		"time", "clock_gettime", "clock_getres",
		"epoll_create", "epoll_wait", "epoll_ctl",
		"exit_group", "futex", "set_robust_list",
		"get_robust_list", "epoll_create1",
	}

	switch threatType {
	case "reverse_shell":
		profile.Syscalls = append(profile.Syscalls, SeccompSyscall{
			Names:  []string{"connect", "sendto", "sendmsg"},
			Action: "SCMP_ACT_ERRNO",
		})
		profile.Syscalls = append(profile.Syscalls, SeccompSyscall{
			Names:  []string{"execve", "fork", "vfork", "clone"},
			Action: "SCMP_ACT_ALLOW",
		})

	case "privilege_escalation":
		profile.Syscalls = append(profile.Syscalls, SeccompSyscall{
			Names: []string{"setuid", "setgid", "setreuid", "setregid",
				"setresuid", "setresgid", "setfsuid", "setfsgid",
				"mount", "umount2", "chroot", "pivot_root"},
			Action: "SCMP_ACT_ERRNO",
		})

	case "data_exfiltration":
		profile.Syscalls = append(profile.Syscalls, SeccompSyscall{
			Names:  []string{"sendto", "sendmsg", "sendmmsg"},
			Action: "SCMP_ACT_ERRNO",
		})

	case "file_tampering":
		profile.Syscalls = append(profile.Syscalls, SeccompSyscall{
			Names: []string{"unlink", "unlinkat", "rename", "renameat",
				"chmod", "fchmod", "chown", "fchown",
				"truncate", "ftruncate"},
			Action: "SCMP_ACT_ERRNO",
		})

	case "fork_bomb":
		profile.Syscalls = append(profile.Syscalls, SeccompSyscall{
			Names:  []string{"clone", "fork", "vfork", "clone3"},
			Action: "SCMP_ACT_ERRNO",
		})

	case "kernel_module":
		profile.Syscalls = append(profile.Syscalls, SeccompSyscall{
			Names:  []string{"init_module", "finit_module", "delete_module"},
			Action: "SCMP_ACT_ERRNO",
		})

	case "anti_debugging":
		profile.Syscalls = append(profile.Syscalls, SeccompSyscall{
			Names:  []string{"ptrace"},
			Action: "SCMP_ACT_ERRNO",
		})

	default:
		profile.Syscalls = append(profile.Syscalls, SeccompSyscall{
			Names: []string{"ptrace", "init_module", "finit_module",
				"mount", "umount2", "chroot", "pivot_root"},
			Action: "SCMP_ACT_ERRNO",
		})
	}

	profile.Syscalls = append(profile.Syscalls, SeccompSyscall{
		Names:  alwaysAllow,
		Action: "SCMP_ACT_ALLOW",
	})

	if len(allowedSyscalls) > 0 {
		profile.Syscalls = append(profile.Syscalls, SeccompSyscall{
			Names:  allowedSyscalls,
			Action: "SCMP_ACT_ALLOW",
		})
	}

	return profile
}

func (sg *SeccompGenerator) GenerateFromThreat(category string) *SeccompProfile {
	return sg.GenerateProfile(category, nil)
}

func (sg *SeccompGenerator) GenerateCustom(allowed []string, blocked []string) *SeccompProfile {
	sg.mu.Lock()
	defer sg.mu.Unlock()

	profile := &SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"},
	}

	if len(blocked) > 0 {
		profile.Syscalls = append(profile.Syscalls, SeccompSyscall{
			Names:  blocked,
			Action: "SCMP_ACT_ERRNO",
		})
	}

	if len(allowed) > 0 {
		profile.Syscalls = append(profile.Syscalls, SeccompSyscall{
			Names:  allowed,
			Action: "SCMP_ACT_ALLOW",
		})
	}

	return profile
}

func (sg *SeccompGenerator) SaveProfile(profile *SeccompProfile, path string) error {
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal seccomp profile: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

func (sg *SeccompGenerator) ProfileToJSON(profile *SeccompProfile) string {
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data)
}

func (sg *SeccompGenerator) ValidateProfile(profile *SeccompProfile) error {
	if profile.DefaultAction == "" {
		return fmt.Errorf("defaultAction is required")
	}
	validActions := map[string]bool{
		"SCMP_ACT_ALLOW": true, "SCMP_ACT_ERRNO": true,
		"SCMP_ACT_KILL": true, "SCMP_ACT_TRACE": true,
		"SCMP_ACT_LOG": true,
	}
	if !validActions[profile.DefaultAction] {
		return fmt.Errorf("invalid defaultAction: %s", profile.DefaultAction)
	}
	for i, sc := range profile.Syscalls {
		for _, name := range sc.Names {
			if _, ok := sg.syscallMap[name]; !ok {
				return fmt.Errorf("syscalls[%d]: unknown syscall %s", i, name)
			}
		}
	}
	return nil
}

func (sg *SeccompGenerator) GetSupportedSyscalls() []string {
	syscalls := make([]string, 0, len(sg.syscallMap))
	for name := range sg.syscallMap {
		syscalls = append(syscalls, name)
	}
	sort.Strings(syscalls)
	return syscalls
}

func (sg *SeccompGenerator) initSyscallMap() {
	sg.syscallMap = map[string]int{
		"read": 0, "write": 1, "open": 2, "close": 3,
		"stat": 4, "fstat": 5, "lstat": 6, "poll": 7,
		"lseek": 8, "mmap": 9, "mprotect": 10, "munmap": 11,
		"brk": 12, "rt_sigaction": 13, "rt_sigprocmask": 14,
		"ioctl": 16, "access": 21, "pipe": 22, "select": 23,
		"sched_yield": 24, "mremap": 25, "msync": 26,
		"mincore": 27, "madvise": 28, "shmget": 29,
		"shmat": 30, "shmctl": 31, "dup": 32, "dup2": 33,
		"pause": 34, "nanosleep": 35, "getitimer": 36,
		"alarm": 37, "setitimer": 38, "getpid": 39,
		"sendfile": 40, "socket": 41, "connect": 42,
		"accept": 43, "sendto": 44, "recvfrom": 45,
		"sendmsg": 46, "recvmsg": 47, "shutdown": 48,
		"bind": 49, "listen": 50, "getsockname": 51,
		"getpeername": 52, "socketpair": 53, "setsockopt": 54,
		"getsockopt": 55, "clone": 56, "fork": 57,
		"vfork": 58, "execve": 59, "exit": 60,
		"wait4": 61, "kill": 62, "uname": 63,
		"semget": 64, "semop": 65, "semctl": 66,
		"shmdt": 67, "msgget": 68, "msgsnd": 69,
		"msgrcv": 70, "msgctl": 71, "fcntl": 72,
		"flock": 73, "fsync": 74, "fdatasync": 75,
		"truncate": 76, "ftruncate": 77, "getdents": 78,
		"getcwd": 79, "chdir": 80, "fchdir": 81,
		"rename": 82, "mkdir": 83, "rmdir": 84,
		"creat": 85, "link": 86, "unlink": 87,
		"symlink": 88, "readlink": 89, "chmod": 90,
		"fchmod": 91, "chown": 92, "fchown": 93,
		"lchown": 94, "umask": 95, "gettimeofday": 96,
		"getrlimit": 97, "getrusage": 98, "sysinfo": 99,
		"times": 100, "ptrace": 101, "getuid": 102,
		"syslog": 103, "getgid": 104, "setuid": 105,
		"setgid": 106, "geteuid": 107, "getegid": 108,
		"setpgid": 109, "getppid": 110, "getpgrp": 111,
		"setsid": 112, "setreuid": 113, "setregid": 114,
		"getgroups": 114, "setgroups": 116, "setresuid": 117,
		"getresuid": 118, "setresgid": 119, "getresgid": 120,
		"getpgid": 121, "setfsuid": 122, "setfsgid": 123,
		"getsid": 124, "capget": 125, "capset": 126,
		"rt_sigpending": 127, "rt_sigtimedwait": 128,
		"rt_sigqueueinfo": 130, "rt_sigsuspend": 131,
		"sigaltstack": 132, "utime": 133, "mknod": 134,
		"uselib": 135, "personality": 136, "ustat": 137,
		"statfs": 138, "fstatfs": 139, "sysfs": 140,
		"getpriority": 141, "setpriority": 142,
		"sched_setparam": 143, "sched_getparam": 144,
		"sched_setscheduler": 145, "sched_getscheduler": 146,
		"sched_get_priority_max": 147, "sched_get_priority_min": 148,
		"sched_rr_get_interval": 149, "mlock": 150,
		"munlock": 151, "mlockall": 152, "munlockall": 153,
		"vhangup": 154, "modify_ldt": 155, "pivot_root": 156,
		"_sysctl": 157, "prctl": 158, "arch_prctl": 159,
		"adjtimex": 160, "setrlimit": 161, "chroot": 162,
		"sync": 163, "acct": 164, "settimeofday": 165,
		"mount": 166, "umount2": 167, "swapon": 168,
		"swapoff": 169, "reboot": 170, "sethostname": 171,
		"setdomainname": 172, "iopl": 173, "ioperm": 174,
		"create_module": 175, "init_module": 176,
		"delete_module": 177, "get_kernel_syms": 178,
		"query_module": 179, "quotactl": 180,
		"nfsservctl": 181, "getpmsg": 182, "putpmsg": 183,
		"afs_syscall": 184, "tuxcall": 185, "security": 186,
		"gettid": 187, "readahead": 188, "setxattr": 189,
		"lsetxattr": 190, "fsetxattr": 191, "getxattr": 192,
		"lgetxattr": 193, "fgetxattr": 194, "listxattr": 195,
		"llistxattr": 196, "flistxattr": 197, "removexattr": 198,
		"lremovexattr": 199, "fremovexattr": 200,
		"tkill": 201, "time": 202, "futex": 203,
		"sched_setaffinity": 204, "sched_getaffinity": 205,
		"set_thread_area": 206, "io_setup": 207,
		"io_destroy": 208, "io_getevents": 209,
		"io_submit": 210, "io_cancel": 211, "get_thread_area": 212,
		"lookup_dcookie": 213, "epoll_create": 214,
		"epoll_ctl_old": 215, "epoll_wait_old": 216,
		"remap_file_pages": 217, "getdents64": 218,
		"set_tid_address": 219, "restart_syscall": 220,
		"semtimedop": 221, "fadvise64": 222,
		"timer_create": 223, "timer_settime": 224,
		"timer_gettime": 225, "timer_getoverrun": 226,
		"timer_delete": 227, "clock_settime": 228,
		"clock_gettime": 229, "clock_getres": 230,
		"clock_nanosleep": 231, "exit_group": 232,
		"epoll_wait": 233, "epoll_ctl": 234,
		"tgkill": 235, "utimes": 236, "vserver": 237,
		"mbind": 238, "set_mempolicy": 239,
		"get_mempolicy": 240, "mq_open": 241,
		"mq_unlink": 242, "mq_timedsend": 243,
		"mq_timedreceive": 244, "mq_notify": 245,
		"mq_getsetattr": 246, "kexec_load": 247,
		"waitid": 248, "add_key": 249, "request_key": 250,
		"keyctl": 251, "ioprio_set": 252, "ioprio_get": 253,
		"inotify_init": 254, "inotify_add_watch": 255,
		"inotify_rm_watch": 256, "migrate_pages": 257,
		"openat": 258, "mkdirat": 259, "mknodat": 260,
		"fchownat": 261, "futimesat": 262, "newfstatat": 263,
		"unlinkat": 264, "renameat": 265, "linkat": 266,
		"symlinkat": 267, "readlinkat": 268, "fchmodat": 269,
		"faccessat": 270, "pselect6": 271, "ppoll": 272,
		"unshare": 273, "set_robust_list": 274,
		"get_robust_list": 275, "splice": 276,
		"tee": 277, "sync_file_range": 278,
		"vmsplice": 279, "move_pages": 280,
		"utimensat": 281, "epoll_pwait": 282,
		"signalfd": 283, "timerfd_create": 284,
		"eventfd": 285, "fallocate": 286,
		"timerfd_settime": 287, "timerfd_gettime": 288,
		"accept4": 289, "signalfd4": 290,
		"eventfd2": 291, "epoll_create1": 292,
		"dup3": 293, "pipe2": 294, "inotify_init1": 295,
		"preadv": 296, "pwritev": 297, "rt_tgsigqueueinfo": 298,
		"perf_event_open": 299, "recvmmsg": 300,
		"fanotify_init": 301, "fanotify_mark": 302,
		"prlimit64": 303, "name_to_handle_at": 304,
		"open_by_handle_at": 305, "clock_adjtime": 306,
		"syncfs": 307, "sendmmsg": 308,
		"setns": 309, "getcpu": 310,
		"process_vm_readv": 311, "process_vm_writev": 312,
		"kcmp": 313, "finit_module": 314,
	}
}

func (sg *SeccompGenerator) ParseSyscallList(list string) []string {
	if list == "" {
		return nil
	}
	parts := strings.Split(list, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
