# AEGIS Engine
Production-grade code sandbox in C++ for Linux — built in ~48 hours.
Executes untrusted Python code in a fully isolated environment using Linux kernel primitives: user namespaces, PID namespaces, mount namespaces, network namespaces, pivot_root, seccomp syscall filtering, and cgroups v2. JSON in, JSON out. Thread-safe.
Why this exists
Most sandboxing tutorials teach chroot. chroot alone is not a sandbox — a privileged process can escape it in seconds. AEGIS uses the same isolation primitives that container runtimes like runc use internally, built from scratch without Docker or any container runtime dependency.
What it actually does
Código
Isolation layers
Layer
Mechanism
What it prevents
Filesystem
pivot_root + tmpfs
Reading /etc/passwd, host files
Privilege
CLONE_NEWUSER + uid map
Root inside ≠ root on host
Process
CLONE_NEWPID
Seeing or signaling host processes
Syscalls
seccomp via libseccomp
mount(), ptrace(), unshare(), etc.
Memory
cgroups memory.max + RLIMIT_AS
Memory bombs, OOM host
CPU
cgroups cpu.max + RLIMIT_CPU
Infinite loops, CPU starvation
Network
CLONE_NEWNET (optional)
Exfiltration, reverse shells
Concurrency
No globals — ChildArgs struct per execution
Race conditions under load
Two-layer memory enforcement: cgroups v2 is the primary limit. In environments where the memory controller is not delegated (common in VMs and some cloud hosts), cgroups fails silently. RLIMIT_AS activates automatically as a backup — the sandbox never runs without at least one memory limit active.
Interface
Send a JSON request on stdin, receive a JSON response on stdout.
Execute Python:
Json
Response:
Json
Static forensic analysis:
Json
Returns: file type (magic bytes), MD5/SHA256 hashes, extracted IPs and URLs, entropy estimate.
Status values: success · timeout · memory_limit · security_violation · error
Build
Bash
Test
Bash
The test battery covers: mount() via ctypes, reading /etc/passwd after pivot_root, memory bomb, CPU infinite loop, socket creation with network disabled, and more.
Windows
On Windows, AEGIS delegates to the Linux binary running inside WSL2 (same isolation guarantees, no reimplementation). Requires WSL2 installed with the Linux binary compiled inside the distro. See src/sandbox_windows_wsl.cpp.
A native Windows implementation using Job Objects is also included (src/sandbox_windows.cpp) — Job Objects do not provide filesystem or network isolation equivalent to Linux namespaces, so the WSL2 path is preferred for security-sensitive deployments.
Security notes
Never run as root. The aegis-sandbox dedicated user is required. If the binary starts as root and that user doesn't exist, it exits immediately with an error — fail-closed, not fail-open.
External audit not yet performed. The escape battery is a regression guard, not a replacement for a security review. Do not expose this to the public internet without an audit.
AppArmor profile available in deploy/apparmor/ for an additional mandatory access control layer.
Design decisions
clone() + struct over fork() + globals
fork() inherits the parent's memory state and cannot create new namespaces atomically. clone() lets us set all five namespace flags in a single call. All per-execution state lives in ChildArgs (passed by pointer to the child), eliminating the global file descriptor race that made alarm()+SIGALRM unsafe under concurrent load.
pivot_root over chroot
chroot only changes the root for pathname resolution — the rest of the mount tree stays visible and a privileged process can escape via /proc/1/root. pivot_root replaces the entire mount namespace root and makes the old tree unreachable.
Code via pipe, not environment variable
Environment variables are readable from /proc/<pid>/environ by any process that can open that file. A dedicated pipe closes that leak and removes the length limit on code input.
Two memory limits
Testing on real VMs showed cgroups failing silently when the memory cgroup controller wasn't delegated to the user slice. RLIMIT_AS was added as a backup. The sandbox never runs with neither limit active.
Built by
Diego Maldonado — systems engineer, self-taught.
Built in approximately 48 hours of focused work.
Feedback and security reports welcome.