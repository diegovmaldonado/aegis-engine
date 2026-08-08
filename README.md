# AEGIS Engine

A Linux sandbox in C++ that actually isolates untrusted code — no Docker, no container runtime, just kernel primitives.

I had a problem to solve so I solved it.

---

## The problem with most sandboxes

Every tutorial teaches `chroot`. The problem: `chroot` is not a sandbox. A process with the right capabilities can escape it in under a second via `/proc/1/root`. Most "sandboxes" built on top of `chroot` have this hole.

AEGIS doesn't use chroot. It uses `pivot_root` inside a fresh tmpfs, combined with Linux namespaces and seccomp syscall filtering — the same primitives `runc` (Docker's core) uses internally.

---

## What it does

```
untrusted code (JSON stdin)
        │
        ▼
┌─────────────────────────────────────────────┐
│  drop privileges (fail-closed)              │
│  clone() with 5 namespaces:                 │
│    CLONE_NEWUSER  → uid 0 inside = unpriv   │
│    CLONE_NEWPID   → child sees PID 1        │
│    CLONE_NEWNS    → private mount tree      │
│    CLONE_NEWNET   → no network (optional)   │
│    CLONE_NEWUTS   → hostname isolated       │
│  pivot_root into tmpfs                      │
│  seccomp: kill on mount/ptrace/unshare/etc  │
│  cgroups v2: memory.max + cpu.max           │
│    fallback: RLIMIT_AS + RLIMIT_CPU         │
│  code passed via pipe (not env var)         │
└─────────────────────────────────────────────┘
        │
        ▼
result (JSON stdout)
```

---

## Isolation layers

| Layer | Mechanism | What it stops |
|---|---|---|
| Filesystem | `pivot_root` + tmpfs | Host file access, `/etc/passwd`, device nodes |
| Privilege | `CLONE_NEWUSER` + uid map | Root inside = unprivileged outside |
| Process | `CLONE_NEWPID` | Seeing or signaling host processes |
| Syscalls | seccomp (libseccomp) | `mount()`, `ptrace()`, `unshare()`, etc. |
| Memory | cgroups `memory.max` + `RLIMIT_AS` | Memory bombs, host OOM |
| CPU | cgroups `cpu.max` + `RLIMIT_CPU` | Infinite loops |
| Network | `CLONE_NEWNET` (optional) | Reverse shells, data exfiltration |

**On the double memory limit:** cgroups v2 is the primary enforcer. But on many VMs and cloud hosts, the memory cgroup controller isn't delegated to the user slice — cgroups silently does nothing. I found this the hard way during testing. `RLIMIT_AS` kicks in automatically as a fallback. The sandbox never runs without at least one limit active.

---

## Usage

Send JSON on stdin, get JSON back on stdout.

**Run Python code:**
```json
{
  "operation": "execute_python",
  "target": { "content": "print(2 + 2)" },
  "limits": {
    "max_memory_mb": 64,
    "max_cpu_seconds": 5,
    "max_wall_seconds": 10,
    "network": false
  }
}
```

**Response:**
```json
{
  "status": "success",
  "stdout": "4\n",
  "stderr": "",
  "exit_code": 0,
  "wall_time_ms": 83
}
```

**Analyze a file (forensics):**
```json
{
  "operation": "analyze_file_static",
  "target": { "path": "/path/to/suspicious_file" }
}
```
Returns file type (magic bytes), MD5/SHA256, entropy, extracted IPs and URLs.

Status values: `success` · `timeout` · `memory_limit` · `security_violation` · `error`

---

## Build

```bash
# Ubuntu/Debian
sudo apt install cmake libseccomp-dev libssl-dev

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Create the dedicated user (required)
sudo useradd --system --no-create-home --shell /usr/sbin/nologin aegis-sandbox
```

---

## Test

```bash
# Quick test
echo '{"operation":"execute_python","target":{"content":"print(42)"},"limits":{"max_memory_mb":64,"max_cpu_seconds":5,"max_wall_seconds":10,"network":false}}' \
  | ./build/aegis-engine

# Escape attempt battery
python3 tests/test_escape_battery.py ./build/aegis-engine
```

The test battery tries: `mount()` via ctypes, reading host `/etc/passwd` after pivot_root, memory bomb (allocate until OOM), CPU infinite loop, socket creation with network disabled, and a few other common escape patterns.

---

## Why these design choices

**`clone()` instead of `fork()`**  
`fork()` can't create namespaces atomically. `clone()` with all five namespace flags in one call means the child is fully isolated from the moment it exists. All execution state lives in a `ChildArgs` struct passed by pointer — no globals, no race conditions when handling concurrent requests.

**`pivot_root` instead of `chroot`**  
`chroot` only changes how paths are resolved. The old mount tree is still there and accessible via `/proc/1/root` to anything privileged. `pivot_root` swaps the entire mount namespace root and makes the old tree unreachable from inside.

**Pipe instead of environment variable for code input**  
Env vars are readable from `/proc/<pid>/environ` by anything that can open that file. A pipe closes that leak and also removes the size limit on code input.

---

## Windows

AEGIS delegates to the Linux binary running inside WSL2 — same isolation guarantees, no separate implementation needed. See `src/sandbox_windows_wsl.cpp`.

A native Windows version using Job Objects is included (`src/sandbox_windows.cpp`) but Job Objects don't give filesystem or network isolation comparable to Linux namespaces. Use WSL2 for anything security-sensitive.

---

## Security

- Don't run as root. The `aegis-sandbox` system user is required. If the binary starts as root and that user doesn't exist, it exits immediately — fail-closed.
- No external security audit has been done. The escape battery is a regression test, not a security certification.
- An AppArmor profile is in `deploy/apparmor/` if you want an extra layer.

---

## About

Built by Diego Maldonado. Self-taught systems engineer.  
I work as a driver at night and build things like this in my spare time.  
Looking for work — if this is useful to you, reach out.

GitHub: [diegovmaldonado](https://github.com/diegovmaldonado)  
LinkedIn: [Diego Maldonado](https://www.linkedin.com/in/diego-maldonado-aaaa29427)
