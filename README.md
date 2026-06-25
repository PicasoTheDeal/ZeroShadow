# ZeroShadow

ZeroShadow is a low-level Linux user-space supervisor enforcing coarse-grained Control-Flow Integrity (CFI). It uses `ptrace` to single-step target threads, validating the instruction pointer (`RIP`) against known-executable memory boundaries dynamically extracted from `/proc/[pid]/maps`. Any execution jump to an unauthorized region (stack, heap, unmapped) results in immediate termination.

## Core Engine

- **Execution Tracking:** A unified `waitpid` loop single-steps all active threads (`PTRACE_SINGLESTEP`). Every instruction boundary is verified.
- **Dynamic Maps:** Parses `/proc/[pid]/maps` on attach. Intercepts `mmap`/`mprotect` syscalls via `PTRACE_O_TRACESYSGOOD` to track `PROT_EXEC` state changes live.
- **Thread Lineage:** Enforces `PTRACE_O_TRACECLONE | FORK | VFORK`. Newly spawned threads are automatically trapped and added to the supervision loop before user-space code executes.

## Hardened Syscall Interception (TOCTOU Mitigation)

Exploits often attempt to blind debuggers by blocking `SIGTRAP` or `SIGSEGV` via `rt_sigprocmask`. ZeroShadow intercepts this syscall and closes the Time-of-Check to Time-of-Use (TOCTOU) window:

1. Traps `rt_sigprocmask` on entry.
2. Uses atomic `process_vm_readv` to pull the tracee's pending signal mask directly from memory.
3. Strips the `SIGTRAP` and `SIGSEGV` bits locally.
4. Pushes the sanitized mask back to the tracee via `process_vm_writev`.
5. Resumes the syscall. The kernel consumes the clean mask. No race conditions, no blind spots.

## Integration Guide

### Method A: Passive Attachment

Hot-attach to an already running production process. Extracts current memory boundaries and begins single-stepping instantly.
```bash
# Attach to active PID
./ZeroShadow <target_pid> <binary_path>
```
### Method B: Active Launch

Supervised spawn. ZeroShadow forks, the child calls PTRACE_TRACEME and executes the target binary. Catches the process at the very first instruction before any user-space code runs.

```bash
# Launch and trace
./ZeroShadow /path/to/binary
```

## Build & Project Structure

Requires a C++17 compiler and a Linux kernel (4.11+) supporting process_vm_writev.

```bash
make
```
```bash
.
├── include
│   ├── elf_parser.hpp   # PT_LOAD execution extraction
│   └── tracer.hpp       # supervisor architecture and state management
├── Makefile
├── README.md
└── src
    ├── elf_parser.cpp
    ├── main.cpp         # entry point and argument routing
    └── tracer.cpp       # ptrace loop, syscall interception, and CFI enforcement
```

## The Journey / Build Process

* **Start of the build:** [Post #313](https://t.me/Tetstack/313)
* **Finalizing the Alpha:** [Post #437](https://t.me/Tetstack/437)
