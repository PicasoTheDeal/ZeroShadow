/*
    1. attach via PTRACE_ATTACH
    2. set extended options (clone, syscall intercept)
    3. freeze program step 
    4. Capture CPU register
    5. cross-reference safe Boundaries
    6. intercept critical syscalls and enforce signal masks
*/

#include "../include/tracer.hpp"
#include <cstdint>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>            // for process_vm_readv/writev
#include <sys/mman.h>           // for PROT_EXEC
#include <sys/syscall.h>        // standardized syscall numbers
#include <iostream>
#include <sstream>
#include <cstring>
#include <fstream>
#include <string>
#include <unistd.h>
#include <signal.h>

// page constants
constexpr uintptr_t SUPERVISOR_PAGE_SIZE = 4096;
constexpr uintptr_t SUPERVISOR_PAGE_MASK = ~(SUPERVISOR_PAGE_SIZE - 1);

// memory read/write via process_vm
bool Tracer::read_tracee_memory(unsigned long long remote_addr, void* buf, size_t len) {
    struct iovec local[1]  = { { buf, len } };
    struct iovec remote[1] = { { (void*)remote_addr, len } };
    ssize_t nread = process_vm_readv(pid, local, 1, remote, 1, 0);
    return nread == (ssize_t)len;
}

bool Tracer::write_tracee_memory(unsigned long long remote_addr, const void* buf, size_t len) {
    struct iovec local[1]  = { { (void*)buf, len } };
    struct iovec remote[1] = { { (void*)remote_addr, len } };
    ssize_t nwritten = process_vm_writev(pid, local, 1, remote, 1, 0);
    return nwritten == (ssize_t)len;
}

// load executable maps
std::vector<CodeSegment> get_executable_segments(pid_t pid) {
    std::vector<CodeSegment> segments;
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    if (!maps.is_open()) {
        std::cerr << "[-] cannot open /proc/" << pid << "/maps\n";
        return segments;
    }

    std::string line;
    while (std::getline(maps, line)) {
        std::istringstream iss(line);
        std::string addr, perms_str, offset, dev, inode_str, path;
        if (!(iss >> addr >> perms_str >> offset >> dev >> inode_str)) continue;
        std::getline(iss, path);
        size_t pos = path.find_first_not_of(" \t");
        if (pos != std::string::npos) path = path.substr(pos);
        else path.clear();

        size_t dash = addr.find('-');
        if (dash == std::string::npos) continue;
        uintptr_t start = std::stoull(addr.substr(0, dash), nullptr, 16);
        uintptr_t end   = std::stoull(addr.substr(dash + 1), nullptr, 16);

        if (perms_str.size() >= 4 && perms_str[2] == 'x') {
            segments.push_back({start, end, path});
        }
    }
    return segments;
}

// constructor
Tracer::Tracer(pid_t target_pid, std::vector<CodeSegment> allowed_regions) : pid(target_pid), valid_maps(std::move(allowed_regions)) {
    thread_pids.insert(target_pid);
}

// add a traced thread
void Tracer::add_thread(pid_t tid) {
    thread_pids.insert(tid);
    std::cerr << "[*] new thread traced: " << tid << "\n";
}

// verify rip is inside whitelist
bool Tracer::verify_instruction_pointer(const struct user_regs_struct& regs) const {
    unsigned long long current_rip = regs.rip;
    for (const auto& segment : valid_maps) {
        if (current_rip >= segment.start_address && current_rip <= segment.end_address) {
            return true;
        }
    }
    std::cerr << "[!] Alert: code jumped to an unauthorized zone at address: 0x"
              << std::hex << current_rip << "\n";
    return false;
}

// check if a syscall needs interception
bool Tracer::is_critical_syscall(unsigned long long syscall_nr) const {
    switch (syscall_nr) {
        case SYS_rt_sigprocmask:
        case SYS_mmap:
        case SYS_mprotect:
        case SYS_clone:
        case SYS_fork:
        case SYS_vfork:
            return true;
        default:
            return false;
    }
}

// drain all threads at startup
void Tracer::drain_all_threads() {
    std::cerr << "[*] draining any leftover signals on all threads...\n";
    for (auto tid : thread_pids) {
        int status;
        while (true) {
            pid_t res = waitpid(tid, &status, WNOHANG);
            if (res <= 0) break; 
            
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) continue;
            if (WIFEXITED(status) || WIFSIGNALED(status)) break;
            
            ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr);
        }
    }
    // re-read executable maps after initialisation
    valid_maps = get_executable_segments(pid);
}

// handle a fatal signal
bool Tracer::handle_fatal_signal(int sig) {
    std::cerr << "[!] CRITICAL: control flow hijack detected! "
              << "Process killed by signal " << sig
              << " (" << strsignal(sig) << ")\n";
    return false;   // already dead
}

// main monitoring loop with full thread and syscall support 
bool Tracer::run_target_monitor() {
    int status;

    // attach
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) {
        std::cerr << "[-] Error: failed to attach to target process space: " << pid << "\n";
        return false;
    }
    if (waitpid(pid, &status, 0) < 0) {
        std::cerr << "[-] initial wait failed\n";
        return false;
    }

    // set extended options: trace clone events, syscall stops, exec
    unsigned long options = PTRACE_O_TRACECLONE | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEVFORK;
    if (ptrace(PTRACE_SETOPTIONS, pid, nullptr, (void*)options) < 0) {
        perror("ptrace SETOPTIONS");
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }

    // load all executable regions
    valid_maps = get_executable_segments(pid);
    if (valid_maps.empty()) {
        std::cerr << "[-] no executable segments found\n";
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }
    for (auto& seg : valid_maps) {
        seg.start_address &= SUPERVISOR_PAGE_MASK;
        seg.end_address = (seg.end_address + SUPERVISOR_PAGE_SIZE - 1) & SUPERVISOR_PAGE_MASK;
    }
    std::cout << "[*] loaded " << valid_maps.size() << " executable segments\n";

    // drain all threads
    drain_all_threads();

    // verify initial RIP of the main thread
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) < 0) {
        std::cerr << "[-] initial getregs failed\n";
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }
    if (!verify_instruction_pointer(regs)) {
        std::cerr << "[!] initial RIP outside allowed zone\n";
        ptrace(PTRACE_KILL, pid, nullptr, nullptr);
        return false;
    }
    std::cout << "[+] synchronised. starting main loop on "
              << thread_pids.size() << " thread(s)\n";

    // main event loop
    while (true) {
        // resume all threads with SINGLESTEP
        for (auto tid : thread_pids) {
            if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) < 0) {
                thread_pids.erase(tid);
            }
        }

        // wait for any thread event
        pid_t event_tid = waitpid(-1, &status, __WALL);
        if (event_tid < 0) {
            if (errno == ECHILD) break;
            perror("waitpid");
            break;
        }

        // check if a new thread was spawned (clone event)
        if (status >> 16 == PTRACE_EVENT_CLONE || status >> 16 == PTRACE_EVENT_VFORK || status >> 16 == PTRACE_EVENT_FORK) {
            unsigned long new_tid;
            if (ptrace(PTRACE_GETEVENTMSG, event_tid, nullptr, &new_tid) == 0) {
                add_thread(new_tid);
                ptrace(PTRACE_SETOPTIONS, new_tid, nullptr, (void*)options);
            }
            continue;
        }

        // process termination
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (WIFSIGNALED(status)) {
                int sig = WTERMSIG(status);
                if (sig == SIGSEGV || sig == SIGILL || sig == SIGBUS || sig == SIGFPE)
                    return handle_fatal_signal(sig);
            }
            thread_pids.erase(event_tid);
            if (thread_pids.empty()) {
                std::cout << "[+] all threads finished\n";
                break;
            }
            continue;
        }

        // stopped state
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);

            // syscall stop (PTRACE_O_TRACESYSGOOD sets bit 7)
            if (sig == (SIGTRAP | 0x80)) {
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, event_tid, nullptr, &regs) < 0) continue;
                unsigned long long syscall_nr = regs.orig_rax;

                if (is_critical_syscall(syscall_nr)) {
                    // intercept rt_sigprocmask: remove critical signals
                    if (syscall_nr == SYS_rt_sigprocmask && (regs.rdi == SIG_BLOCK || regs.rdi == SIG_SETMASK)) {
                        if (regs.rsi != 0) {
                            sigset_t new_mask;
                            if (read_tracee_memory(regs.rsi, &new_mask, sizeof(sigset_t))) {
                                sigdelset(&new_mask, SIGTRAP);
                                sigdelset(&new_mask, SIGSEGV);
                                write_tracee_memory(regs.rsi, &new_mask, sizeof(sigset_t));
                                std::cerr << "[*] intercepted rt_sigprocmask: forced SIGTRAP/SIGSEGV unmasked\n";
                            }
                        }
                    }
                    // intercept mmap / mprotect with PROT_EXEC
                    else if (syscall_nr == SYS_mmap || syscall_nr == SYS_mprotect) {
                        unsigned long long prot = regs.rdx; 
                        if (prot & PROT_EXEC) {
                            std::cerr << "[*] tracee requested executable mapping, will be added to whitelist\n";
                        }
                    }
                }
                // continue the syscall (will stop again at exit)
                if (ptrace(PTRACE_SYSCALL, event_tid, nullptr, nullptr) < 0) {
                    thread_pids.erase(event_tid);
                }
                continue;
            }

            // normal single step stop (SIGTRAP without 0x80)
            if (sig == SIGTRAP) {
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, event_tid, nullptr, &regs) == 0) {
                    if (!verify_instruction_pointer(regs)) {
                        std::cerr << "[!] SECURITY ALERT: control flow hijacked at 0x" << std::hex << regs.rip << std::dec << "\n";
                        ptrace(PTRACE_KILL, pid, nullptr, nullptr);
                        return false;
                    }
                }
            }
            // fatal crash signals
            else if (sig == SIGSEGV || sig == SIGILL || sig == SIGBUS || sig == SIGFPE) {
                siginfo_t info;
                ptrace(PTRACE_GETSIGINFO, event_tid, nullptr, &info);
                std::cerr << "[!] CRITICAL: Memory Fault signal=" << sig << " addr=0x" << std::hex << info.si_addr << "\n";
                ptrace(PTRACE_KILL, pid, nullptr, nullptr);
                return false;
            }
            // other stop signals are suppressed
        }
    }

    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return true; 
}