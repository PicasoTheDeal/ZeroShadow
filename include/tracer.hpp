/*
--what tracer needs to do 
1. attach it self onto running process unig PID
2. accept the valid memory boundaries we just extracted using ElfParser.
3. intercept the CPU instruction pointer at every step to ensure the app hasn't been hijacked by an exploit.
4. trace all threads and enforce signal masks via syscall interception
*/

#ifndef TRACER_HPP
#define TRACER_HPP

#include "elf_parser.hpp"
#include <sys/types.h>
#include <sys/user.h>
#include <vector>
#include <set>

class Tracer {
public:
    explicit Tracer(pid_t target_pid, std::vector<CodeSegment> allowed_regions);
    bool run_target_monitor();
    pid_t get_target_pid() const noexcept { return pid; }

private:
    pid_t pid;
    std::vector<CodeSegment> valid_maps;
    std::set<pid_t> thread_pids;        // all known thread ids

    bool verify_instruction_pointer(const struct user_regs_struct& regs) const;
    void add_thread(pid_t tid);
    bool handle_fatal_signal(int sig);
    void drain_all_threads();
    bool is_critical_syscall(unsigned long long syscall_nr) const;
    void intercept_sigprocmask(struct user_regs_struct& regs);
    void intercept_mmap_or_mprotect(struct user_regs_struct& regs);
    bool read_tracee_memory(unsigned long long remote_addr, void* buf, size_t len);
    bool write_tracee_memory(unsigned long long remote_addr, const void* buf, size_t len);
};

#endif // TRACER_HPP