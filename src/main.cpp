// brain
// bring both headers here
#include "../include/elf_parser.hpp"
#include "../include/tracer.hpp"

#include <iostream>
#include <cstdlib>
#include <csignal>
#include <string>
#include <fstream>
#include <dirent.h>
#include <unistd.h>
#include <sys/ptrace.h>


volatile std::sig_atomic_t g_keep_running = 1;
void signal_handler(int signal) {
    if (signal == SIGINT) {
        g_keep_running = 0;
    }
}

int main(int argc, char* argv[]) {

    std::signal(SIGINT, signal_handler);

    // strict argument checking starting
    if (argc != 3) {
        std::cerr << "[-] usage: " << argv[0] << "<target_pid> <binary_path>\n";
        return EXIT_FAILURE;
    }

    // lock in target parameters
    const pid_t target_pid = std::atoi(argv[1]);
    const std::string binary_path = argv[2];

    std::cout << "[*] booting ZeroShadow supervisor...\n";

    // spin up the parser and map secure boundaries
    ElfParser parser(binary_path);
    if (!parser.parse_binary()) {
        std::cerr << "[-] Error: ELF parsing or missing from executable segments.\n";
        return EXIT_FAILURE;
    }

    std::cout << "[+] memory boundaries mapped.\n";

    // pass the PID and the authorized map to the hardware tracer
    Tracer Supervisor(target_pid, parser.get_code_segment());

    std::cout << "[*] hooking PID: " << target_pid << "...\n";
    if (!Supervisor.run_target_monitor()) {
        std::cerr << "Error: supervisor loop drooped or connection lost.\n";
        return EXIT_FAILURE;
    }

    std::cout << "[+] supervisor shutdown clean.\n";
    return EXIT_SUCCESS;

    std::cout << "\n[*] detaching from target process..." << std::endl;
    ptrace(PTRACE_DETACH, target_pid, nullptr, nullptr);

    return 0;
}