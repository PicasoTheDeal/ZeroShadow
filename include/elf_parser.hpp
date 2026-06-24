// include file 
#ifndef ELF_PARSER_HPP
#define ELF_PARSER_HPP

// standard tracking tools (string, vectors, and bit-width numbers (64-bit))

#include <string>
#include <vector>
#include <cstdint>

// elf praser from linux system 

#include <elf.h>

// core storage structure
// gives the exact memory boundaries to determine if a return address is safe or corrupted.

struct CodeSegment {
    uint64_t start_address;
    uint64_t end_address;
    std::string name = "";
};

// the parser engine
class ElfParser {
    public:
        // take path of the binary we want to view
        explicit ElfParser(const std::string& binary_path);

        // parse the binary to extract segments
        bool parse_binary();

        // boundariy return (noexcept for raw complier speed)
        const std::vector<CodeSegment>& get_code_segment() const noexcept;

    private:
        // internal storage for path
        std::string path;
        // the value is hold
        std::vector<CodeSegment> segments;
};

#endif // ELF_PARSER_HPP