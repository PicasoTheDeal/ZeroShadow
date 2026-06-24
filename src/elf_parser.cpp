//connecting the files
#include "../include/elf_parser.hpp"

// <fstream> (file stream) becuase we need it to look into binaries
#include <fstream>
#include <iostream>
#include <elf.h>

// grab file path and store inside private storage area
ElfParser::ElfParser(const std::string& binary_path) : path(binary_path) {
    //  empty (inentionally) as  the initializer list above already stores the path.
}

// Read-Only Data Window (to secure a read only window for the rest of the program)

const std::vector<CodeSegment>& ElfParser::get_code_segment() const noexcept {
    return segments;
}

// we use bool here instead of the .hpp file for security (Unchecked return values)
bool ElfParser::parse_binary() {
    // open the file target in raw binary input mode if file is missing return false
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    // Every linux binary (if Authentic) begins with 4 unique bytes 0x7F , E , L , F (Magic bytes)
    Elf64_Ehdr ehdr;
    file.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
    
    // this will check if the data is corrupted or not so we don't scan it
    // ELFMAG validation symbols are provided in the <elf.h> which is system native and already provided in the .hpp (line 13)
    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 || ehdr.e_ident[EI_MAG1] != ELFMAG1 || ehdr.e_ident[EI_MAG2] != ELFMAG2 || ehdr.e_ident[EI_MAG3] != ELFMAG3) {
        return false;
    }

    //now to code implementation
    //first move our file pointer to the section header table offset
    file.seekg(ehdr.e_shoff);

    //allocate space and read all section 
    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
    file.read(reinterpret_cast<char*>(shdrs.data()), ehdr.e_shnum * sizeof(Elf64_Shdr));
    
    // string table index
    Elf64_Shdr shstrndx = shdrs[ehdr.e_shstrndx];
    std::vector<char> shstrtab(shstrndx.sh_size);
    file.seekg(shstrndx.sh_offset);
    file.read(shstrtab.data(), shstrndx.sh_size);

    // the code inspects each section to find where the authorized instruction lives
    for (const auto& shdr : shdrs) {
        // checks for the flag that identifies an active instruction
        if (shdr.sh_flags & SHF_EXECINSTR) {
            CodeSegment code_space;
            code_space.start_address = shdr.sh_addr;
            code_space.end_address = shdr.sh_addr + shdr.sh_size;
            code_space.name = ".text"; //standard region label
            segments.push_back(code_space);
        }
    }

    return !segments.empty();
}