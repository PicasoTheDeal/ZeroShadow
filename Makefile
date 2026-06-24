# compilers
CXX      := g++
CC       := gcc
CXXFLAGS := -std=c++17 -Wall -Wextra -Iinclude
CFLAGS   := -Wall -Wextra

# targets
SUPERVISOR := ZeroShadow
STUB       := runtime/shadow_stub
VULN_APP   := tests/vulnerable_app

# components tracking (C++)
SRCS       := src/elf_parser.cpp src/tracer.cpp src/main.cpp
OBJS       := $(SRCS:.cpp=.o)

# compiles every components in sequence
all: $(SUPERVISOR) $(STUB) $(VULN_APP)

# link the C++ security Core
$(SUPERVISOR): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(SUPERVISOR)

# compiles individual module
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# compiles the raw x86_64 assembly stub target
$(STUB): runtime/shadow_stub.s
	$(CC) -nostdlib runtime/shadow_stub.s -o $(STUB)

# compiles the vulnerable application target (with stack protectors disabled)
$(VULN_APP): tests/vulnerable_app.c
	$(CC) $(CFLAGS) -fno-stack-protector tests/vulnerable_app.c -o $(VULN_APP)

# clean all artifacts
clean:
	rm -f src/*.o $(SUPERVISOR) $(STUB) $(VULN_APP)