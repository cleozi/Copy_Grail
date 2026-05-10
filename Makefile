# Makefile for copygrail - CVE-2026-31431 LPE Exploit
#
# A clean, portable build system for the single-file C++ exploit.
# Builds a fully static binary for maximum compatibility.
 
# Compiler settings
CXX := g++
 
# Base compiler flags (warnings + standard)
BASE_CXXFLAGS := -Wall -Wextra -std=c++17 -Wno-missing-field-initializers -Wno-unused-result
 
# Release optimizations
RELEASE_CXXFLAGS := -O2
 
# Debug flags (for development)
DEBUG_CXXFLAGS := -g -O0 -DDEBUG
 
# Linker flags (zlib for compression)
LDFLAGS := -lz
 
# Static linking for portability (no shared library dependencies)
STATIC_LDFLAGS := -static
 
# Target and source
TARGET := copygrail
SRC := copygrail.cpp
 
# Default target: static release build (matches README)
all: release
 
# Release build (optimized, static)
release: CXXFLAGS = $(BASE_CXXFLAGS) $(RELEASE_CXXFLAGS)
release: LDFLAGS += $(STATIC_LDFLAGS)
release: $(TARGET)
 
# Debug build (with symbols, no optimization)
debug: CXXFLAGS = $(BASE_CXXFLAGS) $(DEBUG_CXXFLAGS)
debug: $(TARGET)
 
# Build rule
$(TARGET): $(SRC)
	@echo "Building $(TARGET)..."
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "Build complete: $(TARGET) (static binary ~2.3 MB)"
 
# Clean up build artifacts
clean:
	rm -f $(TARGET)
	@echo "Cleaned up build files."
 
# Rebuild from scratch
rebuild: clean all
 
# Install target (optional, for system-wide use - requires root)
install: $(TARGET)
