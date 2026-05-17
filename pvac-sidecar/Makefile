# PVAC sidecar — JSON-over-stdio daemon that wraps the vendored
# (GPL-2+) PVAC fork from octra-labs/webcli into a clean-licensed
# IPC boundary.
#
# Build inside Docker (see Dockerfile); the host doesn't need a
# C++ toolchain. Output: ./octra-pvac-sidecar (single binary).

CXX      ?= g++
PVAC_DIR := vendor/pvac

# PVAC's headers use SIMD intrinsics. Default to x86_64 SSE/AES when
# the host arch is x86, ARMv8+crypto on aarch64. Override on the make
# command line if you need a different target.
UNAME_M  := $(shell uname -m)
ifeq ($(UNAME_M),aarch64)
ARCH := -march=armv8-a+crypto
else ifeq ($(UNAME_M),arm64)
ARCH := -march=armv8-a+crypto
else
ARCH := -march=native
endif

CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter \
            -pthread $(ARCH) \
            -Ivendor -I$(PVAC_DIR) -I$(PVAC_DIR)/include

# Force the libstdc++ / libgcc symbols into the binary so the artifact
# is portable across containers with similar glibc but no runtime g++.
LDFLAGS  := -pthread

TARGET   := octra-pvac-sidecar

OBJS     := build/main.o build/pvac_c_api.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS)

build:
	@mkdir -p build

build/main.o: src/main.cpp | build
	$(CXX) $(CXXFLAGS) -c -o $@ $<

build/pvac_c_api.o: $(PVAC_DIR)/pvac_c_api.cpp | build
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rf build $(TARGET)

.PHONY: all clean
