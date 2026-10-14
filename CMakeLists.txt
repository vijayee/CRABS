cmake_minimum_required(VERSION 3.22)
project(crabs C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Default to Release when no build type is given (single-config generators).
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Hardening flags for CRABS's own targets ONLY. deps/openabe-c is a vendored
# fork full of warnings and is linked as a prebuilt archive, and the fetched
# googletest in test/ is third-party — never apply warnings-as-errors there.
# NOTE: -Werror is intentionally omitted for now — pre-existing warnings in
# committed sources (unused parameters in src/CRDT/crdt_merge.c, unused
# function in src/Attribute/attribute_machine.c) trip it. Re-add once those
# are cleaned up.
set(CRABS_WARNING_FLAGS -Wall -Wextra)
set(CRABS_HARDENING_FLAGS
    -fstack-protector-strong
    $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=3>)

# Optional sanitizer build: -DCRABS_SANITIZE=ON instruments CRABS's own
# targets with AddressSanitizer + UBSan (wired into testcrabs via test/).
option(CRABS_SANITIZE "Build CRABS targets with AddressSanitizer + UBSan" OFF)
set(CRABS_SANITIZE_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer)

file(GLOB_RECURSE C_SRC "src/*/*.c")
file(GLOB_RECURSE C_INC "src/*/*.h")

include(CTest)

# OpenABE (real CP-ABE) is a git submodule at deps/openabe-c.
# Run `git submodule update --init --recursive` after cloning.
set(OPENABE_ROOT ${CMAKE_SOURCE_DIR}/deps/openabe-c)
set(OPENABE_INCLUDE ${OPENABE_ROOT}/include)
set(OPENABE_LIB ${OPENABE_ROOT}/build)
set(RELIC_LIB ${OPENABE_ROOT}/deps/relic/build/lib)

add_library(crabs STATIC ${C_SRC})
target_include_directories(crabs PUBLIC src ${OPENABE_INCLUDE})
target_compile_options(crabs PRIVATE ${CRABS_WARNING_FLAGS} ${CRABS_HARDENING_FLAGS})
if(CRABS_SANITIZE)
  target_compile_options(crabs PRIVATE ${CRABS_SANITIZE_FLAGS})
endif()

# Audit X-9: use find_package(Threads) for portable threading. On Linux/macOS
# this finds pthreads; on Windows it finds the Windows threading primitives.
# The Threads::Threads target abstracts the platform difference.
find_package(Threads REQUIRED)

# Audit X-6/X-7: define _POSIX_C_SOURCE on non-Windows platforms so that
# strtok_r, strdup, localtime_r, gmtime_r, and clock_gettime are declared
# by the system headers. The platform.h abstraction maps these to their
# Windows equivalents (_strdup, strtok_s, localtime_s, gmtime_s,
# GetSystemTimeAsFileTime) when _WIN32 is defined.
if(NOT WIN32)
  target_compile_definitions(crabs PRIVATE _POSIX_C_SOURCE=200809L)
endif()

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    target_include_directories(crabs PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(crabs PRIVATE ${OPENSSL_LIBRARIES})
else()
    message(FATAL_ERROR "OpenSSL not found.")
endif()

# Audit X-9: portable library linking. Use find_library for GMP and
# CMake's static library path variables for OpenABE/RELIC instead of
# hardcoding .a (Unix) suffixes. On Windows, static libs use .lib.
set(OPENABE_LIB_FILE  ${OPENABE_LIB}/liboabe_c.a)
set(RELIC_LIB_FILE    ${RELIC_LIB}/librelic_s.a)
if(WIN32)
  set(OPENABE_LIB_FILE ${OPENABE_LIB}/oabe_c.lib)
  set(RELIC_LIB_FILE   ${RELIC_LIB}/relic_s.lib)
endif()

# Link OpenABE + RELIC + GMP (order matters for static linking: object files
# that reference oabe_* must come before liboabe_c, which references relic,
# which references gmp).
find_library(GMP_LIBRARY NAMES gmp)
if(NOT GMP_LIBRARY)
  message(FATAL_ERROR "GMP library not found. Install libgmp-dev (Linux) or gmp (Homebrew/macOS).")
endif()

target_link_libraries(crabs PRIVATE
    ${OPENABE_LIB_FILE}
    ${RELIC_LIB_FILE}
    ${GMP_LIBRARY}
    Threads::Threads
    ${OPENSSL_LIBRARIES})

# CLI executable
add_executable(crabs_node src/CLI/main.c src/CLI/cli.c)
target_link_libraries(crabs_node PRIVATE crabs Threads::Threads ${OPENSSL_LIBRARIES})
target_compile_options(crabs_node PRIVATE ${CRABS_WARNING_FLAGS} ${CRABS_HARDENING_FLAGS})
if(CRABS_SANITIZE)
  target_compile_options(crabs_node PRIVATE ${CRABS_SANITIZE_FLAGS})
  target_link_options(crabs_node PRIVATE ${CRABS_SANITIZE_FLAGS})
endif()

add_subdirectory(test)