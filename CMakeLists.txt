cmake_minimum_required(VERSION 3.22)
project(crabs C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

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

add_subdirectory(test)