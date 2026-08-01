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

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    target_include_directories(crabs PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(crabs PRIVATE ${OPENSSL_LIBRARIES})
else()
    message(FATAL_ERROR "OpenSSL not found.")
endif()

# Link OpenABE + RELIC + GMP (order matters for static linking: object files
# that reference oabe_* must come before liboabe_c, which references relic,
# which references gmp).
target_link_libraries(crabs PRIVATE
    ${OPENABE_LIB}/liboabe_c.a
    ${RELIC_LIB}/librelic_s.a
    gmp
    pthread
    ${OPENSSL_LIBRARIES})

# CLI executable
add_executable(crabs_node src/CLI/main.c src/CLI/cli.c)
target_link_libraries(crabs_node PRIVATE crabs ${OPENSSL_LIBRARIES})

add_subdirectory(test)
