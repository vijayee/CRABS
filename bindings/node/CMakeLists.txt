cmake_minimum_required(VERSION 3.22)
project(crabs_node CXX C)

# cmake-js provides CMAKE_JS_INC (Node.js headers) and sets up the addon build.
# Run `npx cmake-js compile` from this directory to build.

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

# ============================================================
# CRABS source — compile the library directly into the addon
# ============================================================
# We compile the CRABS C sources directly rather than linking a pre-built
# static library, so the addon is self-contained and doesn't require a
# separate build step for libcrabs.a.

set(CRABS_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
file(GLOB_RECURSE CRABS_C_SRC "${CRABS_ROOT}/src/*/*.c")

# ============================================================
# OpenABE / RELIC / GMP (same as the main CMakeLists.txt)
# ============================================================
set(OPENABE_ROOT ${CRABS_ROOT}/deps/openabe-c)
set(OPENABE_INCLUDE ${OPENABE_ROOT}/include)
set(OPENABE_LIB ${OPENABE_ROOT}/build)
set(RELIC_LIB ${OPENABE_ROOT}/deps/relic/build/lib)

set(OPENABE_LIB_FILE  ${OPENABE_LIB}/liboabe_c.a)
set(RELIC_LIB_FILE    ${RELIC_LIB}/librelic_s.a)
if(WIN32)
  set(OPENABE_LIB_FILE ${OPENABE_LIB}/oabe_c.lib)
  set(RELIC_LIB_FILE   ${RELIC_LIB}/relic_s.lib)
endif()

find_library(GMP_LIBRARY NAMES gmp)
if(NOT GMP_LIBRARY)
  message(FATAL_ERROR "GMP library not found.")
endif()

# ============================================================
# OpenSSL
# ============================================================
find_package(OpenSSL REQUIRED)

# ============================================================
# Threading
# ============================================================
find_package(Threads REQUIRED)

# ============================================================
# N-API addon
# ============================================================
# node-addon-api is a header-only C++ wrapper for N-API. Add its include
# directory directly (it does not have a CMakeLists.txt).
set(NODE_ADDON_API_INC ${CMAKE_CURRENT_SOURCE_DIR}/node_modules/node-addon-api)

add_library(crabs_node SHARED
  ${CMAKE_CURRENT_SOURCE_DIR}/src/crabs_node.cc
  ${CRABS_C_SRC}
)

set_target_properties(crabs_node PROPERTIES
  PREFIX ""
  SUFFIX ".node"
)

target_include_directories(crabs_node PRIVATE
  ${CMAKE_JS_INC}
  ${NODE_ADDON_API_INC}
  ${CRABS_ROOT}/src
  ${OPENABE_INCLUDE}
  ${OPENSSL_INCLUDE_DIR}
)

target_compile_definitions(crabs_node PRIVATE
  NAPI_VERSION=8
  _POSIX_C_SOURCE=200809L
)

if(NOT WIN32)
  target_compile_definitions(crabs_node PRIVATE _POSIX_C_SOURCE=200809L)
endif()

target_link_libraries(crabs_node PRIVATE
  ${OPENABE_LIB_FILE}
  ${RELIC_LIB_FILE}
  ${GMP_LIBRARY}
  Threads::Threads
  ${OPENSSL_LIBRARIES}
)