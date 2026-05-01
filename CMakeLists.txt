cmake_minimum_required(VERSION 3.22)
project(crabs C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

file(GLOB_RECURSE C_SRC "src/*/*.c")
file(GLOB_RECURSE C_INC "src/*/*.h")

include(CTest)

add_library(crabs STATIC ${C_SRC})
target_include_directories(crabs PUBLIC src)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    target_include_directories(crabs PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(crabs PRIVATE ${OPENSSL_LIBRARIES})
else()
    message(FATAL_ERROR "OpenSSL not found.")
endif()

# CLI executable
add_executable(crabs_node src/CLI/main.c src/CLI/cli.c)
target_link_libraries(crabs_node PRIVATE crabs ${OPENSSL_LIBRARIES})

add_subdirectory(test)
