cmake_minimum_required(VERSION 3.10)
project(genesis-agent)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(src)

# Core library
file(GLOB_RECURSE CORE_SOURCES "src/core/*.cpp" "src/core/*.hpp")
add_library(genesis-core STATIC ${CORE_SOURCES})

# Hooks library
file(GLOB_RECURSE HOOKS_SOURCES "src/hooks/*.cpp" "src/hooks/*.hpp")
add_library(genesis-hooks STATIC ${HOOKS_SOURCES})

# Response library
file(GLOB_RECURSE RESPONSE_SOURCES "src/response/*.cpp" "src/response/*.hpp")
add_library(genesis-response STATIC ${RESPONSE_SOURCES})

# Sync library
file(GLOB_RECURSE SYNC_SOURCES "src/sync/*.cpp" "src/sync/*.hpp")
add_library(genesis-sync STATIC ${SYNC_SOURCES})

# Main executable
add_executable(genesis-agent src/main.cpp)
target_link_libraries(genesis-agent genesis-core genesis-hooks genesis-response genesis-sync)

# Find required libraries
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(UUID REQUIRED uuid)

target_link_libraries(genesis-agent genesis-core genesis-hooks genesis-response genesis-sync Threads::Threads ${UUID_LIBRARIES})

# Enable testing
enable_testing()

# Add tests if they exist
if(EXISTS "${CMAKE_SOURCE_DIR}/tests")
    add_subdirectory(tests)
endif()

# Compiler warnings
target_compile_options(genesis-agent PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
)