cmake_minimum_required(VERSION 3.16)
project(genesis_agent VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Find required packages
find_package(Threads REQUIRED)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

# Source files
set(CORE_SOURCES
    src/core/system_monitor.cpp
    src/core/behavioral_profiler.cpp
    src/core/immune_engine.cpp
)

set(RESPONSE_SOURCES
    src/response/placeholder.cpp
)

set(ALL_SOURCES
    ${CORE_SOURCES}
    ${RESPONSE_SOURCES}
    src/main.cpp
)

# Create executable
add_executable(genesis_agent ${ALL_SOURCES})

# Link libraries
target_link_libraries(genesis_agent 
    Threads::Threads
    stdc++fs  # For std::filesystem
)

# Install target
install(TARGETS genesis_agent DESTINATION bin)

# Create tests if BUILD_TESTS is ON
option(BUILD_TESTS "Build test suite" ON)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Create documentation target
find_program(DOXYGEN_EXECUTABLE doxygen)
if(DOXYGEN_EXECUTABLE)
    add_custom_target(docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating documentation with Doxygen"
        VERBATIM
    )
endif()

# Print build information
message(STATUS "Genesis Agent Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Install Prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  Build Tests: ${BUILD_TESTS}")