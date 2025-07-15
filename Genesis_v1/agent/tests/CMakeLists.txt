# Test CMakeLists.txt
cmake_minimum_required(VERSION 3.16)

# Find Google Test
find_package(GTest QUIET)

if(NOT GTest_FOUND)
    # Download and build Google Test
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

# Include test directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src)

# Test source files
set(TEST_SOURCES
    test_system_monitor.cpp
    test_behavioral_profiler.cpp
    test_response_actions.cpp
    test_immune_engine.cpp
    test_integration.cpp
    test_security.cpp
)

# Core sources (without main.cpp)
set(CORE_TEST_SOURCES
    ../src/core/system_monitor.cpp
    ../src/core/behavioral_profiler.cpp
    ../src/core/immune_engine.cpp
    ../src/response/placeholder.cpp
)

# Create test executable
add_executable(genesis_tests 
    ${TEST_SOURCES} 
    ${CORE_TEST_SOURCES}
)

# Link test libraries
target_link_libraries(genesis_tests
    gtest
    gtest_main
    gmock
    gmock_main
    Threads::Threads
    stdc++fs
)

# Add tests to CTest
include(GoogleTest)
gtest_discover_tests(genesis_tests)

# Individual test targets for easier debugging
foreach(test_file ${TEST_SOURCES})
    get_filename_component(test_name ${test_file} NAME_WE)
    add_executable(${test_name}
        ${test_file}
        ${CORE_TEST_SOURCES}
    )
    target_link_libraries(${test_name}
        gtest
        gtest_main
        gmock
        gmock_main
        Threads::Threads
        stdc++fs
    )
endforeach()

# Custom test targets
add_custom_target(test_security
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/test_security
    DEPENDS test_security
    COMMENT "Running security tests"
)

add_custom_target(test_integration  
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/test_integration
    DEPENDS test_integration
    COMMENT "Running integration tests"
)

message(STATUS "Test suite configured with Google Test")