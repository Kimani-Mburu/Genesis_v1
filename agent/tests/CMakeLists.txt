# Tests CMakeLists.txt
cmake_minimum_required(VERSION 3.10)

# Test for Behavioral Profiler
add_executable(test_behavioral_profiler test_behavioral_profiler.cpp)
target_link_libraries(test_behavioral_profiler genesis-core)
target_include_directories(test_behavioral_profiler PRIVATE ../src)

# Add test to CTest
add_test(NAME BehavioralProfilerTest COMMAND test_behavioral_profiler)

# Test for Immune Engine (if we create one)
# add_executable(test_immune_engine test_immune_engine.cpp)
# target_link_libraries(test_immune_engine genesis-core)
# target_include_directories(test_immune_engine PRIVATE ../src)
# add_test(NAME ImmuneEngineTest COMMAND test_immune_engine)

# Set test properties
set_tests_properties(BehavioralProfilerTest PROPERTIES TIMEOUT 30)