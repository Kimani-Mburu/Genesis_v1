#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>
#include "../src/core/behavioral_profiler.hpp"

using namespace genesis::core;

void test_basic_functionality() {
    std::cout << "Testing basic behavioral profiler functionality..." << std::endl;
    
    BehavioralProfiler profiler(1, 0.2); // 1 hour learning window, 20% adaptation rate
    
    // Test initial state
    assert(!profiler.is_running());
    assert(profiler.get_monitored_process_count() == 0);
    assert(profiler.is_learning()); // Should be in learning mode initially
    
    // Test starting and stopping
    assert(profiler.start());
    assert(profiler.is_running());
    assert(!profiler.start()); // Should fail if already running
    
    profiler.stop();
    assert(!profiler.is_running());
    
    std::cout << "✅ Basic functionality test passed" << std::endl;
}

void test_behavior_pattern_processing() {
    std::cout << "Testing behavior pattern processing..." << std::endl;
    
    BehavioralProfiler profiler(1, 0.1);
    
    // Create test behavior pattern
    BehaviorPattern pattern;
    pattern.process_name = "test_process";
    pattern.cpu_usage = 5.0;
    pattern.memory_usage = 50.0;
    pattern.syscall_frequency = 100;
    pattern.network_connections = {"80:tcp", "443:tcp"};
    pattern.file_accesses = {"/tmp", "/var/log"};
    pattern.timestamp = std::chrono::system_clock::now();
    
    // Add pattern
    profiler.add_behavior_pattern(pattern);
    
    // Check if profile was created
    assert(profiler.get_monitored_process_count() == 1);
    
    auto profile = profiler.get_profile("test_process");
    assert(profile != nullptr);
    assert(profile->sample_count == 1);
    assert(profile->avg_cpu_usage == 5.0);
    assert(profile->avg_memory_usage == 50.0);
    
    // Add another pattern to test averaging
    pattern.cpu_usage = 15.0;
    pattern.memory_usage = 60.0;
    profiler.add_behavior_pattern(pattern);
    
    profile = profiler.get_profile("test_process");
    assert(profile != nullptr);
    assert(profile->sample_count == 2);
    // With 10% adaptation rate: new_avg = 0.1 * 15.0 + 0.9 * 5.0 = 6.0
    assert(std::abs(profile->avg_cpu_usage - 6.0) < 0.1);
    
    std::cout << "✅ Behavior pattern processing test passed" << std::endl;
}

void test_anomaly_detection() {
    std::cout << "Testing anomaly detection..." << std::endl;
    
    BehavioralProfiler profiler(1, 0.1);
    
    // Build baseline with normal patterns
    BehaviorPattern normal_pattern;
    normal_pattern.process_name = "stable_process";
    normal_pattern.cpu_usage = 10.0;
    normal_pattern.memory_usage = 100.0;
    normal_pattern.syscall_frequency = 200;
    normal_pattern.network_connections = {"80:tcp"};
    normal_pattern.file_accesses = {"/tmp"};
    normal_pattern.timestamp = std::chrono::system_clock::now();
    
    // Add multiple normal patterns to establish baseline
    for (int i = 0; i < 15; i++) {
        // Add small variations
        normal_pattern.cpu_usage = 10.0 + (i % 3 - 1) * 0.5;
        normal_pattern.memory_usage = 100.0 + (i % 5 - 2) * 2.0;
        profiler.add_behavior_pattern(normal_pattern);
    }
    
    // Test normal pattern (should have low anomaly score)
    double normal_score = profiler.calculate_anomaly_score(normal_pattern);
    std::cout << "Normal pattern anomaly score: " << normal_score << std::endl;
    
    // Create anomalous pattern
    BehaviorPattern anomaly_pattern = normal_pattern;
    anomaly_pattern.cpu_usage = 50.0; // Much higher than normal
    anomaly_pattern.memory_usage = 500.0; // Much higher than normal
    anomaly_pattern.network_connections = {"1337:tcp", "4444:tcp"}; // Unknown connections
    
    double anomaly_score = profiler.calculate_anomaly_score(anomaly_pattern);
    std::cout << "Anomalous pattern score: " << anomaly_score << std::endl;
    
    assert(anomaly_score > normal_score);
    assert(anomaly_score > 0.3); // Should be significantly anomalous
    
    std::cout << "✅ Anomaly detection test passed" << std::endl;
}

void test_profile_export_import() {
    std::cout << "Testing profile export/import..." << std::endl;
    
    BehavioralProfiler profiler(1, 0.1);
    
    // Add some test data
    BehaviorPattern pattern;
    pattern.process_name = "export_test";
    pattern.cpu_usage = 12.5;
    pattern.memory_usage = 75.0;
    pattern.syscall_frequency = 150;
    pattern.timestamp = std::chrono::system_clock::now();
    
    profiler.add_behavior_pattern(pattern);
    
    // Export profiles
    std::string exported = profiler.export_profiles();
    assert(!exported.empty());
    assert(exported.find("export_test") != std::string::npos);
    
    std::cout << "Exported profile data: " << exported.substr(0, 100) << "..." << std::endl;
    
    // Test import (currently just validates format)
    assert(profiler.import_profiles(exported));
    
    std::cout << "✅ Profile export/import test passed" << std::endl;
}

int main() {
    std::cout << "Running Behavioral Profiler Tests..." << std::endl;
    std::cout << "=====================================" << std::endl;
    
    try {
        test_basic_functionality();
        test_behavior_pattern_processing();
        test_anomaly_detection();
        test_profile_export_import();
        
        std::cout << "\n🎉 All tests passed! Behavioral Profiler is working correctly." << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Test failed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "❌ Test failed with unknown exception" << std::endl;
        return 1;
    }
}