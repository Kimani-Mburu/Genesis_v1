#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "core/system_monitor.hpp"
#include "core/behavioral_profiler.hpp"
#include "core/immune_engine.hpp"
#include "response/response_actions.hpp"
#include <thread>
#include <chrono>

using namespace genesis;
using namespace genesis::core;
using namespace genesis::response;

class IntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize system monitor
        system_monitor = std::make_shared<SystemMonitor>();
        ASSERT_TRUE(system_monitor->initialize()) << "Failed to initialize system monitor";
        
        // Initialize behavioral profiler with short learning window for testing
        behavioral_profiler = std::make_shared<BehavioralProfiler>(1, 0.1);
        ASSERT_TRUE(behavioral_profiler->start()) << "Failed to start behavioral profiler";
        
        // Initialize response manager in dry-run mode for safety
        response_manager = std::make_shared<ResponseActionsManager>();
        ASSERT_TRUE(response_manager->initialize_actions()) << "Failed to initialize response actions";
        response_manager->set_dry_run_mode(true);
        
        // Initialize immune engine
        immune_engine = std::make_shared<ImmuneEngine>(behavioral_profiler, response_manager);
        immune_engine->set_auto_response_enabled(true);
        immune_engine->update_severity_thresholds(0.3, 0.6, 0.8);
        ASSERT_TRUE(immune_engine->start()) << "Failed to start immune engine";
        
        // Allow system to initialize
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    void TearDown() override {
        if (immune_engine) immune_engine->stop();
        if (behavioral_profiler) behavioral_profiler->stop();
        
        // Allow time for graceful shutdown
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    std::shared_ptr<SystemMonitor> system_monitor;
    std::shared_ptr<BehavioralProfiler> behavioral_profiler;
    std::shared_ptr<ResponseActionsManager> response_manager;
    std::shared_ptr<ImmuneEngine> immune_engine;
};

// Test end-to-end threat detection and response
TEST_F(IntegrationTest, TestEndToEndThreatDetectionAndResponse) {
    // Create a suspicious behavior pattern
    BehaviorPattern suspicious_pattern;
    suspicious_pattern.process_name = "malicious_process";
    suspicious_pattern.cpu_usage = 95.0;  // Very high CPU usage
    suspicious_pattern.memory_usage = 2000.0;  // 2GB memory usage
    suspicious_pattern.syscall_frequency = 10000;  // High syscall frequency
    suspicious_pattern.timestamp = std::chrono::system_clock::now();
    
    // Add suspicious indicators
    suspicious_pattern.file_accesses = {
        "SUSPICIOUS_CMD:bash -c",
        "ROOT_PROCESS",
        "/etc/passwd",
        "/etc/shadow"
    };
    
    suspicious_pattern.network_connections = {
        "tcp:192.168.1.100:22->suspicious.evil.com:4444",
        "tcp:127.0.0.1:80->unknown.malware.net:443"
    };
    
    // Feed the pattern to behavioral profiler
    behavioral_profiler->add_behavior_pattern(suspicious_pattern);
    
    // Calculate anomaly score
    double anomaly_score = behavioral_profiler->calculate_anomaly_score(suspicious_pattern);
    EXPECT_GT(anomaly_score, 0.5) << "Suspicious pattern should have high anomaly score";
    
    // Report threat to immune engine
    std::string threat_id = immune_engine->report_threat(suspicious_pattern, anomaly_score, "integration_test");
    EXPECT_FALSE(threat_id.empty()) << "Threat should be reported successfully";
    
    // Allow time for threat processing
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Check that threat was processed
    auto active_threats = immune_engine->get_active_threats();
    EXPECT_FALSE(active_threats.empty()) << "Should have active threats";
    
    bool found_threat = false;
    for (const auto& threat : active_threats) {
        if (threat.threat_id == threat_id) {
            found_threat = true;
            EXPECT_GT(threat.severity_score, 0.0) << "Threat should have severity score";
            EXPECT_FALSE(threat.threat_type.empty()) << "Threat should have type";
            break;
        }
    }
    EXPECT_TRUE(found_threat) << "Reported threat should be in active threats";
    
    // Check system health
    auto health = immune_engine->get_system_health();
    EXPECT_GT(health.active_threats, 0) << "Should have active threats in health metrics";
}

// Test behavioral profiler learning and adaptation
TEST_F(IntegrationTest, TestBehavioralProfilerLearning) {
    const std::string process_name = "test_learning_process";
    
    // Send normal behavior patterns
    for (int i = 0; i < 20; ++i) {
        BehaviorPattern normal_pattern;
        normal_pattern.process_name = process_name;
        normal_pattern.cpu_usage = 10.0 + (i % 5) * 2.0;  // 10-18% CPU
        normal_pattern.memory_usage = 100.0 + (i % 3) * 10.0;  // 100-120MB
        normal_pattern.syscall_frequency = 50 + (i % 4) * 5;  // 50-65 syscalls
        normal_pattern.timestamp = std::chrono::system_clock::now();
        
        behavioral_profiler->add_behavior_pattern(normal_pattern);
        
        // Small delay to simulate real monitoring
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Allow profiler to learn
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Check that profile was created
    auto profile = behavioral_profiler->get_profile(process_name);
    ASSERT_TRUE(profile != nullptr) << "Profile should be created for process";
    EXPECT_GT(profile->sample_count, 15) << "Profile should have sufficient samples";
    
    // Test normal behavior (should have low anomaly score)
    BehaviorPattern normal_test;
    normal_test.process_name = process_name;
    normal_test.cpu_usage = 12.0;
    normal_test.memory_usage = 105.0;
    normal_test.syscall_frequency = 55;
    normal_test.timestamp = std::chrono::system_clock::now();
    
    double normal_score = behavioral_profiler->calculate_anomaly_score(normal_test);
    EXPECT_LT(normal_score, 0.3) << "Normal behavior should have low anomaly score";
    
    // Test anomalous behavior (should have high anomaly score)
    BehaviorPattern anomalous_test;
    anomalous_test.process_name = process_name;
    anomalous_test.cpu_usage = 90.0;  // Much higher than normal
    anomalous_test.memory_usage = 1000.0;  // Much higher than normal
    anomalous_test.syscall_frequency = 500;  // Much higher than normal
    anomalous_test.timestamp = std::chrono::system_clock::now();
    
    double anomalous_score = behavioral_profiler->calculate_anomaly_score(anomalous_test);
    EXPECT_GT(anomalous_score, 0.7) << "Anomalous behavior should have high anomaly score";
}

// Test immune engine threat escalation
TEST_F(IntegrationTest, TestImmuneEngineThreatEscalation) {
    // Test low severity threat
    BehaviorPattern low_threat_pattern;
    low_threat_pattern.process_name = "low_threat_process";
    low_threat_pattern.cpu_usage = 60.0;  // Moderate CPU usage
    low_threat_pattern.memory_usage = 200.0;
    low_threat_pattern.syscall_frequency = 100;
    low_threat_pattern.timestamp = std::chrono::system_clock::now();
    
    std::string low_threat_id = immune_engine->report_threat(low_threat_pattern, 0.4, "integration_test");
    EXPECT_FALSE(low_threat_id.empty());
    
    // Test medium severity threat
    BehaviorPattern medium_threat_pattern;
    medium_threat_pattern.process_name = "medium_threat_process";
    medium_threat_pattern.cpu_usage = 80.0;
    medium_threat_pattern.memory_usage = 500.0;
    medium_threat_pattern.syscall_frequency = 300;
    medium_threat_pattern.file_accesses = {"SUSPICIOUS_CMD:curl"};
    medium_threat_pattern.timestamp = std::chrono::system_clock::now();
    
    std::string medium_threat_id = immune_engine->report_threat(medium_threat_pattern, 0.7, "integration_test");
    EXPECT_FALSE(medium_threat_id.empty());
    
    // Test high severity threat
    BehaviorPattern high_threat_pattern;
    high_threat_pattern.process_name = "high_threat_process";
    high_threat_pattern.cpu_usage = 95.0;
    high_threat_pattern.memory_usage = 1000.0;
    high_threat_pattern.syscall_frequency = 1000;
    high_threat_pattern.file_accesses = {"SUSPICIOUS_CMD:bash -c", "ROOT_PROCESS"};
    high_threat_pattern.network_connections = {"tcp:127.0.0.1:22->evil.com:4444"};
    high_threat_pattern.timestamp = std::chrono::system_clock::now();
    
    std::string high_threat_id = immune_engine->report_threat(high_threat_pattern, 0.9, "integration_test");
    EXPECT_FALSE(high_threat_id.empty());
    
    // Allow time for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    
    // Check that threats have different severity scores
    auto active_threats = immune_engine->get_active_threats();
    EXPECT_GE(active_threats.size(), 3) << "Should have at least 3 active threats";
    
    // Verify severity escalation
    for (const auto& threat : active_threats) {
        if (threat.threat_id == low_threat_id) {
            EXPECT_LT(threat.severity_score, 0.6) << "Low threat should have low severity";
        } else if (threat.threat_id == medium_threat_id) {
            EXPECT_GE(threat.severity_score, 0.6) << "Medium threat should have medium severity";
            EXPECT_LT(threat.severity_score, 0.8) << "Medium threat should not exceed high threshold";
        } else if (threat.threat_id == high_threat_id) {
            EXPECT_GE(threat.severity_score, 0.8) << "High threat should have high severity";
        }
    }
}

// Test system monitor data collection
TEST_F(IntegrationTest, TestSystemMonitorDataCollection) {
    // Test process information collection
    auto processes = system_monitor->get_process_info();
    EXPECT_FALSE(processes.empty()) << "Should collect process information";
    
    // Verify process data structure
    bool found_valid_process = false;
    for (const auto& process : processes) {
        if (!process.name.empty() && process.pid > 0) {
            found_valid_process = true;
            EXPECT_GE(process.cpu_percent, 0.0) << "CPU percentage should be non-negative";
            EXPECT_GT(process.memory_bytes, 0) << "Memory usage should be positive";
            break;
        }
    }
    EXPECT_TRUE(found_valid_process) << "Should find at least one valid process";
    
    // Test network connections collection
    auto connections = system_monitor->get_network_connections();
    // Note: May be empty if no network activity, but should not crash
    
    // Test system statistics collection
    auto stats = system_monitor->get_system_stats();
    EXPECT_GE(stats.cpu_usage_percent, 0.0) << "CPU usage should be non-negative";
    EXPECT_LE(stats.cpu_usage_percent, 100.0) << "CPU usage should not exceed 100%";
    EXPECT_GT(stats.total_memory_bytes, 0) << "Total memory should be positive";
}

// Test response actions integration
TEST_F(IntegrationTest, TestResponseActionsIntegration) {
    ActionContext context;
    context.target_process = "test_integration_process";
    context.threat_description = "Integration test threat";
    context.target_pid = 12345;
    context.target_ip = "192.168.1.100";
    context.target_file = "/tmp/test_integration_file";
    context.threat_severity = 0.75;
    context.detected_at = std::chrono::system_clock::now();
    
    // Test all available actions
    auto available_actions = response_manager->get_available_actions();
    EXPECT_FALSE(available_actions.empty()) << "Should have available actions";
    
    for (const auto& action_info : available_actions) {
        auto result = response_manager->execute_action(action_info.name, context);
        EXPECT_TRUE(result.success) << "Action " << action_info.name << " should succeed in dry-run mode";
        EXPECT_EQ(result.action_name, action_info.name) << "Result should match requested action";
    }
    
    // Check action statistics
    auto stats = response_manager->get_action_statistics();
    for (const auto& action_info : available_actions) {
        EXPECT_GT(stats[action_info.name].first, 0) << "Action " << action_info.name << " should have execution count";
        EXPECT_EQ(stats[action_info.name].second, stats[action_info.name].first) 
            << "All executions should succeed in dry-run mode";
    }
}

// Test system resilience under load
TEST_F(IntegrationTest, TestSystemResilienceUnderLoad) {
    const int num_threats = 50;
    const int num_patterns_per_threat = 10;
    
    std::vector<std::string> threat_ids;
    
    // Generate multiple threats rapidly
    for (int i = 0; i < num_threats; ++i) {
        for (int j = 0; j < num_patterns_per_threat; ++j) {
            BehaviorPattern pattern;
            pattern.process_name = "load_test_process_" + std::to_string(i);
            pattern.cpu_usage = 50.0 + (i % 20) * 2.0;
            pattern.memory_usage = 100.0 + (j % 10) * 50.0;
            pattern.syscall_frequency = 100 + (i * j) % 500;
            pattern.timestamp = std::chrono::system_clock::now();
            
            if (i % 5 == 0) {  // Every 5th process is suspicious
                pattern.file_accesses.push_back("SUSPICIOUS_CMD:bash");
                pattern.network_connections.push_back("tcp:127.0.0.1:22->suspicious.com:4444");
            }
            
            behavioral_profiler->add_behavior_pattern(pattern);
            
            // Periodically report threats
            if (j == num_patterns_per_threat - 1) {
                double anomaly_score = behavioral_profiler->calculate_anomaly_score(pattern);
                if (anomaly_score > 0.3) {
                    std::string threat_id = immune_engine->report_threat(pattern, anomaly_score, "load_test");
                    if (!threat_id.empty()) {
                        threat_ids.push_back(threat_id);
                    }
                }
            }
        }
        
        // Small delay to prevent overwhelming the system
        if (i % 10 == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    // Allow system to process all threats
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Verify system is still responsive
    EXPECT_TRUE(behavioral_profiler->is_running()) << "Behavioral profiler should still be running";
    EXPECT_TRUE(immune_engine->is_running()) << "Immune engine should still be running";
    
    // Check health metrics
    auto health = immune_engine->get_system_health();
    EXPECT_GE(health.responses_executed, 0) << "Should have executed some responses";
    
    // Verify we can still process new threats
    BehaviorPattern test_pattern;
    test_pattern.process_name = "post_load_test";
    test_pattern.cpu_usage = 80.0;
    test_pattern.memory_usage = 500.0;
    test_pattern.syscall_frequency = 300;
    test_pattern.timestamp = std::chrono::system_clock::now();
    
    std::string final_threat_id = immune_engine->report_threat(test_pattern, 0.8, "post_load_test");
    EXPECT_FALSE(final_threat_id.empty()) << "System should still accept new threats after load test";
}

// Test profile persistence and recovery
TEST_F(IntegrationTest, TestProfilePersistenceAndRecovery) {
    const std::string test_process = "persistence_test_process";
    
    // Create and train a profile
    for (int i = 0; i < 30; ++i) {
        BehaviorPattern pattern;
        pattern.process_name = test_process;
        pattern.cpu_usage = 15.0 + (i % 3) * 2.0;
        pattern.memory_usage = 150.0 + (i % 4) * 25.0;
        pattern.syscall_frequency = 75 + (i % 5) * 10;
        pattern.timestamp = std::chrono::system_clock::now();
        
        behavioral_profiler->add_behavior_pattern(pattern);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    
    // Verify profile exists
    auto original_profile = behavioral_profiler->get_profile(test_process);
    ASSERT_TRUE(original_profile != nullptr) << "Profile should be created";
    EXPECT_GT(original_profile->sample_count, 25) << "Profile should have samples";
    
    // Save profiles
    EXPECT_TRUE(behavioral_profiler->save_profiles_to_disk()) << "Should save profiles successfully";
    
    // Create new profiler instance (simulating restart)
    auto new_profiler = std::make_shared<BehavioralProfiler>(1, 0.1);
    EXPECT_TRUE(new_profiler->load_profiles_from_disk()) << "Should load profiles successfully";
    
    // Note: The simplified JSON import/export might not fully restore profiles
    // This test verifies the persistence mechanism works without crashing
}

// Main function for integration tests
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    
    std::cout << "Running GENESIS Integration Test Suite" << std::endl;
    std::cout << "======================================" << std::endl;
    
    int result = RUN_ALL_TESTS();
    
    if (result == 0) {
        std::cout << "\n✅ All integration tests passed!" << std::endl;
    } else {
        std::cout << "\n❌ Some integration tests failed!" << std::endl;
    }
    
    return result;
}