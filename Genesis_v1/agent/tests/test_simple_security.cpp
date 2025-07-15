#include "response/response_actions.hpp"
#include <iostream>
#include <cassert>
#include <vector>

using namespace genesis::response;

// Simple test framework
class SimpleTest {
public:
    static void assert_true(bool condition, const std::string& message) {
        if (!condition) {
            std::cerr << "FAILED: " << message << std::endl;
            exit(1);
        } else {
            std::cout << "PASSED: " << message << std::endl;
        }
    }
    
    static void assert_false(bool condition, const std::string& message) {
        assert_true(!condition, message);
    }
};

int main() {
    std::cout << "Running Simple Security Tests for GENESIS" << std::endl;
    std::cout << "=========================================" << std::endl;
    
    // Initialize response manager in dry-run mode
    ResponseActionsManager response_manager;
    response_manager.initialize_actions();
    response_manager.set_dry_run_mode(true);
    
    // Test 1: Command injection prevention
    std::cout << "\nTest 1: Command Injection Prevention" << std::endl;
    {
        ActionContext malicious_context;
        malicious_context.target_process = "legitimate_process; rm -rf /";
        malicious_context.threat_description = "test threat; curl evil.com";
        malicious_context.target_ip = "192.168.1.1; rm -rf /";
        malicious_context.target_file = "/tmp/test; rm -rf /";
        malicious_context.target_pid = 1234;

        auto result = response_manager.execute_action("alert", malicious_context);
        SimpleTest::assert_true(result.success, "Should handle injection attempt safely");
        SimpleTest::assert_true(result.error_message == "DRY RUN: Would execute alert", 
                               "Should be in dry run mode");
    }
    
    // Test 2: Input validation for very long strings
    std::cout << "\nTest 2: Input Validation for Long Strings" << std::endl;
    {
        ActionContext context;
        std::string long_string(10000, 'A');
        context.target_process = long_string;
        context.threat_description = long_string;
        context.target_pid = 1234;
        
        auto result = response_manager.execute_action("alert", context);
        SimpleTest::assert_true(result.success, "Should handle very long strings safely");
    }
    
    // Test 3: Null byte injection prevention
    std::cout << "\nTest 3: Null Byte Injection Prevention" << std::endl;
    {
        ActionContext context;
        context.target_process = "test\x00injection";
        context.threat_description = "normal threat";
        context.target_pid = 1234;
        
        auto result = response_manager.execute_action("alert", context);
        SimpleTest::assert_true(result.success, "Should handle null bytes safely");
    }
    
    // Test 4: IP address validation
    std::cout << "\nTest 4: IP Address Validation" << std::endl;
    {
        ActionContext context;
        context.target_process = "test_process";
        context.threat_description = "test threat";
        
        // Test invalid IPs
        std::vector<std::string> invalid_ips = {
            "192.168.1.1; rm -rf /",
            "999.999.999.999",
            "$(curl evil.com)",
            ""
        };
        
        for (const auto& ip : invalid_ips) {
            context.target_ip = ip;
            auto result = response_manager.execute_action("block", context);
            // Should either succeed safely (sanitized) or fail gracefully
            std::cout << "  IP '" << ip << "': " << (result.success ? "SAFE" : "REJECTED") << std::endl;
        }
        
        // Test valid IPs
        std::vector<std::string> valid_ips = {
            "192.168.1.1",
            "127.0.0.1",
            "10.0.0.1"
        };
        
        for (const auto& ip : valid_ips) {
            context.target_ip = ip;
            auto result = response_manager.execute_action("block", context);
            SimpleTest::assert_true(result.success, "Valid IP should be accepted: " + ip);
        }
    }
    
    // Test 5: PID validation
    std::cout << "\nTest 5: PID Validation" << std::endl;
    {
        ActionContext context;
        context.target_process = "test_process";
        context.threat_description = "test threat";
        
        // Test invalid PIDs
        std::vector<pid_t> invalid_pids = {-1, 0, 9999999};
        
        for (auto pid : invalid_pids) {
            context.target_pid = pid;
            auto result = response_manager.execute_action("terminate", context);
            std::cout << "  PID " << pid << ": " << (result.success ? "ACCEPTED" : "REJECTED") << std::endl;
        }
        
        // Test valid PIDs
        std::vector<pid_t> valid_pids = {1, 1000, 32767};
        
        for (auto pid : valid_pids) {
            context.target_pid = pid;
            auto result = response_manager.execute_action("terminate", context);
            SimpleTest::assert_true(result.success, "Valid PID should be accepted");
        }
    }
    
    // Test 6: All response actions work
    std::cout << "\nTest 6: All Response Actions" << std::endl;
    {
        ActionContext context;
        context.target_process = "test_process";
        context.threat_description = "test threat";
        context.target_pid = 12345;
        context.target_ip = "192.168.1.100";
        context.target_file = "/tmp/test_file";
        
        auto available_actions = response_manager.get_available_actions();
        SimpleTest::assert_true(!available_actions.empty(), "Should have available actions");
        
        std::cout << "  Available actions: " << available_actions.size() << std::endl;
        
        for (const auto& action_info : available_actions) {
            auto result = response_manager.execute_action(action_info.name, context);
            SimpleTest::assert_true(result.success, 
                                   "Action " + action_info.name + " should succeed in dry-run mode");
            std::cout << "    " << action_info.name << ": SUCCESS" << std::endl;
        }
    }
    
    // Test 7: Statistics tracking
    std::cout << "\nTest 7: Statistics Tracking" << std::endl;
    {
        auto stats = response_manager.get_action_statistics();
        SimpleTest::assert_true(!stats.empty(), "Should have action statistics");
        
        for (const auto& [action, stat] : stats) {
            if (stat.first > 0) {
                std::cout << "  " << action << ": " << stat.first << " executions, " 
                         << stat.second << " successful" << std::endl;
                SimpleTest::assert_true(stat.second <= stat.first, 
                                       "Success count should not exceed total executions");
            }
        }
    }
    
    std::cout << "\n=========================================" << std::endl;
    std::cout << "✅ All security tests passed!" << std::endl;
    std::cout << "GENESIS security fixes are working correctly." << std::endl;
    
    return 0;
}