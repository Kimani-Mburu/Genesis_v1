#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <chrono>
#include <mutex>
#include <atomic>
#include <filesystem>

namespace genesis {
namespace response {

/**
 * @brief Context information for executing response actions
 */
struct ActionContext {
    std::string threat_description;
    std::string target_process;
    pid_t target_pid = 0;
    std::string target_ip;
    std::string target_file;
    double threat_severity = 0.0; // 0.0-1.0 scale
    std::chrono::system_clock::time_point detected_at;
    std::string detection_source;
    std::unordered_map<std::string, std::string> additional_data;
};

/**
 * @brief Result of executing a response action
 */
struct ActionResult {
    std::string action_name;
    bool success = false;
    std::string error_message;
    std::chrono::system_clock::time_point executed_at;
    std::chrono::milliseconds execution_duration{0};
    std::unordered_map<std::string, std::string> result_data;
};

/**
 * @brief Information about a suspended process
 */
struct SuspendedProcessInfo {
    std::string process_name;
    std::chrono::system_clock::time_point suspended_at;
    std::string reason;
};

/**
 * @brief Function signature for response actions
 */
using ActionFunction = std::function<bool(const ActionContext&)>;

/**
 * @brief Information about a registered action
 */
struct ActionInfo {
    std::string name;
    ActionFunction action;
    std::string description;
    bool requires_privileges;
    size_t execution_count = 0;
    size_t success_count = 0;
    std::chrono::system_clock::time_point last_executed;
};

/**
 * @brief Manages and executes security response actions with proper privilege handling
 * 
 * This class provides a secure framework for executing various response actions
 * in response to detected threats. It includes proper input validation,
 * privilege management, and comprehensive logging.
 */
class ResponseActionsManager {
public:
    ResponseActionsManager();
    ~ResponseActionsManager();

    /**
     * @brief Initialize the response actions system
     * @return true if initialization successful
     */
    bool initialize_actions();

    /**
     * @brief Register a new response action
     * @param name Action name (must be unique)
     * @param action Function to execute
     * @param description Human-readable description
     * @param requires_privileges Whether action needs elevated privileges
     */
    void register_action(const std::string& name,
                        ActionFunction action,
                        const std::string& description,
                        bool requires_privileges);

    /**
     * @brief Execute a response action with proper validation
     * @param action_name Name of action to execute
     * @param context Action context and parameters
     * @return Result of action execution
     */
    ActionResult execute_action(const std::string& action_name,
                               const ActionContext& context);

    /**
     * @brief Get list of available actions
     * @return Vector of action information
     */
    std::vector<ActionInfo> get_available_actions() const;

    /**
     * @brief Enable or disable dry-run mode
     * @param enabled If true, actions will be simulated only
     */
    void set_dry_run_mode(bool enabled);

    /**
     * @brief Drop privileges to specified user/group
     * @param username Target username
     * @param groupname Target group name
     * @return true if successful
     */
    bool drop_privileges(const std::string& username, const std::string& groupname);

    /**
     * @brief Resume a suspended process
     * @param pid Process ID to resume
     * @return true if successful
     */
    bool resume_process(pid_t pid);

    /**
     * @brief Get statistics about action executions
     * @return Map of action names to execution statistics
     */
    std::unordered_map<std::string, std::pair<size_t, size_t>> get_action_statistics() const;

private:
    // Core action implementations with security hardening
    bool execute_alert_action(const ActionContext& context);
    bool execute_isolate_action(const ActionContext& context);
    bool execute_terminate_action(const ActionContext& context);
    bool execute_block_action(const ActionContext& context);
    bool execute_quarantine_action(const ActionContext& context);
    bool execute_suspend_action(const ActionContext& context);

    // Helper methods for secure operations
    bool validate_context(const ActionContext& context) const;
    std::string sanitize_string(const std::string& input) const;
    bool execute_command_safely(const std::vector<std::string>& command) const;
    bool block_process_network(pid_t pid);
    void send_monitoring_notification(const ActionContext& context);
    void log_action_execution(const ActionResult& result, const ActionContext& context);

    // Input validation helpers
    bool is_valid_process_name(const std::string& name) const;
    bool is_valid_file_path(const std::string& path) const;
    bool is_valid_ip_address(const std::string& ip) const;
    bool is_valid_pid(pid_t pid) const;

private:
    mutable std::mutex actions_mutex_;
    std::unordered_map<std::string, ActionInfo> actions_;
    std::unordered_map<pid_t, SuspendedProcessInfo> suspended_processes_;
    
    std::atomic<bool> privilege_dropped_;
    std::atomic<bool> dry_run_mode_;
    
    // Security and validation
    static constexpr size_t MAX_STRING_LENGTH = 1024;
    static constexpr size_t MAX_PID_VALUE = 4194304; // Typical Linux max PID
};

} // namespace response
} // namespace genesis