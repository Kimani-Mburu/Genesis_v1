#include "response_actions.hpp"
#include <iostream>
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>

namespace genesis {
namespace response {

ResponseActionsManager::ResponseActionsManager() 
    : privilege_dropped_(false)
    , dry_run_mode_(false) {
    initialize_actions();
}

ResponseActionsManager::~ResponseActionsManager() = default;

bool ResponseActionsManager::initialize_actions() {
    try {
        // Register standard response actions
        register_action("alert", 
            [this](const ActionContext& ctx) { return execute_alert_action(ctx); },
            "Send alert notification", false);
            
        register_action("isolate", 
            [this](const ActionContext& ctx) { return execute_isolate_action(ctx); },
            "Isolate process using cgroups", true);
            
        register_action("terminate", 
            [this](const ActionContext& ctx) { return execute_terminate_action(ctx); },
            "Terminate malicious process", true);
            
        register_action("block", 
            [this](const ActionContext& ctx) { return execute_block_action(ctx); },
            "Block network access using iptables", true);
            
        register_action("quarantine", 
            [this](const ActionContext& ctx) { return execute_quarantine_action(ctx); },
            "Quarantine suspicious files", true);
            
        register_action("suspend", 
            [this](const ActionContext& ctx) { return execute_suspend_action(ctx); },
            "Suspend process execution", false);

        std::cout << "[ResponseActions] Initialized " << actions_.size() << " response actions" << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "[ResponseActions] Failed to initialize: " << e.what() << std::endl;
        return false;
    }
}

void ResponseActionsManager::register_action(const std::string& name,
                                           ActionFunction action,
                                           const std::string& description,
                                           bool requires_privileges) {
    std::lock_guard<std::mutex> lock(actions_mutex_);
    
    ActionInfo info;
    info.name = name;
    info.action = action;
    info.description = description;
    info.requires_privileges = requires_privileges;
    info.execution_count = 0;
    info.success_count = 0;
    
    actions_[name] = info;
}

ActionResult ResponseActionsManager::execute_action(const std::string& action_name,
                                                   const ActionContext& context) {
    ActionResult result;
    result.action_name = action_name;
    result.executed_at = std::chrono::system_clock::now();
    result.success = false;
    
    std::lock_guard<std::mutex> lock(actions_mutex_);
    
    auto it = actions_.find(action_name);
    if (it == actions_.end()) {
        result.error_message = "Unknown action: " + action_name;
        return result;
    }
    
    ActionInfo& info = it->second;
    info.execution_count++;
    
    // Check privileges if required
    if (info.requires_privileges && privilege_dropped_) {
        result.error_message = "Action requires elevated privileges but running with dropped privileges";
        return result;
    }
    
    // Check if running in dry-run mode
    if (dry_run_mode_) {
        result.success = true;
        result.error_message = "DRY RUN: Would execute " + action_name;
        info.success_count++;
        log_action_execution(result, context);
        return result;
    }
    
    try {
        // Execute the action
        result.success = info.action(context);
        
        if (result.success) {
            info.success_count++;
            result.error_message = "Action completed successfully";
        } else {
            result.error_message = "Action execution failed";
        }
        
        log_action_execution(result, context);
        
    } catch (const std::exception& e) {
        result.error_message = "Exception during action execution: " + std::string(e.what());
        std::cerr << "[ResponseActions] Exception in " << action_name << ": " << e.what() << std::endl;
    }
    
    return result;
}

std::vector<ActionInfo> ResponseActionsManager::get_available_actions() const {
    std::lock_guard<std::mutex> lock(actions_mutex_);
    
    std::vector<ActionInfo> result;
    for (const auto& [name, info] : actions_) {
        result.push_back(info);
    }
    
    return result;
}

void ResponseActionsManager::set_dry_run_mode(bool enabled) {
    dry_run_mode_ = enabled;
    std::cout << "[ResponseActions] Dry run mode " << (enabled ? "enabled" : "disabled") << std::endl;
}

bool ResponseActionsManager::drop_privileges(const std::string& username, const std::string& groupname) {
    if (getuid() != 0) {
        std::cout << "[ResponseActions] Not running as root, cannot drop privileges" << std::endl;
        return true; // Not an error
    }
    
    try {
        // Get user and group information
        struct passwd* pwd = getpwnam(username.c_str());
        if (!pwd) {
            std::cerr << "[ResponseActions] User not found: " << username << std::endl;
            return false;
        }
        
        struct group* grp = getgrnam(groupname.c_str());
        if (!grp) {
            std::cerr << "[ResponseActions] Group not found: " << groupname << std::endl;
            return false;
        }
        
        // Change group first
        if (setgid(grp->gr_gid) != 0) {
            std::cerr << "[ResponseActions] Failed to set group: " << groupname << std::endl;
            return false;
        }
        
        // Change user
        if (setuid(pwd->pw_uid) != 0) {
            std::cerr << "[ResponseActions] Failed to set user: " << username << std::endl;
            return false;
        }
        
        privilege_dropped_ = true;
        std::cout << "[ResponseActions] Dropped privileges to " << username << ":" << groupname << std::endl;
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "[ResponseActions] Error dropping privileges: " << e.what() << std::endl;
        return false;
    }
}

bool ResponseActionsManager::execute_alert_action(const ActionContext& context) {
    try {
        // Validate input to prevent injection attacks
        if (!validate_context(context)) {
            std::cerr << "[ResponseActions] Invalid context for alert action" << std::endl;
            return false;
        }
        
        // Sanitize strings to prevent command injection
        std::string safe_threat = sanitize_string(context.threat_description);
        std::string safe_process = sanitize_string(context.target_process);
        
        // Use safe command execution instead of std::system
        std::vector<std::string> syslog_cmd = {
            "logger", "-p", "security.warning",
            "GENESIS ALERT: " + safe_threat + " (Process: " + safe_process + ")"
        };
        
        bool result = execute_command_safely(syslog_cmd);
        
        // Also write to console for immediate visibility
        std::cout << "🚨 SECURITY ALERT: " << safe_threat 
                 << " (Process: " << safe_process << ")" << std::endl;
        
        // Send notification to monitoring systems
        send_monitoring_notification(context);
        
        return result;
        
    } catch (const std::exception& e) {
        std::cerr << "[ResponseActions] Alert action failed: " << e.what() << std::endl;
        return false;
    }
}

bool ResponseActionsManager::execute_isolate_action(const ActionContext& context) {
    try {
        if (!validate_context(context) || !is_valid_pid(context.target_pid)) {
            std::cerr << "[ResponseActions] Invalid context for isolation" << std::endl;
            return false;
        }
        
        // Create isolation cgroup using safe file operations
        std::string cgroup_path = "/sys/fs/cgroup/genesis_isolation";
        
        try {
            std::filesystem::create_directories(cgroup_path);
        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "[ResponseActions] Failed to create isolation cgroup: " << e.what() << std::endl;
            return false;
        }
        
        // Set CPU limit to 1% using direct file I/O (safer than shell commands)
        std::ofstream cpu_file(cgroup_path + "/cpu.cfs_quota_us");
        if (cpu_file) {
            cpu_file << "1000" << std::endl;
            cpu_file.close();
        } else {
            std::cerr << "[ResponseActions] Failed to set CPU limit" << std::endl;
        }
        
        // Set memory limit to 10MB using direct file I/O
        std::ofstream mem_file(cgroup_path + "/memory.limit_in_bytes");
        if (mem_file) {
            mem_file << "10485760" << std::endl;
            mem_file.close();
        } else {
            std::cerr << "[ResponseActions] Failed to set memory limit" << std::endl;
        }
        
        // Move process to isolation cgroup using direct file I/O
        std::ofstream cgroup_file(cgroup_path + "/cgroup.procs");
        if (cgroup_file) {
            cgroup_file << context.target_pid << std::endl;
            cgroup_file.close();
            
            std::cout << "[ResponseActions] Process " << context.target_pid 
                     << " isolated successfully" << std::endl;
            return true;
        } else {
            std::cerr << "[ResponseActions] Failed to isolate process " << context.target_pid << std::endl;
            return false;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[ResponseActions] Isolation action failed: " << e.what() << std::endl;
        return false;
    }
}

bool ResponseActionsManager::execute_terminate_action(const ActionContext& context) {
    try {
        if (context.target_pid <= 0) {
            std::cerr << "[ResponseActions] Invalid PID for termination: " << context.target_pid << std::endl;
            return false;
        }
        
        std::cout << "[ResponseActions] Terminating process " << context.target_pid 
                 << " (" << context.target_process << ")" << std::endl;
        
        // First try SIGTERM for graceful shutdown
        if (kill(context.target_pid, SIGTERM) == 0) {
            // Wait a moment for graceful shutdown
            sleep(2);
            
            // Check if process still exists
            if (kill(context.target_pid, 0) == 0) {
                // Process still running, use SIGKILL
                std::cout << "[ResponseActions] Process didn't respond to SIGTERM, using SIGKILL" << std::endl;
                if (kill(context.target_pid, SIGKILL) == 0) {
                    return true;
                }
            } else {
                // Process terminated gracefully
                return true;
            }
        }
        
        std::cerr << "[ResponseActions] Failed to terminate process " << context.target_pid << std::endl;
        return false;
        
    } catch (const std::exception& e) {
        std::cerr << "[ResponseActions] Termination action failed: " << e.what() << std::endl;
        return false;
    }
}

bool ResponseActionsManager::execute_block_action(const ActionContext& context) {
    try {
        if (!validate_context(context) || !is_valid_ip_address(context.target_ip)) {
            std::cerr << "[ResponseActions] Invalid IP address for blocking" << std::endl;
            return false;
        }
        
        std::string safe_ip = sanitize_string(context.target_ip);
        
        // Use safe command execution for iptables
        std::vector<std::string> block_input_cmd = {
            "iptables", "-A", "INPUT", "-s", safe_ip, "-j", "DROP"
        };
        
        std::vector<std::string> block_output_cmd = {
            "iptables", "-A", "OUTPUT", "-d", safe_ip, "-j", "DROP"
        };
        
        bool input_success = execute_command_safely(block_input_cmd);
        bool output_success = execute_command_safely(block_output_cmd);
        
        if (!input_success) {
            std::cerr << "[ResponseActions] Failed to block input from " << safe_ip << std::endl;
        }
        
        if (!output_success) {
            std::cerr << "[ResponseActions] Failed to block output to " << safe_ip << std::endl;
        }
        
        bool success = input_success && output_success;
        
        if (success) {
            std::cout << "[ResponseActions] Blocked network access for " << safe_ip << std::endl;
            
            // Also block the specific process if PID is available
            if (is_valid_pid(context.target_pid)) {
                block_process_network(context.target_pid);
            }
        }
        
        return success;
        
    } catch (const std::exception& e) {
        std::cerr << "[ResponseActions] Block action failed: " << e.what() << std::endl;
        return false;
    }
}

bool ResponseActionsManager::execute_quarantine_action(const ActionContext& context) {
    try {
        if (context.target_file.empty()) {
            std::cerr << "[ResponseActions] No file specified for quarantine" << std::endl;
            return false;
        }
        
        // Create quarantine directory
        std::string quarantine_dir = "/var/lib/genesis/quarantine";
        std::string mkdir_cmd = "mkdir -p " + quarantine_dir;
        
        if (std::system(mkdir_cmd.c_str()) != 0) {
            std::cerr << "[ResponseActions] Failed to create quarantine directory" << std::endl;
            return false;
        }
        
        // Generate unique quarantine filename
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        
        std::string quarantine_file = quarantine_dir + "/quarantined_" + 
                                    std::to_string(timestamp) + "_" + 
                                    std::filesystem::path(context.target_file).filename().string();
        
        // Move file to quarantine (safer than copy+delete)
        std::string move_cmd = "mv \"" + context.target_file + "\" \"" + quarantine_file + "\"";
        
        if (std::system(move_cmd.c_str()) == 0) {
            // Create metadata file
            std::string metadata_file = quarantine_file + ".metadata";
            std::ofstream metadata(metadata_file);
            metadata << "Original path: " << context.target_file << std::endl;
            metadata << "Quarantined at: " << timestamp << std::endl;
            metadata << "Threat: " << context.threat_description << std::endl;
            metadata << "Process: " << context.target_process << std::endl;
            metadata.close();
            
            // Remove execute permissions
            std::string chmod_cmd = "chmod 000 \"" + quarantine_file + "\"";
            std::system(chmod_cmd.c_str());
            
            std::cout << "[ResponseActions] File quarantined: " << context.target_file 
                     << " -> " << quarantine_file << std::endl;
            return true;
        } else {
            std::cerr << "[ResponseActions] Failed to quarantine file: " << context.target_file << std::endl;
            return false;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[ResponseActions] Quarantine action failed: " << e.what() << std::endl;
        return false;
    }
}

bool ResponseActionsManager::execute_suspend_action(const ActionContext& context) {
    try {
        if (context.target_pid <= 0) {
            std::cerr << "[ResponseActions] Invalid PID for suspension: " << context.target_pid << std::endl;
            return false;
        }
        
        // Suspend process using SIGSTOP
        if (kill(context.target_pid, SIGSTOP) == 0) {
            std::cout << "[ResponseActions] Process " << context.target_pid 
                     << " suspended successfully" << std::endl;
            
            // Store suspended process info for potential resume
            suspended_processes_[context.target_pid] = {
                context.target_process,
                std::chrono::system_clock::now(),
                context.threat_description
            };
            
            return true;
        } else {
            std::cerr << "[ResponseActions] Failed to suspend process " << context.target_pid << std::endl;
            return false;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[ResponseActions] Suspend action failed: " << e.what() << std::endl;
        return false;
    }
}

bool ResponseActionsManager::resume_process(pid_t pid) {
    try {
        auto it = suspended_processes_.find(pid);
        if (it == suspended_processes_.end()) {
            std::cerr << "[ResponseActions] Process " << pid << " not in suspended list" << std::endl;
            return false;
        }
        
        // Resume process using SIGCONT
        if (kill(pid, SIGCONT) == 0) {
            std::cout << "[ResponseActions] Process " << pid << " resumed successfully" << std::endl;
            suspended_processes_.erase(it);
            return true;
        } else {
            std::cerr << "[ResponseActions] Failed to resume process " << pid << std::endl;
            return false;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[ResponseActions] Resume action failed: " << e.what() << std::endl;
        return false;
    }
}

bool ResponseActionsManager::block_process_network(pid_t pid) {
    try {
        // Use network namespaces to isolate process network access
        std::string netns_name = "genesis_isolation_" + std::to_string(pid);
        
        // Create isolated network namespace
        std::string create_ns_cmd = "ip netns add " + netns_name;
        if (std::system(create_ns_cmd.c_str()) != 0) {
            std::cerr << "[ResponseActions] Failed to create network namespace" << std::endl;
            return false;
        }
        
        // Move process to isolated namespace
        std::string move_cmd = "ip netns attach " + netns_name + " " + std::to_string(pid);
        if (std::system(move_cmd.c_str()) == 0) {
            std::cout << "[ResponseActions] Process " << pid << " network isolated" << std::endl;
            return true;
        } else {
            // Cleanup namespace if move failed
            std::string cleanup_cmd = "ip netns delete " + netns_name;
            std::system(cleanup_cmd.c_str());
            return false;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[ResponseActions] Network blocking failed: " << e.what() << std::endl;
        return false;
    }
}

void ResponseActionsManager::send_monitoring_notification(const ActionContext& context) {
    try {
        // Send to external monitoring systems (SIEM, etc.)
        // This could be extended to support various notification channels
        
        std::cout << "[ResponseActions] Notification sent for threat: " 
                 << context.threat_description << std::endl;
                 
    } catch (const std::exception& e) {
        std::cerr << "[ResponseActions] Failed to send notification: " << e.what() << std::endl;
    }
}

void ResponseActionsManager::log_action_execution(const ActionResult& result, 
                                                const ActionContext& context) {
    try {
        // Sanitize all logged data
        std::string safe_action = sanitize_string(result.action_name);
        std::string safe_process = sanitize_string(context.target_process);
        std::string safe_threat = sanitize_string(context.threat_description);
        
        // Log to system log using safe command execution
        std::ostringstream log_message;
        log_message << "GENESIS Action: " << safe_action 
                   << " | Success: " << (result.success ? "YES" : "NO")
                   << " | Target: " << safe_process
                   << " | PID: " << context.target_pid
                   << " | Threat: " << safe_threat;
        
        std::vector<std::string> syslog_cmd = {
            "logger", "-p", "security.info", log_message.str()
        };
        execute_command_safely(syslog_cmd);
        
        // Also log to console
        std::cout << "[ResponseActions] " << log_message.str() << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "[ResponseActions] Failed to log action: " << e.what() << std::endl;
    }
}

// Security helper methods implementation
bool ResponseActionsManager::validate_context(const ActionContext& context) const {
    // Check string lengths to prevent buffer overflows
    if (context.threat_description.length() > MAX_STRING_LENGTH ||
        context.target_process.length() > MAX_STRING_LENGTH ||
        context.target_ip.length() > MAX_STRING_LENGTH ||
        context.target_file.length() > MAX_STRING_LENGTH) {
        return false;
    }
    
    // Check for null bytes that could indicate injection attempts
    auto has_null_byte = [](const std::string& str) {
        return str.find('\0') != std::string::npos;
    };
    
    if (has_null_byte(context.threat_description) ||
        has_null_byte(context.target_process) ||
        has_null_byte(context.target_ip) ||
        has_null_byte(context.target_file)) {
        return false;
    }
    
    return true;
}

std::string ResponseActionsManager::sanitize_string(const std::string& input) const {
    std::string result;
    result.reserve(input.length());
    
    for (char c : input) {
        // Remove dangerous shell characters
        if (c == ';' || c == '|' || c == '&' || c == '$' || c == '`' ||
            c == '"' || c == '\'' || c == '\\' || c == '\n' || c == '\r' ||
            c == '\0' || c == '<' || c == '>') {
            result += '_'; // Replace with underscore
        } else if (std::isprint(c) || std::isspace(c)) {
            result += c;
        }
        // Skip non-printable characters
    }
    
    // Truncate if too long
    if (result.length() > MAX_STRING_LENGTH) {
        result.resize(MAX_STRING_LENGTH);
    }
    
    return result;
}

bool ResponseActionsManager::execute_command_safely(const std::vector<std::string>& command) const {
    if (command.empty()) {
        return false;
    }
    
    try {
        // Use execvp approach for safer command execution
        pid_t pid = fork();
        
        if (pid == 0) {
            // Child process
            std::vector<char*> args;
            for (const auto& arg : command) {
                args.push_back(const_cast<char*>(arg.c_str()));
            }
            args.push_back(nullptr);
            
            execvp(args[0], args.data());
            _exit(127); // exec failed
        } else if (pid > 0) {
            // Parent process - wait for child
            int status;
            waitpid(pid, &status, 0);
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        } else {
            // Fork failed
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "[ResponseActions] Command execution failed: " << e.what() << std::endl;
        return false;
    }
}

bool ResponseActionsManager::is_valid_process_name(const std::string& name) const {
    if (name.empty() || name.length() > 255) {
        return false;
    }
    
    // Process names should not contain dangerous characters
    for (char c : name) {
        if (!std::isalnum(c) && c != '_' && c != '-' && c != '.' && c != '/') {
            return false;
        }
    }
    
    return true;
}

bool ResponseActionsManager::is_valid_file_path(const std::string& path) const {
    if (path.empty() || path.length() > 4096) {
        return false;
    }
    
    // Basic path validation - should start with / for absolute paths
    if (path[0] != '/') {
        return false;
    }
    
    // Check for dangerous path components
    if (path.find("..") != std::string::npos ||
        path.find("//") != std::string::npos) {
        return false;
    }
    
    return true;
}

bool ResponseActionsManager::is_valid_ip_address(const std::string& ip) const {
    if (ip.empty() || ip.length() > 45) { // Max IPv6 length
        return false;
    }
    
    // Simple IPv4 validation
    if (ip.find(':') == std::string::npos) {
        // IPv4 format
        std::istringstream iss(ip);
        std::string octet;
        int count = 0;
        
        while (std::getline(iss, octet, '.')) {
            if (++count > 4) return false;
            
            try {
                int val = std::stoi(octet);
                if (val < 0 || val > 255) return false;
            } catch (...) {
                return false;
            }
        }
        
        return count == 4;
    }
    
    // For IPv6, accept it if it contains valid hex characters and colons
    for (char c : ip) {
        if (!std::isxdigit(c) && c != ':') {
            return false;
        }
    }
    
    return true;
}

bool ResponseActionsManager::is_valid_pid(pid_t pid) const {
    return pid > 0 && static_cast<size_t>(pid) <= MAX_PID_VALUE;
}

std::unordered_map<std::string, std::pair<size_t, size_t>> 
ResponseActionsManager::get_action_statistics() const {
    std::lock_guard<std::mutex> lock(actions_mutex_);
    
    std::unordered_map<std::string, std::pair<size_t, size_t>> stats;
    for (const auto& [name, info] : actions_) {
        stats[name] = {info.execution_count, info.success_count};
    }
    
    return stats;
}

} // namespace response
} // namespace genesis