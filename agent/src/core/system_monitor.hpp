#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <chrono>

namespace genesis {
namespace core {

/**
 * @brief Cross-platform system monitoring capabilities
 */
class SystemMonitor {
public:
    struct ProcessInfo {
        std::string name;
        pid_t pid;
        double cpu_percent;
        size_t memory_bytes;
        size_t syscall_count;
        std::vector<std::string> network_connections;
        std::vector<std::string> open_files;
        std::chrono::system_clock::time_point last_updated;
    };

    struct NetworkConnection {
        std::string local_addr;
        std::string remote_addr;
        std::string protocol;
        std::string state;
        pid_t pid;
    };

    SystemMonitor();
    ~SystemMonitor();

    /**
     * @brief Initialize system monitoring
     * @return true if successful, false otherwise
     */
    bool initialize();

    /**
     * @brief Get current process information
     * @return Vector of active processes
     */
    std::vector<ProcessInfo> get_process_info();

    /**
     * @brief Get network connections
     * @return Vector of active connections
     */
    std::vector<NetworkConnection> get_network_connections();

    /**
     * @brief Get system resource usage
     */
    struct SystemStats {
        double cpu_usage_percent;
        double memory_usage_percent;
        size_t total_memory_bytes;
        size_t available_memory_bytes;
        size_t disk_io_bytes;
        size_t network_io_bytes;
    };

    SystemStats get_system_stats();

    /**
     * @brief Check if running with sufficient privileges
     * @return true if can monitor system, false otherwise
     */
    bool has_sufficient_privileges() const;

private:
    bool collect_proc_info(std::vector<ProcessInfo>& processes);
    bool collect_network_info(std::vector<NetworkConnection>& connections);
    bool parse_proc_stat(const std::string& stat_file, ProcessInfo& info);
    bool parse_proc_status(const std::string& status_file, ProcessInfo& info);
    
    std::unordered_map<pid_t, uint64_t> last_cpu_times_;
    std::chrono::steady_clock::time_point last_update_;
    bool initialized_;
};

} // namespace core
} // namespace genesis