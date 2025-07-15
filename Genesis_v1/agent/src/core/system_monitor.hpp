#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <chrono>

namespace genesis {
namespace core {

/**
 * @brief Cross-platform system monitoring capabilities with enhanced security and performance
 */
class SystemMonitor {
public:
    struct ProcessInfo {
        std::string name;
        std::string command_line;
        pid_t pid;
        uid_t uid = 0;
        uid_t effective_uid = 0;
        gid_t gid = 0;
        gid_t effective_gid = 0;
        double cpu_percent;
        size_t memory_bytes;
        size_t virtual_memory_bytes;
        size_t syscall_count;
        std::vector<std::string> network_connections;
        std::vector<std::string> open_files;
        bool has_network_activity = false;
        std::chrono::system_clock::time_point last_updated;
    };

    struct NetworkConnection {
        std::string local_addr;
        std::string remote_addr;
        std::string protocol;
        std::string state;
        pid_t pid = 0;
        uid_t uid = 0;
        unsigned long inode = 0;
    };

    struct FileSystemEvent {
        std::string path;
        std::string event_type; // create, modify, delete, access
        std::chrono::system_clock::time_point timestamp;
        size_t size;
        uid_t uid = 0;
        gid_t gid = 0;
    };

    /**
     * @brief Comprehensive system resource usage statistics
     */
    struct SystemStats {
        // CPU Statistics
        double cpu_usage_percent = 0.0;
        double cpu_user_percent = 0.0;
        double cpu_system_percent = 0.0;
        double cpu_iowait_percent = 0.0;
        
        // Memory Statistics
        double memory_usage_percent = 0.0;
        size_t total_memory_bytes = 0;
        size_t available_memory_bytes = 0;
        size_t buffer_memory_bytes = 0;
        size_t cache_memory_bytes = 0;
        size_t total_swap_bytes = 0;
        size_t free_swap_bytes = 0;
        
        // Disk Statistics
        double disk_usage_percent = 0.0;
        size_t total_disk_bytes = 0;
        size_t available_disk_bytes = 0;
        size_t disk_read_bytes = 0;
        size_t disk_write_bytes = 0;
        
        // Network Statistics
        size_t network_rx_bytes = 0;
        size_t network_tx_bytes = 0;
    };

    SystemMonitor();
    ~SystemMonitor();

    /**
     * @brief Initialize system monitoring with privilege checking
     * @return true if successful, false otherwise
     */
    bool initialize();

    /**
     * @brief Get current process information with security context
     * @return Vector of active processes sorted by resource usage
     */
    std::vector<ProcessInfo> get_process_info();

    /**
     * @brief Get network connections with process mapping
     * @return Vector of active connections
     */
    std::vector<NetworkConnection> get_network_connections();

    /**
     * @brief Get comprehensive system resource usage
     * @return System statistics
     */
    SystemStats get_system_stats();

    /**
     * @brief Get recent file system events for security monitoring
     * @return Vector of recent file events
     */
    std::vector<FileSystemEvent> get_recent_file_events();

    /**
     * @brief Check if running with sufficient privileges for complete monitoring
     * @return true if can monitor system comprehensively, false if limited
     */
    bool has_sufficient_privileges() const;

private:
    // Core data collection methods
    bool collect_proc_info(std::vector<ProcessInfo>& processes);
    bool collect_process_details(const std::string& proc_path, ProcessInfo& info, long time_delta);
    
    // Process information parsing
    bool parse_proc_stat(const std::string& stat_file, ProcessInfo& info, long time_delta);
    bool parse_proc_status(const std::string& status_file, ProcessInfo& info);
    bool parse_proc_cmdline(const std::string& cmdline_file, ProcessInfo& info);
    void collect_process_files(const std::string& fd_path, ProcessInfo& info);
    void collect_process_network(pid_t pid, ProcessInfo& info);
    
    // Network monitoring
    bool collect_tcp_connections(std::vector<NetworkConnection>& connections);
    bool collect_udp_connections(std::vector<NetworkConnection>& connections);
    bool collect_unix_connections(std::vector<NetworkConnection>& connections);
    bool parse_net_file(const std::string& filename, const std::string& protocol,
                       std::vector<NetworkConnection>& connections);
    std::string parse_address(const std::string& hex_addr);
    void map_connections_to_processes(std::vector<NetworkConnection>& connections);
    
    // System statistics collection
    void collect_memory_stats(SystemStats& stats);
    void collect_cpu_stats(SystemStats& stats);
    void collect_disk_stats(SystemStats& stats);
    void collect_network_stats(SystemStats& stats);
    void collect_file_events(const std::string& path, std::vector<FileSystemEvent>& events);
    
    // CPU baseline management
    void update_cpu_baseline();
    
    // State tracking
    std::unordered_map<pid_t, uint64_t> last_cpu_times_;
    std::chrono::steady_clock::time_point last_update_;
    bool initialized_;
    bool has_root_privileges_;
    long page_size_;
    
    // CPU baseline for calculating usage percentages
    struct {
        unsigned long total_time = 0;
        unsigned long active_time = 0;
    } cpu_baseline_;
    
    // Configuration constants
    static constexpr size_t MAX_MONITORED_PROCESSES = 200;
    static constexpr size_t MAX_FILES_PER_PROCESS = 50;
    static constexpr size_t MAX_NETWORK_CONNECTIONS = 1000;
};

} // namespace core
} // namespace genesis