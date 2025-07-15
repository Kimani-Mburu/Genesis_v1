#include "system_monitor.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

namespace genesis {
namespace core {

SystemMonitor::SystemMonitor() 
    : last_update_(std::chrono::steady_clock::now())
    , initialized_(false) {
}

SystemMonitor::~SystemMonitor() = default;

bool SystemMonitor::initialize() {
    // Check if we can access /proc
    if (!std::filesystem::exists("/proc")) {
        std::cerr << "[SystemMonitor] /proc filesystem not accessible" << std::endl;
        return false;
    }

    // Check if we can read process information
    if (!std::filesystem::exists("/proc/stat")) {
        std::cerr << "[SystemMonitor] Cannot access /proc/stat" << std::endl;
        return false;
    }

    // Verify we can read network information
    if (!std::filesystem::exists("/proc/net/tcp")) {
        std::cerr << "[SystemMonitor] Cannot access /proc/net/tcp" << std::endl;
        return false;
    }

    initialized_ = true;
    std::cout << "[SystemMonitor] Initialized with real /proc monitoring" << std::endl;
    return true;
}

std::vector<SystemMonitor::ProcessInfo> SystemMonitor::get_process_info() {
    std::vector<ProcessInfo> processes;
    
    if (!initialized_) {
        return processes;
    }

    try {
        collect_proc_info(processes);
    } catch (const std::exception& e) {
        std::cerr << "[SystemMonitor] Error collecting process info: " << e.what() << std::endl;
    }

    return processes;
}

std::vector<SystemMonitor::NetworkConnection> SystemMonitor::get_network_connections() {
    std::vector<NetworkConnection> connections;
    
    if (!initialized_) {
        return connections;
    }

    try {
        collect_network_info(connections);
    } catch (const std::exception& e) {
        std::cerr << "[SystemMonitor] Error collecting network info: " << e.what() << std::endl;
    }

    return connections;
}

SystemMonitor::SystemStats SystemMonitor::get_system_stats() {
    SystemStats stats = {};
    
    if (!initialized_) {
        return stats;
    }

    try {
        // Read /proc/meminfo for memory stats
        std::ifstream meminfo("/proc/meminfo");
        std::string line;
        
        while (std::getline(meminfo, line)) {
            std::istringstream iss(line);
            std::string key;
            size_t value;
            std::string unit;
            
            if (iss >> key >> value >> unit) {
                if (key == "MemTotal:") {
                    stats.total_memory_bytes = value * 1024; // Convert from KB
                } else if (key == "MemAvailable:") {
                    stats.available_memory_bytes = value * 1024;
                }
            }
        }
        
        if (stats.total_memory_bytes > 0) {
            stats.memory_usage_percent = 100.0 * 
                (stats.total_memory_bytes - stats.available_memory_bytes) / 
                stats.total_memory_bytes;
        }

        // Read /proc/stat for CPU stats (simplified)
        std::ifstream stat("/proc/stat");
        if (std::getline(stat, line)) {
            std::istringstream iss(line);
            std::string cpu_label;
            long user, nice, system, idle;
            if (iss >> cpu_label >> user >> nice >> system >> idle) {
                long total = user + nice + system + idle;
                if (total > 0) {
                    stats.cpu_usage_percent = 100.0 * (total - idle) / total;
                }
            }
        }

    } catch (const std::exception& e) {
        std::cerr << "[SystemMonitor] Error getting system stats: " << e.what() << std::endl;
    }

    return stats;
}

bool SystemMonitor::has_sufficient_privileges() const {
    // Check if we can read /proc entries that require privileges
    return (access("/proc/1/stat", R_OK) == 0);
}

bool SystemMonitor::collect_proc_info(std::vector<ProcessInfo>& processes) {
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        return false;
    }

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        // Check if directory name is a PID (all digits)
        std::string name = entry->d_name;
        if (name.find_first_not_of("0123456789") == std::string::npos && !name.empty()) {
            pid_t pid = std::stoi(name);
            
            ProcessInfo info = {};
            info.pid = pid;
            info.last_updated = std::chrono::system_clock::now();
            
            // Read process information
            std::string proc_path = "/proc/" + name;
            
            // Get process name from /proc/PID/comm
            std::ifstream comm_file(proc_path + "/comm");
            if (comm_file) {
                std::getline(comm_file, info.name);
            }
            
            // Parse /proc/PID/stat for CPU and memory info
            if (parse_proc_stat(proc_path + "/stat", info)) {
                // Parse /proc/PID/status for additional memory info
                parse_proc_status(proc_path + "/status", info);
                
                // Get open files
                std::string fd_path = proc_path + "/fd";
                if (std::filesystem::exists(fd_path)) {
                    try {
                        for (const auto& fd_entry : std::filesystem::directory_iterator(fd_path)) {
                            if (std::filesystem::is_symlink(fd_entry)) {
                                std::error_code ec;
                                auto target = std::filesystem::read_symlink(fd_entry, ec);
                                if (!ec && target.string().find("/dev/") != 0) {
                                    info.open_files.push_back(target.string());
                                }
                            }
                        }
                    } catch (const std::exception& e) {
                        // Permission denied or other error - continue
                    }
                }
                
                processes.push_back(info);
            }
        }
    }
    
    closedir(proc_dir);
    return true;
}

bool SystemMonitor::collect_network_info(std::vector<NetworkConnection>& connections) {
    // Parse /proc/net/tcp for TCP connections
    std::ifstream tcp_file("/proc/net/tcp");
    std::string line;
    
    // Skip header line
    if (!std::getline(tcp_file, line)) {
        return false;
    }
    
    while (std::getline(tcp_file, line)) {
        std::istringstream iss(line);
        std::string sl, local_addr, remote_addr, st, tx_queue, rx_queue;
        int uid, timeout, inode;
        
        if (iss >> sl >> local_addr >> remote_addr >> st >> tx_queue >> rx_queue >> timeout >> uid >> timeout >> inode) {
            NetworkConnection conn;
            conn.local_addr = local_addr;
            conn.remote_addr = remote_addr;
            conn.protocol = "tcp";
            conn.state = st;
            conn.pid = 0; // Would need to map inode to PID (complex)
            
            connections.push_back(conn);
        }
    }
    
    return true;
}

bool SystemMonitor::parse_proc_stat(const std::string& stat_file, ProcessInfo& info) {
    std::ifstream file(stat_file);
    if (!file) {
        return false;
    }
    
    std::string line;
    if (!std::getline(file, line)) {
        return false;
    }
    
    std::istringstream iss(line);
    std::string pid, comm, state;
    long ppid, pgrp, session, tty_nr, tpgid;
    unsigned long flags, minflt, cminflt, majflt, cmajflt;
    unsigned long utime, stime, cutime, cstime;
    long priority, nice, num_threads, itrealvalue;
    unsigned long long starttime, vsize;
    long rss;
    
    // Parse the stat file (fields based on proc(5) man page)
    if (iss >> pid >> comm >> state >> ppid >> pgrp >> session >> tty_nr >> tpgid >> flags
           >> minflt >> cminflt >> majflt >> cmajflt >> utime >> stime >> cutime >> cstime
           >> priority >> nice >> num_threads >> itrealvalue >> starttime >> vsize >> rss) {
        
        // Calculate CPU usage (simplified)
        unsigned long total_time = utime + stime;
        auto current_time = std::chrono::steady_clock::now();
        auto time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
            current_time - last_update_).count();
        
        if (time_diff > 0 && last_cpu_times_.count(info.pid)) {
            unsigned long last_total = last_cpu_times_[info.pid];
            unsigned long cpu_diff = total_time - last_total;
            info.cpu_percent = (cpu_diff * 100.0) / time_diff;
        } else {
            info.cpu_percent = 0.0;
        }
        
        last_cpu_times_[info.pid] = total_time;
        
        // Memory usage (RSS in pages, convert to bytes)
        long page_size = sysconf(_SC_PAGESIZE);
        info.memory_bytes = rss * page_size;
        
        // Syscall count (approximated by minor + major faults)
        info.syscall_count = minflt + majflt;
        
        return true;
    }
    
    return false;
}

bool SystemMonitor::parse_proc_status(const std::string& status_file, ProcessInfo& info) {
    std::ifstream file(status_file);
    if (!file) {
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.find("VmRSS:") == 0) {
            std::istringstream iss(line);
            std::string key, unit;
            size_t value;
            if (iss >> key >> value >> unit) {
                info.memory_bytes = value * 1024; // Convert from KB to bytes
            }
            break;
        }
    }
    
    return true;
}

} // namespace core
} // namespace genesis