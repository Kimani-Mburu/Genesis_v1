#include "system_monitor.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <cstring>

namespace genesis {
namespace core {

SystemMonitor::SystemMonitor() 
    : last_update_(std::chrono::steady_clock::now())
    , initialized_(false)
    , has_root_privileges_(false)
    , page_size_(sysconf(_SC_PAGESIZE)) {
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

    // Check privilege level
    has_root_privileges_ = (getuid() == 0);
    if (!has_root_privileges_) {
        std::cout << "[SystemMonitor] Running without root privileges - some monitoring may be limited" << std::endl;
    }

    // Initialize baseline CPU stats
    update_cpu_baseline();

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
        
        // Sort by CPU usage for better monitoring focus
        std::sort(processes.begin(), processes.end(), 
                 [](const ProcessInfo& a, const ProcessInfo& b) {
                     return a.cpu_percent > b.cpu_percent;
                 });
        
        // Limit to top N processes to avoid overwhelming the system
        if (processes.size() > MAX_MONITORED_PROCESSES) {
            processes.resize(MAX_MONITORED_PROCESSES);
        }
        
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
        collect_tcp_connections(connections);
        collect_udp_connections(connections);
        collect_unix_connections(connections);
        
        // Map inodes to PIDs for better process correlation
        map_connections_to_processes(connections);
        
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
        collect_memory_stats(stats);
        collect_cpu_stats(stats);
        collect_disk_stats(stats);
        collect_network_stats(stats);
        
    } catch (const std::exception& e) {
        std::cerr << "[SystemMonitor] Error getting system stats: " << e.what() << std::endl;
    }

    return stats;
}

bool SystemMonitor::has_sufficient_privileges() const {
    return has_root_privileges_ || (access("/proc/1/stat", R_OK) == 0);
}

std::vector<SystemMonitor::FileSystemEvent> SystemMonitor::get_recent_file_events() {
    std::vector<FileSystemEvent> events;
    
    try {
        // Monitor specific sensitive directories
        std::vector<std::string> monitored_paths = {
            "/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
            "/home", "/var/log", "/tmp"
        };
        
        for (const auto& path : monitored_paths) {
            collect_file_events(path, events);
        }
        
        // Sort by timestamp
        std::sort(events.begin(), events.end(),
                 [](const FileSystemEvent& a, const FileSystemEvent& b) {
                     return a.timestamp > b.timestamp;
                 });
        
    } catch (const std::exception& e) {
        std::cerr << "[SystemMonitor] Error collecting file events: " << e.what() << std::endl;
    }
    
    return events;
}

bool SystemMonitor::collect_proc_info(std::vector<ProcessInfo>& processes) {
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        return false;
    }

    auto current_time = std::chrono::steady_clock::now();
    auto time_delta = std::chrono::duration_cast<std::chrono::milliseconds>(
        current_time - last_update_).count();
    
    if (time_delta == 0) time_delta = 1; // Avoid division by zero

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        // Check if directory name is a PID (all digits)
        std::string name = entry->d_name;
        if (name.find_first_not_of("0123456789") == std::string::npos && !name.empty()) {
            pid_t pid = std::stoi(name);
            
            ProcessInfo info = {};
            info.pid = pid;
            info.last_updated = std::chrono::system_clock::now();
            
            // Read process information with proper error handling
            std::string proc_path = "/proc/" + name;
            
            if (!collect_process_details(proc_path, info, time_delta)) {
                continue; // Skip processes we can't read
            }
            
            processes.push_back(info);
        }
    }
    
    closedir(proc_dir);
    last_update_ = current_time;
    return true;
}

bool SystemMonitor::collect_process_details(const std::string& proc_path, 
                                           ProcessInfo& info, 
                                           long time_delta) {
    // Get process name from /proc/PID/comm
    std::ifstream comm_file(proc_path + "/comm");
    if (comm_file && !std::getline(comm_file, info.name)) {
        return false;
    }
    
    // Parse /proc/PID/stat for CPU and memory info
    if (!parse_proc_stat(proc_path + "/stat", info, time_delta)) {
        return false;
    }
    
    // Parse /proc/PID/status for additional memory info and security context
    parse_proc_status(proc_path + "/status", info);
    
    // Get command line
    parse_proc_cmdline(proc_path + "/cmdline", info);
    
    // Get open files (if we have permission)
    collect_process_files(proc_path + "/fd", info);
    
    // Get network connections for this process
    collect_process_network(info.pid, info);
    
    return true;
}

bool SystemMonitor::parse_proc_stat(const std::string& stat_file, 
                                   ProcessInfo& info, 
                                   long time_delta) {
    std::ifstream file(stat_file);
    if (!file) {
        return false;
    }
    
    std::string line;
    if (!std::getline(file, line)) {
        return false;
    }
    
    // Parse stat file - handle process names with spaces/special chars
    std::istringstream iss(line);
    std::string pid_str, comm, state;
    iss >> pid_str >> comm >> state;
    
    // Skip to the fields we need (after comm which might contain spaces)
    size_t last_paren = line.find_last_of(')');
    if (last_paren == std::string::npos) return false;
    
    std::istringstream field_stream(line.substr(last_paren + 1));
    
    std::string field;
    std::vector<std::string> fields;
    while (field_stream >> field) {
        fields.push_back(field);
    }
    
    if (fields.size() < 20) return false; // Not enough fields
    
    // Extract relevant fields (0-indexed after state field)
    try {
        unsigned long utime = std::stoul(fields[11]);   // User time
        unsigned long stime = std::stoul(fields[12]);   // System time
        unsigned long cutime = std::stoul(fields[13]);  // Children user time
        unsigned long cstime = std::stoul(fields[14]);  // Children system time
        unsigned long long vsize = std::stoull(fields[20]); // Virtual memory size
        long rss = std::stol(fields[21]);               // Resident set size
        
        // Calculate CPU usage
        unsigned long total_time = utime + stime + cutime + cstime;
        
        if (last_cpu_times_.count(info.pid)) {
            unsigned long last_total = last_cpu_times_[info.pid];
            if (total_time >= last_total) {
                unsigned long cpu_delta = total_time - last_total;
                // CPU percentage = (cpu_time_delta / time_delta) * 100
                // Note: CPU times are in clock ticks, convert to percentage
                info.cpu_percent = (static_cast<double>(cpu_delta) / sysconf(_SC_CLK_TCK)) * 
                                  (1000.0 / time_delta) * 100.0;
            }
        }
        
        last_cpu_times_[info.pid] = total_time;
        
        // Memory usage
        info.memory_bytes = rss * page_size_;
        info.virtual_memory_bytes = vsize;
        
        // Syscall count approximation (not perfect but useful)
        info.syscall_count = utime + stime; // Approximation
        
        return true;
        
    } catch (const std::exception& e) {
        return false;
    }
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
        } else if (line.find("Uid:") == 0) {
            std::istringstream iss(line);
            std::string key;
            uid_t real_uid, effective_uid, saved_uid, fs_uid;
            if (iss >> key >> real_uid >> effective_uid >> saved_uid >> fs_uid) {
                info.uid = real_uid;
                info.effective_uid = effective_uid;
            }
        } else if (line.find("Gid:") == 0) {
            std::istringstream iss(line);
            std::string key;
            gid_t real_gid, effective_gid, saved_gid, fs_gid;
            if (iss >> key >> real_gid >> effective_gid >> saved_gid >> fs_gid) {
                info.gid = real_gid;
                info.effective_gid = effective_gid;
            }
        }
    }
    
    return true;
}

bool SystemMonitor::parse_proc_cmdline(const std::string& cmdline_file, ProcessInfo& info) {
    std::ifstream file(cmdline_file);
    if (!file) {
        return false;
    }
    
    std::string cmdline;
    std::getline(file, cmdline);
    
    // Replace null separators with spaces
    for (auto& c : cmdline) {
        if (c == '\0') c = ' ';
    }
    
    info.command_line = cmdline;
    return true;
}

void SystemMonitor::collect_process_files(const std::string& fd_path, ProcessInfo& info) {
    if (!std::filesystem::exists(fd_path)) {
        return;
    }
    
    try {
        int file_count = 0;
        for (const auto& fd_entry : std::filesystem::directory_iterator(fd_path)) {
            if (++file_count > MAX_FILES_PER_PROCESS) break; // Limit to avoid excessive processing
            
            if (std::filesystem::is_symlink(fd_entry)) {
                std::error_code ec;
                auto target = std::filesystem::read_symlink(fd_entry, ec);
                if (!ec) {
                    std::string target_path = target.string();
                    // Filter out common uninteresting files
                    if (target_path.find("/dev/") != 0 && 
                        target_path.find("pipe:") != 0 &&
                        target_path.find("socket:") != 0) {
                        info.open_files.push_back(target_path);
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        // Permission denied or other error - continue
    }
}

void SystemMonitor::collect_process_network(pid_t pid, ProcessInfo& info) {
    // This is a simplified approach - in practice, you'd need to map
    // socket inodes from /proc/PID/fd to entries in /proc/net/tcp
    // For now, we'll collect basic network usage stats
    
    std::string net_dev_file = "/proc/" + std::to_string(pid) + "/net/dev";
    if (std::filesystem::exists(net_dev_file)) {
        // Process has network namespace info available
        info.has_network_activity = true;
    }
}

bool SystemMonitor::collect_tcp_connections(std::vector<NetworkConnection>& connections) {
    return parse_net_file("/proc/net/tcp", "tcp", connections) &&
           parse_net_file("/proc/net/tcp6", "tcp6", connections);
}

bool SystemMonitor::collect_udp_connections(std::vector<NetworkConnection>& connections) {
    return parse_net_file("/proc/net/udp", "udp", connections) &&
           parse_net_file("/proc/net/udp6", "udp6", connections);
}

bool SystemMonitor::collect_unix_connections(std::vector<NetworkConnection>& connections) {
    std::ifstream file("/proc/net/unix");
    if (!file) return false;
    
    std::string line;
    // Skip header
    std::getline(file, line);
    
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string num, refcount, protocol, flags, type, state, inode, path;
        
        if (iss >> num >> refcount >> protocol >> flags >> type >> state >> inode) {
            NetworkConnection conn;
            conn.protocol = "unix";
            conn.state = state;
            conn.inode = std::stoul(inode);
            
            // Get the rest as path
            std::getline(iss, path);
            if (!path.empty() && path[0] == ' ') {
                path = path.substr(1); // Remove leading space
            }
            conn.local_addr = path;
            
            connections.push_back(conn);
        }
    }
    
    return true;
}

bool SystemMonitor::parse_net_file(const std::string& filename, 
                                  const std::string& protocol,
                                  std::vector<NetworkConnection>& connections) {
    std::ifstream file(filename);
    if (!file) return false;
    
    std::string line;
    // Skip header line
    if (!std::getline(file, line)) return false;
    
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string sl, local_addr, remote_addr, st, tx_queue, rx_queue, tr, tm_when, retrnsmt, uid, timeout, inode;
        
        if (iss >> sl >> local_addr >> remote_addr >> st >> tx_queue >> rx_queue >> tr >> tm_when >> retrnsmt >> uid >> timeout >> inode) {
            NetworkConnection conn;
            conn.local_addr = parse_address(local_addr);
            conn.remote_addr = parse_address(remote_addr);
            conn.protocol = protocol;
            conn.state = st;
            conn.uid = std::stoul(uid);
            conn.inode = std::stoul(inode);
            
            connections.push_back(conn);
        }
    }
    
    return true;
}

std::string SystemMonitor::parse_address(const std::string& hex_addr) {
    if (hex_addr.size() < 9) return hex_addr; // Invalid format
    
    std::string ip_part = hex_addr.substr(0, 8);
    std::string port_part = hex_addr.substr(9);
    
    // Convert hex IP to dotted decimal (for IPv4)
    try {
        uint32_t ip_val = std::stoul(ip_part, nullptr, 16);
        uint16_t port_val = std::stoul(port_part, nullptr, 16);
        
        // IP is stored in little-endian format
        uint8_t a = ip_val & 0xFF;
        uint8_t b = (ip_val >> 8) & 0xFF;
        uint8_t c = (ip_val >> 16) & 0xFF;
        uint8_t d = (ip_val >> 24) & 0xFF;
        
        return std::to_string(a) + "." + std::to_string(b) + "." + 
               std::to_string(c) + "." + std::to_string(d) + ":" + std::to_string(port_val);
    } catch (const std::exception&) {
        return hex_addr; // Return original if parsing fails
    }
}

void SystemMonitor::map_connections_to_processes(std::vector<NetworkConnection>& connections) {
    // Map socket inodes to PIDs by scanning /proc/*/fd/*
    std::unordered_map<unsigned long, pid_t> inode_to_pid;
    
    try {
        for (const auto& proc_entry : std::filesystem::directory_iterator("/proc")) {
            if (!proc_entry.is_directory()) continue;
            
            std::string proc_name = proc_entry.path().filename();
            if (proc_name.find_first_not_of("0123456789") == std::string::npos && !proc_name.empty()) {
                pid_t pid = std::stoi(proc_name);
                std::string fd_path = proc_entry.path() / "fd";
                
                if (std::filesystem::exists(fd_path)) {
                    try {
                        for (const auto& fd_entry : std::filesystem::directory_iterator(fd_path)) {
                            if (std::filesystem::is_symlink(fd_entry)) {
                                std::error_code ec;
                                auto target = std::filesystem::read_symlink(fd_entry, ec);
                                if (!ec) {
                                    std::string target_str = target.string();
                                    if (target_str.find("socket:[") == 0) {
                                        // Extract inode number
                                        size_t start = target_str.find('[') + 1;
                                        size_t end = target_str.find(']');
                                        if (end != std::string::npos) {
                                            unsigned long inode = std::stoul(target_str.substr(start, end - start));
                                            inode_to_pid[inode] = pid;
                                        }
                                    }
                                }
                            }
                        }
                    } catch (const std::exception&) {
                        // Permission denied or other error - continue
                    }
                }
            }
        }
    } catch (const std::exception&) {
        // Error iterating /proc - continue
    }
    
    // Map connections to PIDs
    for (auto& conn : connections) {
        auto it = inode_to_pid.find(conn.inode);
        if (it != inode_to_pid.end()) {
            conn.pid = it->second;
        }
    }
}

void SystemMonitor::collect_memory_stats(SystemStats& stats) {
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
            } else if (key == "Buffers:") {
                stats.buffer_memory_bytes = value * 1024;
            } else if (key == "Cached:") {
                stats.cache_memory_bytes = value * 1024;
            } else if (key == "SwapTotal:") {
                stats.total_swap_bytes = value * 1024;
            } else if (key == "SwapFree:") {
                stats.free_swap_bytes = value * 1024;
            }
        }
    }
    
    if (stats.total_memory_bytes > 0) {
        stats.memory_usage_percent = 100.0 * 
            (stats.total_memory_bytes - stats.available_memory_bytes) / 
            stats.total_memory_bytes;
    }
}

void SystemMonitor::collect_cpu_stats(SystemStats& stats) {
    std::ifstream stat("/proc/stat");
    std::string line;
    
    if (std::getline(stat, line)) {
        std::istringstream iss(line);
        std::string cpu_label;
        unsigned long user, nice, system, idle, iowait, irq, softirq, steal;
        
        if (iss >> cpu_label >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal) {
            unsigned long total = user + nice + system + idle + iowait + irq + softirq + steal;
            unsigned long active = total - idle - iowait;
            
            if (cpu_baseline_.total_time > 0) {
                unsigned long total_delta = total - cpu_baseline_.total_time;
                unsigned long active_delta = active - cpu_baseline_.active_time;
                
                if (total_delta > 0) {
                    stats.cpu_usage_percent = 100.0 * active_delta / total_delta;
                }
            }
            
            cpu_baseline_.total_time = total;
            cpu_baseline_.active_time = active;
            
            stats.cpu_user_percent = 100.0 * user / total;
            stats.cpu_system_percent = 100.0 * system / total;
            stats.cpu_iowait_percent = 100.0 * iowait / total;
        }
    }
}

void SystemMonitor::collect_disk_stats(SystemStats& stats) {
    // Get disk usage for root filesystem
    struct statvfs vfs;
    if (statvfs("/", &vfs) == 0) {
        stats.total_disk_bytes = vfs.f_blocks * vfs.f_frsize;
        stats.available_disk_bytes = vfs.f_bavail * vfs.f_frsize;
        stats.disk_usage_percent = 100.0 * 
            (stats.total_disk_bytes - stats.available_disk_bytes) / 
            stats.total_disk_bytes;
    }
    
    // Get disk I/O stats from /proc/diskstats
    std::ifstream diskstats("/proc/diskstats");
    std::string line;
    
    stats.disk_read_bytes = 0;
    stats.disk_write_bytes = 0;
    
    while (std::getline(diskstats, line)) {
        std::istringstream iss(line);
        int major, minor;
        std::string device;
        unsigned long reads, read_merges, read_sectors, read_ticks;
        unsigned long writes, write_merges, write_sectors, write_ticks;
        
        if (iss >> major >> minor >> device >> reads >> read_merges >> read_sectors >> read_ticks
               >> writes >> write_merges >> write_sectors >> write_ticks) {
            
            // Skip loop devices and other virtual devices
            if (device.find("loop") == 0 || device.find("ram") == 0) continue;
            
            // Sectors are typically 512 bytes
            stats.disk_read_bytes += read_sectors * 512;
            stats.disk_write_bytes += write_sectors * 512;
        }
    }
}

void SystemMonitor::collect_network_stats(SystemStats& stats) {
    std::ifstream netdev("/proc/net/dev");
    std::string line;
    
    // Skip header lines
    std::getline(netdev, line);
    std::getline(netdev, line);
    
    stats.network_rx_bytes = 0;
    stats.network_tx_bytes = 0;
    
    while (std::getline(netdev, line)) {
        std::istringstream iss(line);
        std::string interface;
        unsigned long rx_bytes, rx_packets, rx_errs, rx_drop;
        unsigned long tx_bytes, tx_packets, tx_errs, tx_drop;
        
        if (iss >> interface >> rx_bytes >> rx_packets >> rx_errs >> rx_drop) {
            // Skip to tx stats (there are more rx fields)
            for (int i = 0; i < 4; ++i) iss >> rx_packets; // Skip remaining rx fields
            
            if (iss >> tx_bytes >> tx_packets >> tx_errs >> tx_drop) {
                // Skip loopback interface
                if (interface.find("lo:") == 0) continue;
                
                stats.network_rx_bytes += rx_bytes;
                stats.network_tx_bytes += tx_bytes;
            }
        }
    }
}

void SystemMonitor::collect_file_events(const std::string& path, 
                                       std::vector<FileSystemEvent>& events) {
    try {
        if (!std::filesystem::exists(path)) return;
        
        auto now = std::chrono::system_clock::now();
        auto one_hour_ago = now - std::chrono::hours(1);
        
        for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {
            try {
                auto last_write = std::filesystem::last_write_time(entry);
                
                // Convert to system_clock time point (this is complex due to different clock types)
                auto ftime = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    last_write - std::filesystem::file_time_type::clock::now() + now);
                
                if (ftime > one_hour_ago) {
                    FileSystemEvent event;
                    event.path = entry.path().string();
                    event.timestamp = ftime;
                    event.event_type = "modify"; // Simplified - real implementation would use inotify
                    event.size = std::filesystem::is_regular_file(entry) ? 
                                std::filesystem::file_size(entry) : 0;
                    
                    events.push_back(event);
                }
            } catch (const std::exception&) {
                // Permission denied or other error - continue
            }
        }
    } catch (const std::exception&) {
        // Error accessing path - continue
    }
}

void SystemMonitor::update_cpu_baseline() {
    std::ifstream stat("/proc/stat");
    std::string line;
    
    if (std::getline(stat, line)) {
        std::istringstream iss(line);
        std::string cpu_label;
        unsigned long user, nice, system, idle, iowait, irq, softirq, steal;
        
        if (iss >> cpu_label >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal) {
            cpu_baseline_.total_time = user + nice + system + idle + iowait + irq + softirq + steal;
            cpu_baseline_.active_time = cpu_baseline_.total_time - idle - iowait;
        }
    }
}

} // namespace core
} // namespace genesis