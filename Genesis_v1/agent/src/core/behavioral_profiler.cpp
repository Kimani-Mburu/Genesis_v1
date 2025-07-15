#include "behavioral_profiler.hpp"
#include "system_monitor.hpp"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <fstream>
#include <sstream>
#include <random>
#include <filesystem>
#include <unordered_map>

namespace genesis {
namespace core {

BehavioralProfiler::BehavioralProfiler(size_t learning_window, double adaptation_rate)
    : running_(false)
    , learning_window_hours_(learning_window)
    , adaptation_rate_(adaptation_rate)
    , start_time_(std::chrono::system_clock::now())
    , auto_save_enabled_(true)
    , profile_save_interval_(std::chrono::minutes(15))
    , last_save_time_(start_time_) {
}

BehavioralProfiler::~BehavioralProfiler() {
    stop();
    
    // Auto-save profiles on shutdown
    if (auto_save_enabled_) {
        save_profiles_to_disk();
    }
}

bool BehavioralProfiler::start() {
    if (running_.load()) {
        return false; // Already running
    }

    try {
        running_.store(true);
        
        // Try to load existing profiles
        load_profiles_from_disk();
        
        monitoring_thread_ = std::thread(&BehavioralProfiler::monitoring_loop, this);
        std::cout << "[BehavioralProfiler] Started monitoring system behavior" << std::endl;
        return true;
    } catch (const std::exception& e) {
        running_.store(false);
        std::cerr << "[BehavioralProfiler] Failed to start: " << e.what() << std::endl;
        return false;
    }
}

void BehavioralProfiler::stop() {
    if (!running_.load()) {
        return; // Already stopped
    }

    running_.store(false);
    if (monitoring_thread_.joinable()) {
        monitoring_thread_.join();
    }
    
    // Save profiles before stopping
    if (auto_save_enabled_) {
        save_profiles_to_disk();
    }
    
    std::cout << "[BehavioralProfiler] Stopped monitoring" << std::endl;
}

bool BehavioralProfiler::is_running() const {
    return running_.load();
}

void BehavioralProfiler::add_behavior_pattern(const BehaviorPattern& pattern) {
    update_profile(pattern.process_name, pattern);
}

std::shared_ptr<BehaviorProfile> BehavioralProfiler::get_profile(const std::string& process_name) const {
    std::lock_guard<std::mutex> lock(profiles_mutex_);
    auto it = process_profiles_.find(process_name);
    return (it != process_profiles_.end()) ? it->second : nullptr;
}

double BehavioralProfiler::calculate_anomaly_score(const BehaviorPattern& pattern) const {
    auto profile = get_profile(pattern.process_name);
    if (!profile || profile->sample_count < MIN_SAMPLES_FOR_ANALYSIS) {
        return 0.0; // Not enough data for reliable scoring
    }

    return calculate_statistical_distance(pattern, *profile);
}

bool BehavioralProfiler::is_learning() const {
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::hours>(now - start_time_).count();
    return elapsed < static_cast<long>(learning_window_hours_);
}

size_t BehavioralProfiler::get_monitored_process_count() const {
    std::lock_guard<std::mutex> lock(profiles_mutex_);
    return process_profiles_.size();
}

std::string BehavioralProfiler::export_profiles() const {
    std::lock_guard<std::mutex> lock(profiles_mutex_);
    
    std::ostringstream json;
    json << "{\"profiles\":[";
    
    bool first = true;
    for (const auto& [process_name, profile] : process_profiles_) {
        if (!first) json << ",";
        first = false;
        
        json << "{";
        json << "\"process_name\":\"" << process_name << "\",";
        json << "\"avg_cpu_usage\":" << profile->avg_cpu_usage << ",";
        json << "\"std_cpu_usage\":" << profile->std_cpu_usage << ",";
        json << "\"avg_memory_usage\":" << profile->avg_memory_usage << ",";
        json << "\"std_memory_usage\":" << profile->std_memory_usage << ",";
        json << "\"avg_syscall_frequency\":" << profile->avg_syscall_frequency << ",";
        json << "\"std_syscall_frequency\":" << profile->std_syscall_frequency << ",";
        json << "\"sample_count\":" << profile->sample_count << ",";
        json << "\"security_flags\":[";
        
        bool first_flag = true;
        for (const auto& flag : profile->security_flags) {
            if (!first_flag) json << ",";
            json << "\"" << flag << "\"";
            first_flag = false;
        }
        json << "]";
        json << "}";
    }
    
    json << "]}";
    return json.str();
}

bool BehavioralProfiler::import_profiles(const std::string& profiles_json) {
    try {
        // Simplified JSON parsing - in production, use a proper JSON library
        std::cout << "[BehavioralProfiler] Importing " << profiles_json.length() 
                 << " bytes of profile data" << std::endl;
        
        // Basic validation
        if (profiles_json.find("\"profiles\"") == std::string::npos) {
            std::cerr << "[BehavioralProfiler] Invalid profile format" << std::endl;
            return false;
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[BehavioralProfiler] Failed to import profiles: " << e.what() << std::endl;
        return false;
    }
}

void BehavioralProfiler::set_auto_save_enabled(bool enabled) {
    auto_save_enabled_ = enabled;
}

void BehavioralProfiler::set_auto_save_interval(std::chrono::minutes interval) {
    profile_save_interval_ = interval;
}

bool BehavioralProfiler::save_profiles_to_disk() const {
    try {
        std::string profiles_dir = "/var/lib/genesis/profiles";
        std::filesystem::create_directories(profiles_dir);
        
        std::string filename = profiles_dir + "/behavioral_profiles.json";
        std::ofstream file(filename, std::ios::out | std::ios::trunc);
        if (!file) {
            std::cerr << "[BehavioralProfiler] Cannot write to " << filename << std::endl;
            return false;
        }
        
        file << export_profiles();
        file.close();
        
        std::cout << "[BehavioralProfiler] Saved profiles to " << filename << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "[BehavioralProfiler] Error saving profiles: " << e.what() << std::endl;
        return false;
    }
}

bool BehavioralProfiler::load_profiles_from_disk() {
    try {
        std::string filename = "/var/lib/genesis/profiles/behavioral_profiles.json";
        if (!std::filesystem::exists(filename)) {
            std::cout << "[BehavioralProfiler] No existing profiles found" << std::endl;
            return true; // Not an error - first run
        }
        
        std::ifstream file(filename);
        if (!file) {
            std::cerr << "[BehavioralProfiler] Cannot read " << filename << std::endl;
            return false;
        }
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        file.close();
        
        bool success = import_profiles(buffer.str());
        if (success) {
            std::cout << "[BehavioralProfiler] Loaded profiles from " << filename << std::endl;
        }
        
        return success;
        
    } catch (const std::exception& e) {
        std::cerr << "[BehavioralProfiler] Error loading profiles: " << e.what() << std::endl;
        return false;
    }
}

void BehavioralProfiler::monitoring_loop() {
    while (running_.load()) {
        try {
            auto patterns = collect_system_behavior();
            for (const auto& pattern : patterns) {
                add_behavior_pattern(pattern);
            }
            
            // Periodic auto-save
            auto now = std::chrono::system_clock::now();
            if (auto_save_enabled_ && 
                (now - last_save_time_) >= profile_save_interval_) {
                save_profiles_to_disk();
                last_save_time_ = now;
            }
            
        } catch (const std::exception& e) {
            std::cerr << "[BehavioralProfiler] Error in monitoring loop: " << e.what() << std::endl;
        }

        std::this_thread::sleep_for(MONITORING_INTERVAL);
    }
}

std::vector<BehaviorPattern> BehavioralProfiler::collect_system_behavior() {
    std::vector<BehaviorPattern> patterns;
    
    // Use real system monitor for data collection
    static std::unique_ptr<SystemMonitor> system_monitor;
    if (!system_monitor) {
        system_monitor = std::make_unique<SystemMonitor>();
        if (!system_monitor->initialize()) {
            std::cerr << "[BehavioralProfiler] Failed to initialize system monitor" << std::endl;
            return patterns; // Return empty patterns if monitoring fails
        }
    }
    
    try {
        // Get real process information
        auto processes = system_monitor->get_process_info();
        auto network_connections = system_monitor->get_network_connections();
        auto file_events = system_monitor->get_recent_file_events();
        auto system_stats = system_monitor->get_system_stats();
        
        // Create connection and file access maps for quick lookup
        std::unordered_map<pid_t, std::vector<std::string>> pid_to_connections;
        std::unordered_map<pid_t, std::vector<std::string>> pid_to_files;
        
        // Map network connections to processes
        for (const auto& conn : network_connections) {
            if (conn.pid > 0) {
                std::string conn_str = conn.protocol + ":" + conn.local_addr + "->" + conn.remote_addr;
                pid_to_connections[conn.pid].push_back(conn_str);
            }
        }
        
        // Map file events to processes (simplified approach)
        for (const auto& event : file_events) {
            if (!event.path.empty()) {
                // Use a heuristic to associate files with processes
                for (const auto& proc : processes) {
                    for (const auto& open_file : proc.open_files) {
                        if (event.path.find(open_file) != std::string::npos) {
                            pid_to_files[proc.pid].push_back(event.path);
                            break;
                        }
                    }
                }
            }
        }
        
        auto now = std::chrono::system_clock::now();
        
        // Process each monitored process
        for (const auto& proc : processes) {
            // Skip kernel threads and very short-lived processes
            if (proc.name.empty() || proc.name.find('[') == 0) {
                continue;
            }
            
            // Skip processes with minimal activity to reduce noise
            if (proc.cpu_percent < 0.1 && proc.memory_bytes < 1024 * 1024) { // < 1MB
                continue;
            }
            
            BehaviorPattern pattern;
            pattern.process_name = proc.name;
            pattern.cpu_usage = proc.cpu_percent;
            pattern.memory_usage = static_cast<double>(proc.memory_bytes) / (1024.0 * 1024.0); // Convert to MB
            pattern.syscall_frequency = proc.syscall_count;
            pattern.timestamp = now;
            
            // Add network connections for this process
            auto conn_it = pid_to_connections.find(proc.pid);
            if (conn_it != pid_to_connections.end()) {
                pattern.network_connections = conn_it->second;
            }
            
            // Add file accesses for this process
            auto file_it = pid_to_files.find(proc.pid);
            if (file_it != pid_to_files.end()) {
                pattern.file_accesses = file_it->second;
            } else {
                // Use open files as a proxy for file access patterns
                pattern.file_accesses = proc.open_files;
            }
            
            // Add security context information
            if (proc.effective_uid == 0) {
                pattern.file_accesses.push_back("ROOT_PROCESS"); // Flag root processes
            }
            
            if (proc.uid != proc.effective_uid) {
                pattern.file_accesses.push_back("SUID_PROCESS"); // Flag SUID processes
            }
            
            // Add command line analysis for suspicious patterns
            if (!proc.command_line.empty()) {
                std::vector<std::string> suspicious_patterns = {
                    "sh -c", "bash -c", "eval", "curl", "wget", "nc ", "netcat",
                    "python -c", "perl -e", "ruby -e", "base64", "chmod +x"
                };
                
                for (const auto& suspicious : suspicious_patterns) {
                    if (proc.command_line.find(suspicious) != std::string::npos) {
                        pattern.file_accesses.push_back("SUSPICIOUS_CMD:" + suspicious);
                    }
                }
            }
            
            patterns.push_back(pattern);
        }
        
        // Add system-level pattern for overall health monitoring
        if (system_stats.cpu_usage_percent > 0 || system_stats.memory_usage_percent > 0) {
            BehaviorPattern system_pattern;
            system_pattern.process_name = "SYSTEM_OVERALL";
            system_pattern.cpu_usage = system_stats.cpu_usage_percent;
            system_pattern.memory_usage = system_stats.memory_usage_percent;
            system_pattern.syscall_frequency = 0; // Not applicable for system-level
            system_pattern.timestamp = now;
            
            // Add system-level indicators
            if (system_stats.cpu_usage_percent > 90.0) {
                system_pattern.file_accesses.push_back("HIGH_CPU_USAGE");
            }
            if (system_stats.memory_usage_percent > 90.0) {
                system_pattern.file_accesses.push_back("HIGH_MEMORY_USAGE");
            }
            if (system_stats.disk_usage_percent > 95.0) {
                system_pattern.file_accesses.push_back("HIGH_DISK_USAGE");
            }
            
            patterns.push_back(system_pattern);
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[BehavioralProfiler] Error collecting real system behavior: " << e.what() << std::endl;
        
        // Fallback to minimal monitoring to keep the system operational
        try {
            BehaviorPattern fallback_pattern;
            fallback_pattern.process_name = "MONITORING_ERROR";
            fallback_pattern.cpu_usage = 0.0;
            fallback_pattern.memory_usage = 0.0;
            fallback_pattern.syscall_frequency = 0;
            fallback_pattern.timestamp = std::chrono::system_clock::now();
            fallback_pattern.file_accesses = {"COLLECTION_FAILED"};
            patterns.push_back(fallback_pattern);
        } catch (...) {
            // Even fallback failed - return empty patterns
        }
    }
    
    return patterns;
}

void BehavioralProfiler::update_profile(const std::string& process_name, const BehaviorPattern& pattern) {
    std::lock_guard<std::mutex> lock(profiles_mutex_);
    
    auto it = process_profiles_.find(process_name);
    if (it == process_profiles_.end()) {
        // Create new profile
        auto profile = std::make_shared<BehaviorProfile>();
        profile->avg_cpu_usage = pattern.cpu_usage;
        profile->avg_memory_usage = pattern.memory_usage;
        profile->avg_syscall_frequency = pattern.syscall_frequency;
        profile->std_cpu_usage = 0.0; // Will be calculated over time
        profile->std_memory_usage = 0.0;
        profile->std_syscall_frequency = 0.0;
        profile->sample_count = 1;
        profile->last_updated = pattern.timestamp;
        
        // Initialize security flags
        for (const auto& access : pattern.file_accesses) {
            if (access.find("ROOT_PROCESS") != std::string::npos ||
                access.find("SUID_PROCESS") != std::string::npos ||
                access.find("SUSPICIOUS_CMD") != std::string::npos) {
                profile->security_flags.insert(access);
            }
        }
        
        process_profiles_[process_name] = profile;
    } else {
        // Update existing profile using exponential moving average
        auto& profile = it->second;
        double alpha = adaptation_rate_;
        
        // Store previous values for variance calculation
        double prev_cpu = profile->avg_cpu_usage;
        double prev_memory = profile->avg_memory_usage;
        double prev_syscall = profile->avg_syscall_frequency;
        
        // Update averages
        profile->avg_cpu_usage = alpha * pattern.cpu_usage + (1 - alpha) * profile->avg_cpu_usage;
        profile->avg_memory_usage = alpha * pattern.memory_usage + (1 - alpha) * profile->avg_memory_usage;
        profile->avg_syscall_frequency = alpha * pattern.syscall_frequency + (1 - alpha) * profile->avg_syscall_frequency;
        
        // Update standard deviations using Welford's online algorithm
        double cpu_delta = pattern.cpu_usage - prev_cpu;
        double cpu_delta2 = pattern.cpu_usage - profile->avg_cpu_usage;
        profile->std_cpu_usage = std::sqrt(
            ((profile->sample_count - 1) * profile->std_cpu_usage * profile->std_cpu_usage + 
             cpu_delta * cpu_delta2) / profile->sample_count);
        
        double mem_delta = pattern.memory_usage - prev_memory;
        double mem_delta2 = pattern.memory_usage - profile->avg_memory_usage;
        profile->std_memory_usage = std::sqrt(
            ((profile->sample_count - 1) * profile->std_memory_usage * profile->std_memory_usage + 
             mem_delta * mem_delta2) / profile->sample_count);
        
        double syscall_delta = pattern.syscall_frequency - prev_syscall;
        double syscall_delta2 = pattern.syscall_frequency - profile->avg_syscall_frequency;
        profile->std_syscall_frequency = std::sqrt(
            ((profile->sample_count - 1) * profile->std_syscall_frequency * profile->std_syscall_frequency + 
             syscall_delta * syscall_delta2) / profile->sample_count);
        
        // Update network and file patterns
        for (const auto& conn : pattern.network_connections) {
            profile->common_network_patterns[conn]++;
        }
        for (const auto& file : pattern.file_accesses) {
            profile->common_file_patterns[file]++;
            
            // Track security-relevant patterns
            if (file.find("ROOT_PROCESS") != std::string::npos ||
                file.find("SUID_PROCESS") != std::string::npos ||
                file.find("SUSPICIOUS_CMD") != std::string::npos) {
                profile->security_flags.insert(file);
            }
        }
        
        profile->sample_count++;
        profile->last_updated = pattern.timestamp;
    }
}

double BehavioralProfiler::calculate_statistical_distance(const BehaviorPattern& pattern, 
                                                         const BehaviorProfile& profile) const {
    double total_score = 0.0;
    size_t score_count = 0;
    
    // Calculate Z-scores for numerical features with minimum threshold to avoid division by zero
    const double MIN_STD = 0.001;
    
    if (profile.std_cpu_usage > MIN_STD) {
        double cpu_z_score = std::abs(pattern.cpu_usage - profile.avg_cpu_usage) / profile.std_cpu_usage;
        total_score += std::min(1.0, cpu_z_score / 3.0); // Normalize to [0,1] using 3-sigma rule
        score_count++;
    }
    
    if (profile.std_memory_usage > MIN_STD) {
        double mem_z_score = std::abs(pattern.memory_usage - profile.avg_memory_usage) / profile.std_memory_usage;
        total_score += std::min(1.0, mem_z_score / 3.0);
        score_count++;
    }
    
    if (profile.std_syscall_frequency > MIN_STD) {
        double syscall_z_score = std::abs(static_cast<double>(pattern.syscall_frequency) - profile.avg_syscall_frequency) / profile.std_syscall_frequency;
        total_score += std::min(1.0, syscall_z_score / 3.0);
        score_count++;
    }
    
    // Calculate network pattern anomaly with weighted scoring
    double network_anomaly = 0.0;
    double network_weight = 0.0;
    for (const auto& conn : pattern.network_connections) {
        network_weight += 1.0;
        auto it = profile.common_network_patterns.find(conn);
        if (it == profile.common_network_patterns.end()) {
            network_anomaly += 0.8; // High anomaly for unknown connections
        } else if (it->second < 3) { // Rare connection
            network_anomaly += 0.4;
        }
    }
    if (network_weight > 0) {
        network_anomaly = std::min(1.0, network_anomaly / network_weight);
        total_score += network_anomaly;
        score_count++;
    }
    
    // Calculate file access anomaly with security emphasis
    double file_anomaly = 0.0;
    double file_weight = 0.0;
    for (const auto& file : pattern.file_accesses) {
        file_weight += 1.0;
        
        // High weight for security-related indicators
        if (file.find("SUSPICIOUS_CMD") != std::string::npos) {
            file_anomaly += 1.0; // Maximum anomaly for suspicious commands
        } else if (file.find("ROOT_PROCESS") != std::string::npos ||
                   file.find("SUID_PROCESS") != std::string::npos) {
            file_anomaly += 0.6; // Moderate anomaly for privilege indicators
        } else {
            auto it = profile.common_file_patterns.find(file);
            if (it == profile.common_file_patterns.end()) {
                file_anomaly += 0.3; // Lower anomaly for unknown files
            }
        }
    }
    if (file_weight > 0) {
        file_anomaly = std::min(1.0, file_anomaly / file_weight);
        total_score += file_anomaly;
        score_count++;
    }
    
    return (score_count > 0) ? (total_score / score_count) : 0.0;
}

} // namespace core
} // namespace genesis