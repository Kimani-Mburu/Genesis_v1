#include "behavioral_profiler.hpp"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <fstream>
#include <sstream>
#include <random>
#include <filesystem>

namespace genesis {
namespace core {

BehavioralProfiler::BehavioralProfiler(size_t learning_window, double adaptation_rate)
    : running_(false)
    , learning_window_hours_(learning_window)
    , adaptation_rate_(adaptation_rate)
    , start_time_(std::chrono::system_clock::now()) {
}

BehavioralProfiler::~BehavioralProfiler() {
    stop();
}

bool BehavioralProfiler::start() {
    if (running_.load()) {
        return false; // Already running
    }

    try {
        running_.store(true);
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
    if (!profile || profile->sample_count < 10) {
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
        json << "\"sample_count\":" << profile->sample_count;
        json << "}";
    }
    
    json << "]}";
    return json.str();
}

bool BehavioralProfiler::import_profiles(const std::string& profiles_json) {
    // Simplified JSON parsing - in production, use a proper JSON library
    try {
        std::cout << "[BehavioralProfiler] Importing " << profiles_json.length() 
                 << " bytes of profile data" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[BehavioralProfiler] Failed to import profiles: " << e.what() << std::endl;
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
        } catch (const std::exception& e) {
            std::cerr << "[BehavioralProfiler] Error in monitoring loop: " << e.what() << std::endl;
        }

        std::this_thread::sleep_for(MONITORING_INTERVAL);
    }
}

std::vector<BehaviorPattern> BehavioralProfiler::collect_system_behavior() {
    std::vector<BehaviorPattern> patterns;
    
    // Simulate collecting system behavior data
    // In a real implementation, this would use system APIs to gather:
    // - Process information (/proc on Linux)
    // - Network connections (netstat, ss)
    // - File system monitoring (inotify)
    // - System call tracing (strace, eBPF)
    
    try {
        // Mock data for demonstration
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> cpu_dist(0.1, 15.0);
        std::uniform_real_distribution<> mem_dist(10.0, 100.0);
        std::uniform_int_distribution<> syscall_dist(50, 500);
        
        std::vector<std::string> common_processes = {
            "systemd", "chrome", "firefox", "bash", "ssh", "nginx", "mysql"
        };
        
        for (const auto& process : common_processes) {
            BehaviorPattern pattern;
            pattern.process_name = process;
            pattern.cpu_usage = cpu_dist(gen);
            pattern.memory_usage = mem_dist(gen);
            pattern.syscall_frequency = syscall_dist(gen);
            pattern.timestamp = std::chrono::system_clock::now();
            
            // Simulate network connections
            if (process == "chrome" || process == "firefox") {
                pattern.network_connections = {"443:tcp", "80:tcp", "53:udp"};
            } else if (process == "ssh") {
                pattern.network_connections = {"22:tcp"};
            }
            
            // Simulate file accesses
            pattern.file_accesses = {"/tmp", "/var/log", "/proc"};
            
            patterns.push_back(pattern);
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[BehavioralProfiler] Error collecting system behavior: " << e.what() << std::endl;
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
        profile->sample_count = 1;
        profile->last_updated = pattern.timestamp;
        
        process_profiles_[process_name] = profile;
    } else {
        // Update existing profile using exponential moving average
        auto& profile = it->second;
        double alpha = adaptation_rate_;
        
        // Update averages
        profile->avg_cpu_usage = alpha * pattern.cpu_usage + (1 - alpha) * profile->avg_cpu_usage;
        profile->avg_memory_usage = alpha * pattern.memory_usage + (1 - alpha) * profile->avg_memory_usage;
        profile->avg_syscall_frequency = alpha * pattern.syscall_frequency + (1 - alpha) * profile->avg_syscall_frequency;
        
        // Update standard deviations (simplified)
        double cpu_diff = pattern.cpu_usage - profile->avg_cpu_usage;
        double mem_diff = pattern.memory_usage - profile->avg_memory_usage;
        double syscall_diff = pattern.syscall_frequency - profile->avg_syscall_frequency;
        
        profile->std_cpu_usage = alpha * (cpu_diff * cpu_diff) + (1 - alpha) * (profile->std_cpu_usage * profile->std_cpu_usage);
        profile->std_memory_usage = alpha * (mem_diff * mem_diff) + (1 - alpha) * (profile->std_memory_usage * profile->std_memory_usage);
        profile->std_syscall_frequency = alpha * (syscall_diff * syscall_diff) + (1 - alpha) * (profile->std_syscall_frequency * profile->std_syscall_frequency);
        
        profile->std_cpu_usage = std::sqrt(profile->std_cpu_usage);
        profile->std_memory_usage = std::sqrt(profile->std_memory_usage);
        profile->std_syscall_frequency = std::sqrt(profile->std_syscall_frequency);
        
        // Update network and file patterns
        for (const auto& conn : pattern.network_connections) {
            profile->common_network_patterns[conn]++;
        }
        for (const auto& file : pattern.file_accesses) {
            profile->common_file_patterns[file]++;
        }
        
        profile->sample_count++;
        profile->last_updated = pattern.timestamp;
    }
}

double BehavioralProfiler::calculate_statistical_distance(const BehaviorPattern& pattern, 
                                                         const BehaviorProfile& profile) const {
    double total_score = 0.0;
    size_t score_count = 0;
    
    // Calculate Z-scores for numerical features
    if (profile.std_cpu_usage > 0) {
        double cpu_z_score = std::abs(pattern.cpu_usage - profile.avg_cpu_usage) / profile.std_cpu_usage;
        total_score += std::min(1.0, cpu_z_score / 3.0); // Normalize to [0,1]
        score_count++;
    }
    
    if (profile.std_memory_usage > 0) {
        double mem_z_score = std::abs(pattern.memory_usage - profile.avg_memory_usage) / profile.std_memory_usage;
        total_score += std::min(1.0, mem_z_score / 3.0);
        score_count++;
    }
    
    if (profile.std_syscall_frequency > 0) {
        double syscall_z_score = std::abs(static_cast<double>(pattern.syscall_frequency) - profile.avg_syscall_frequency) / profile.std_syscall_frequency;
        total_score += std::min(1.0, syscall_z_score / 3.0);
        score_count++;
    }
    
    // Calculate network pattern anomaly
    double network_anomaly = 0.0;
    for (const auto& conn : pattern.network_connections) {
        auto it = profile.common_network_patterns.find(conn);
        if (it == profile.common_network_patterns.end()) {
            network_anomaly += 0.5; // Unknown connection pattern
        }
    }
    network_anomaly = std::min(1.0, network_anomaly);
    total_score += network_anomaly;
    score_count++;
    
    // Calculate file access anomaly
    double file_anomaly = 0.0;
    for (const auto& file : pattern.file_accesses) {
        auto it = profile.common_file_patterns.find(file);
        if (it == profile.common_file_patterns.end()) {
            file_anomaly += 0.3; // Unknown file access
        }
    }
    file_anomaly = std::min(1.0, file_anomaly);
    total_score += file_anomaly;
    score_count++;
    
    return (score_count > 0) ? (total_score / score_count) : 0.0;
}

} // namespace core
} // namespace genesis