#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <mutex>
#include <thread>
#include <atomic>

namespace genesis {
namespace core {

/**
 * @brief Represents a system behavior pattern
 */
struct BehaviorPattern {
    std::string process_name;
    std::vector<std::string> network_connections;
    std::vector<std::string> file_accesses;
    double cpu_usage;
    double memory_usage;
    size_t syscall_frequency;
    std::chrono::system_clock::time_point timestamp;
};

/**
 * @brief Statistical profile of normal behavior
 */
struct BehaviorProfile {
    double avg_cpu_usage = 0.0;
    double std_cpu_usage = 0.0;
    double avg_memory_usage = 0.0;
    double std_memory_usage = 0.0;
    double avg_syscall_frequency = 0.0;
    double std_syscall_frequency = 0.0;
    std::unordered_map<std::string, size_t> common_network_patterns;
    std::unordered_map<std::string, size_t> common_file_patterns;
    size_t sample_count = 0;
    std::chrono::system_clock::time_point last_updated;
};

/**
 * @brief BehavioralProfiler monitors system behavior and establishes baselines
 * 
 * This component is inspired by the adaptive immune system's ability to
 * distinguish between "self" and "non-self" entities. It continuously
 * monitors system behavior patterns and builds statistical models of
 * normal operation.
 */
class BehavioralProfiler {
public:
    /**
     * @brief Constructor
     * @param learning_window Time window for establishing initial baseline (in hours)
     * @param adaptation_rate Rate at which the profiler adapts to new patterns (0.0-1.0)
     */
    BehavioralProfiler(size_t learning_window = 24, double adaptation_rate = 0.1);
    
    /**
     * @brief Destructor
     */
    ~BehavioralProfiler();

    /**
     * @brief Start the behavioral profiling process
     * @return true if successfully started, false otherwise
     */
    bool start();

    /**
     * @brief Stop the behavioral profiling process
     */
    void stop();

    /**
     * @brief Check if the profiler is currently running
     * @return true if running, false otherwise
     */
    bool is_running() const;

    /**
     * @brief Add a new behavior pattern to the profiler
     * @param pattern The behavior pattern to analyze
     */
    void add_behavior_pattern(const BehaviorPattern& pattern);

    /**
     * @brief Get the current behavior profile for a process
     * @param process_name Name of the process
     * @return Behavior profile if available, nullptr otherwise
     */
    std::shared_ptr<BehaviorProfile> get_profile(const std::string& process_name) const;

    /**
     * @brief Calculate anomaly score for a given behavior pattern
     * @param pattern The behavior pattern to evaluate
     * @return Anomaly score (0.0 = normal, 1.0 = maximum anomaly)
     */
    double calculate_anomaly_score(const BehaviorPattern& pattern) const;

    /**
     * @brief Check if the system is in learning mode
     * @return true if still learning baseline, false if baseline established
     */
    bool is_learning() const;

    /**
     * @brief Get the number of processes being monitored
     * @return Number of active process profiles
     */
    size_t get_monitored_process_count() const;

    /**
     * @brief Export current profiles for sharing with other instances
     * @return JSON string containing profile data
     */
    std::string export_profiles() const;

    /**
     * @brief Import profiles from another GENESIS instance
     * @param profiles_json JSON string containing profile data
     * @return true if successfully imported, false otherwise
     */
    bool import_profiles(const std::string& profiles_json);

private:
    /**
     * @brief Main monitoring loop
     */
    void monitoring_loop();

    /**
     * @brief Collect current system behavior data
     * @return Vector of current behavior patterns
     */
    std::vector<BehaviorPattern> collect_system_behavior();

    /**
     * @brief Update profile with new behavior pattern
     * @param process_name Name of the process
     * @param pattern New behavior pattern
     */
    void update_profile(const std::string& process_name, const BehaviorPattern& pattern);

    /**
     * @brief Calculate statistical distance between pattern and profile
     * @param pattern Behavior pattern to evaluate
     * @param profile Reference behavior profile
     * @return Statistical distance (anomaly score)
     */
    double calculate_statistical_distance(const BehaviorPattern& pattern, 
                                         const BehaviorProfile& profile) const;

private:
    mutable std::mutex profiles_mutex_;
    std::unordered_map<std::string, std::shared_ptr<BehaviorProfile>> process_profiles_;
    
    std::atomic<bool> running_;
    std::thread monitoring_thread_;
    
    size_t learning_window_hours_;
    double adaptation_rate_;
    std::chrono::system_clock::time_point start_time_;
    
    // Configuration
    static constexpr size_t MAX_PATTERN_HISTORY = 1000;
    static constexpr double ANOMALY_THRESHOLD = 0.7;
    static constexpr std::chrono::seconds MONITORING_INTERVAL{5};
};

} // namespace core
} // namespace genesis