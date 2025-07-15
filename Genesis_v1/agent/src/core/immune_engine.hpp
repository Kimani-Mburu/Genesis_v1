#pragma once

#include "behavioral_profiler.hpp"
#include "../response/response_actions.hpp"
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <unordered_map>

namespace genesis {
namespace core {

/**
 * @brief Represents a detected threat with severity assessment
 */
struct ThreatEvent {
    std::string threat_id;
    std::string threat_type;
    std::string description;
    double severity_score = 0.0; // 0.0-1.0
    std::string source_process;
    pid_t source_pid = 0;
    std::string source_ip;
    std::string source_file;
    std::chrono::system_clock::time_point detected_at;
    BehaviorPattern triggering_pattern;
    double anomaly_score = 0.0;
};

/**
 * @brief Response decision with escalation logic
 */
struct ResponseDecision {
    std::string threat_id;
    std::vector<std::string> actions_to_execute;
    std::string rationale;
    double confidence_level = 0.0;
    std::chrono::system_clock::time_point decision_time;
    bool requires_human_approval = false;
};

/**
 * @brief System health metrics for immune system monitoring
 */
struct ImmuneSystemHealth {
    double overall_threat_level = 0.0;
    size_t active_threats = 0;
    size_t responses_executed = 0;
    size_t successful_responses = 0;
    double false_positive_rate = 0.0;
    double system_load_impact = 0.0;
    std::chrono::system_clock::time_point last_updated;
};

/**
 * @brief Central immune engine that orchestrates threat detection and response
 * 
 * This class serves as the brain of the GENESIS system, coordinating between
 * behavioral profiling, threat assessment, and response execution.
 */
class ImmuneEngine {
public:
    /**
     * @brief Constructor
     * @param profiler Shared behavioral profiler instance
     * @param response_manager Shared response actions manager
     */
    ImmuneEngine(std::shared_ptr<BehavioralProfiler> profiler,
                std::shared_ptr<response::ResponseActionsManager> response_manager);
    
    /**
     * @brief Destructor
     */
    ~ImmuneEngine();

    /**
     * @brief Start the immune engine
     * @return true if started successfully
     */
    bool start();

    /**
     * @brief Stop the immune engine
     */
    void stop();

    /**
     * @brief Check if the immune engine is running
     * @return true if running
     */
    bool is_running() const;

    /**
     * @brief Report a potential threat for assessment
     * @param pattern Behavior pattern that triggered detection
     * @param anomaly_score Anomaly score from behavioral profiler
     * @param source Additional context information
     * @return Unique threat ID for tracking
     */
    std::string report_threat(const BehaviorPattern& pattern, 
                             double anomaly_score,
                             const std::string& source = "behavioral_profiler");

    /**
     * @brief Get current system health metrics
     * @return Current immune system health status
     */
    ImmuneSystemHealth get_system_health() const;

    /**
     * @brief Get active threats
     * @return Vector of currently active threats
     */
    std::vector<ThreatEvent> get_active_threats() const;

    /**
     * @brief Manually trigger response to a threat
     * @param threat_id ID of threat to respond to
     * @param force_execute Whether to bypass normal approval processes
     * @return true if response initiated successfully
     */
    bool trigger_response(const std::string& threat_id, bool force_execute = false);

    /**
     * @brief Update threat severity thresholds
     * @param low_threshold Threshold for low severity threats (0.0-1.0)
     * @param medium_threshold Threshold for medium severity threats (0.0-1.0)
     * @param high_threshold Threshold for high severity threats (0.0-1.0)
     */
    void update_severity_thresholds(double low_threshold, 
                                   double medium_threshold, 
                                   double high_threshold);

    /**
     * @brief Enable or disable automatic response execution
     * @param enabled Whether to automatically execute responses
     */
    void set_auto_response_enabled(bool enabled);

    /**
     * @brief Set maximum number of concurrent responses
     * @param max_concurrent Maximum concurrent response actions
     */
    void set_max_concurrent_responses(size_t max_concurrent);

private:
    /**
     * @brief Main threat processing loop
     */
    void threat_processing_loop();

    /**
     * @brief Assess threat severity and determine response
     * @param threat Threat event to assess
     * @return Response decision
     */
    ResponseDecision assess_threat(const ThreatEvent& threat);

    /**
     * @brief Execute response decision
     * @param decision Response decision to execute
     * @return true if execution successful
     */
    bool execute_response(const ResponseDecision& decision);

    /**
     * @brief Calculate threat severity based on multiple factors
     * @param threat Threat to assess
     * @return Severity score (0.0-1.0)
     */
    double calculate_threat_severity(const ThreatEvent& threat);

    /**
     * @brief Determine appropriate response actions for threat
     * @param threat Threat event
     * @param severity Calculated severity score
     * @return Vector of action names to execute
     */
    std::vector<std::string> determine_response_actions(const ThreatEvent& threat, 
                                                       double severity);

    /**
     * @brief Update system health metrics
     */
    void update_health_metrics();

    /**
     * @brief Generate unique threat ID
     * @return Unique threat identifier
     */
    std::string generate_threat_id();

    /**
     * @brief Cleanup expired threats from active list
     */
    void cleanup_expired_threats();

private:
    std::shared_ptr<BehavioralProfiler> behavioral_profiler_;
    std::shared_ptr<response::ResponseActionsManager> response_manager_;
    
    // Threading and synchronization
    std::atomic<bool> running_;
    std::thread processing_thread_;
    mutable std::mutex threats_mutex_;
    mutable std::mutex health_mutex_;
    std::condition_variable threat_condition_;
    
    // Threat processing
    std::queue<ThreatEvent> threat_queue_;
    std::unordered_map<std::string, ThreatEvent> active_threats_;
    std::unordered_map<std::string, ResponseDecision> pending_responses_;
    
    // Configuration
    double low_severity_threshold_;
    double medium_severity_threshold_;
    double high_severity_threshold_;
    bool auto_response_enabled_;
    size_t max_concurrent_responses_;
    std::atomic<size_t> active_response_count_;
    
    // Health monitoring
    ImmuneSystemHealth health_metrics_;
    std::chrono::system_clock::time_point last_health_update_;
    
    // Statistics
    std::atomic<size_t> total_threats_processed_;
    std::atomic<size_t> total_responses_executed_;
    std::atomic<size_t> successful_responses_;
    
    // Constants
    static constexpr std::chrono::seconds PROCESSING_INTERVAL{1};
    static constexpr std::chrono::minutes THREAT_EXPIRY_TIME{30};
    static constexpr std::chrono::seconds HEALTH_UPDATE_INTERVAL{10};
    static constexpr size_t MAX_THREAT_QUEUE_SIZE = 1000;
    static constexpr size_t MAX_ACTIVE_THREATS = 100;
};

} // namespace core
} // namespace genesis