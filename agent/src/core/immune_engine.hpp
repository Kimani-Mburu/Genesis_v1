#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <mutex>
#include <atomic>
#include <functional>
#include <queue>
#include <thread>

namespace genesis {
namespace core {

// Forward declaration
class BehavioralProfiler;

/**
 * @brief Severity levels for detected threats
 */
enum class ThreatSeverity {
    LOW = 0,
    MEDIUM = 1,
    HIGH = 2,
    CRITICAL = 3
};

/**
 * @brief Types of threats that can be detected
 */
enum class ThreatType {
    BEHAVIORAL_ANOMALY,
    NETWORK_INTRUSION,
    FILE_TAMPERING,
    PRIVILEGE_ESCALATION,
    RESOURCE_EXHAUSTION,
    UNKNOWN
};

/**
 * @brief Represents a detected threat
 */
struct Threat {
    std::string id;
    ThreatType type;
    ThreatSeverity severity;
    std::string description;
    std::string source_process;
    std::string target_resource;
    double confidence_score;
    std::chrono::system_clock::time_point detected_at;
    std::vector<std::string> indicators;
    bool is_mitigated = false;
};

/**
 * @brief Response action that can be taken against a threat
 */
struct ResponseAction {
    std::string action_id;
    std::string action_type; // "isolate", "terminate", "block", "alert"
    std::string target;
    std::string description;
    std::function<bool()> execute;
    std::chrono::seconds timeout{30};
};

/**
 * @brief Result of executing a response action
 */
struct ResponseResult {
    std::string action_id;
    bool success;
    std::string message;
    std::chrono::system_clock::time_point executed_at;
};

/**
 * @brief ImmuneEngine detects anomalies and coordinates threat responses
 * 
 * This component mimics the biological immune system's ability to detect
 * and respond to foreign pathogens. It analyzes behavioral patterns from
 * the BehavioralProfiler and coordinates appropriate defensive responses.
 */
class ImmuneEngine {
public:
    /**
     * @brief Constructor
     * @param profiler Shared pointer to the behavioral profiler
     */
    explicit ImmuneEngine(std::shared_ptr<BehavioralProfiler> profiler);

    /**
     * @brief Destructor
     */
    ~ImmuneEngine();

    /**
     * @brief Start the immune engine
     * @return true if successfully started, false otherwise
     */
    bool start();

    /**
     * @brief Stop the immune engine
     */
    void stop();

    /**
     * @brief Check if the engine is currently running
     * @return true if running, false otherwise
     */
    bool is_running() const;

    /**
     * @brief Register a threat detection handler
     * @param handler Function to call when a threat is detected
     */
    void register_threat_handler(std::function<void(const Threat&)> handler);

    /**
     * @brief Register a response action
     * @param action Response action to register
     */
    void register_response_action(const ResponseAction& action);

    /**
     * @brief Manually report a threat to the immune engine
     * @param threat Threat information
     */
    void report_threat(const Threat& threat);

    /**
     * @brief Get all active threats
     * @return Vector of currently active threats
     */
    std::vector<Threat> get_active_threats() const;

    /**
     * @brief Get threat history
     * @param limit Maximum number of threats to return (0 = all)
     * @return Vector of historical threats
     */
    std::vector<Threat> get_threat_history(size_t limit = 100) const;

    /**
     * @brief Execute response to a specific threat
     * @param threat_id ID of the threat to respond to
     * @param action_type Type of action to execute
     * @return Response result
     */
    ResponseResult execute_response(const std::string& threat_id, 
                                   const std::string& action_type);

    /**
     * @brief Set automatic response threshold
     * @param severity Minimum severity level for automatic responses
     */
    void set_auto_response_threshold(ThreatSeverity severity);

    /**
     * @brief Enable or disable automatic responses
     * @param enabled True to enable automatic responses
     */
    void set_auto_response_enabled(bool enabled);

    /**
     * @brief Get system health status
     * @return Health score (0.0 = compromised, 1.0 = healthy)
     */
    double get_system_health() const;

    /**
     * @brief Export threat intelligence for sharing
     * @return JSON string containing threat intelligence
     */
    std::string export_threat_intelligence() const;

    /**
     * @brief Import threat intelligence from other instances
     * @param intelligence_json JSON string containing threat intelligence
     * @return true if successfully imported, false otherwise
     */
    bool import_threat_intelligence(const std::string& intelligence_json);

private:
    /**
     * @brief Main analysis loop
     */
    void analysis_loop();

    /**
     * @brief Analyze current system state for threats
     */
    void analyze_system_state();

    /**
     * @brief Process a detected threat
     * @param threat The threat to process
     */
    void process_threat(const Threat& threat);

    /**
     * @brief Execute automatic response if enabled and appropriate
     * @param threat The threat that triggered the response
     */
    void execute_auto_response(const Threat& threat);

    /**
     * @brief Generate unique threat ID
     * @return Unique threat identifier
     */
    std::string generate_threat_id() const;

    /**
     * @brief Calculate system health based on current threats
     * @return Health score
     */
    double calculate_system_health() const;

    /**
     * @brief Update threat priority based on system state
     * @param threat Threat to update
     */
    void update_threat_priority(Threat& threat);

private:
    std::shared_ptr<BehavioralProfiler> behavioral_profiler_;
    
    mutable std::mutex threats_mutex_;
    std::vector<Threat> active_threats_;
    std::vector<Threat> threat_history_;
    
    mutable std::mutex actions_mutex_;
    std::vector<ResponseAction> registered_actions_;
    
    std::vector<std::function<void(const Threat&)>> threat_handlers_;
    
    std::atomic<bool> running_;
    std::thread analysis_thread_;
    
    std::atomic<bool> auto_response_enabled_;
    std::atomic<ThreatSeverity> auto_response_threshold_;
    
    // Configuration
    static constexpr size_t MAX_THREAT_HISTORY = 1000;
    static constexpr size_t MAX_ACTIVE_THREATS = 100;
    static constexpr std::chrono::seconds ANALYSIS_INTERVAL{2};
    static constexpr double DEFAULT_CONFIDENCE_THRESHOLD = 0.6;
};

} // namespace core
} // namespace genesis