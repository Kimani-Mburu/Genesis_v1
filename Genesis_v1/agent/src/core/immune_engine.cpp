#include "immune_engine.hpp"
#include <iostream>
#include <random>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace genesis {
namespace core {

ImmuneEngine::ImmuneEngine(std::shared_ptr<BehavioralProfiler> profiler,
                          std::shared_ptr<response::ResponseActionsManager> response_manager)
    : behavioral_profiler_(profiler)
    , response_manager_(response_manager)
    , running_(false)
    , low_severity_threshold_(0.3)
    , medium_severity_threshold_(0.6)
    , high_severity_threshold_(0.8)
    , auto_response_enabled_(true)
    , max_concurrent_responses_(5)
    , active_response_count_(0)
    , last_health_update_(std::chrono::system_clock::now())
    , total_threats_processed_(0)
    , total_responses_executed_(0)
    , successful_responses_(0) {
    
    // Initialize health metrics
    health_metrics_.last_updated = std::chrono::system_clock::now();
}

ImmuneEngine::~ImmuneEngine() {
    stop();
}

bool ImmuneEngine::start() {
    if (running_.load()) {
        return false; // Already running
    }

    if (!behavioral_profiler_ || !response_manager_) {
        std::cerr << "[ImmuneEngine] Missing required components" << std::endl;
        return false;
    }

    try {
        running_.store(true);
        processing_thread_ = std::thread(&ImmuneEngine::threat_processing_loop, this);
        
        std::cout << "[ImmuneEngine] Started threat assessment and response coordination" << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        running_.store(false);
        std::cerr << "[ImmuneEngine] Failed to start: " << e.what() << std::endl;
        return false;
    }
}

void ImmuneEngine::stop() {
    if (!running_.load()) {
        return;
    }

    running_.store(false);
    threat_condition_.notify_all();
    
    if (processing_thread_.joinable()) {
        processing_thread_.join();
    }
    
    std::cout << "[ImmuneEngine] Stopped threat processing" << std::endl;
}

bool ImmuneEngine::is_running() const {
    return running_.load();
}

std::string ImmuneEngine::report_threat(const BehaviorPattern& pattern, 
                                       double anomaly_score,
                                       const std::string& source) {
    if (!running_.load()) {
        return "";
    }

    std::lock_guard<std::mutex> lock(threats_mutex_);
    
    // Check queue capacity
    if (threat_queue_.size() >= MAX_THREAT_QUEUE_SIZE) {
        std::cerr << "[ImmuneEngine] Threat queue full, dropping threat report" << std::endl;
        return "";
    }

    // Create threat event
    ThreatEvent threat;
    threat.threat_id = generate_threat_id();
    threat.anomaly_score = anomaly_score;
    threat.detected_at = std::chrono::system_clock::now();
    threat.triggering_pattern = pattern;
    threat.source_process = pattern.process_name;
    
    // Determine threat type and description based on pattern
    if (std::find_if(pattern.file_accesses.begin(), pattern.file_accesses.end(),
                    [](const std::string& access) {
                        return access.find("SUSPICIOUS_CMD") != std::string::npos;
                    }) != pattern.file_accesses.end()) {
        threat.threat_type = "suspicious_command_execution";
        threat.description = "Process executing suspicious commands";
    } else if (std::find_if(pattern.file_accesses.begin(), pattern.file_accesses.end(),
                           [](const std::string& access) {
                               return access.find("ROOT_PROCESS") != std::string::npos;
                           }) != pattern.file_accesses.end()) {
        threat.threat_type = "privilege_elevation";
        threat.description = "Process running with root privileges";
    } else if (pattern.cpu_usage > 90.0) {
        threat.threat_type = "resource_abuse";
        threat.description = "Process consuming excessive CPU resources";
    } else if (pattern.network_connections.size() > 10) {
        threat.threat_type = "network_anomaly";
        threat.description = "Process establishing excessive network connections";
    } else {
        threat.threat_type = "behavioral_anomaly";
        threat.description = "Process exhibiting anomalous behavior";
    }

    // Calculate initial severity
    threat.severity_score = calculate_threat_severity(threat);

    // Add to processing queue
    threat_queue_.push(threat);
    threat_condition_.notify_one();

    std::cout << "[ImmuneEngine] Reported threat " << threat.threat_id 
             << " (severity: " << std::fixed << std::setprecision(2) << threat.severity_score << ")" << std::endl;

    return threat.threat_id;
}

ImmuneSystemHealth ImmuneEngine::get_system_health() const {
    std::lock_guard<std::mutex> lock(health_mutex_);
    return health_metrics_;
}

std::vector<ThreatEvent> ImmuneEngine::get_active_threats() const {
    std::lock_guard<std::mutex> lock(threats_mutex_);
    
    std::vector<ThreatEvent> threats;
    for (const auto& [id, threat] : active_threats_) {
        threats.push_back(threat);
    }
    
    return threats;
}

bool ImmuneEngine::trigger_response(const std::string& threat_id, bool force_execute) {
    std::lock_guard<std::mutex> lock(threats_mutex_);
    
    auto it = active_threats_.find(threat_id);
    if (it == active_threats_.end()) {
        std::cerr << "[ImmuneEngine] Threat not found: " << threat_id << std::endl;
        return false;
    }

    // Assess the threat and create response decision
    ResponseDecision decision = assess_threat(it->second);
    decision.requires_human_approval = !force_execute && decision.requires_human_approval;

    if (decision.requires_human_approval && !force_execute) {
        std::cout << "[ImmuneEngine] Response for " << threat_id 
                 << " requires human approval" << std::endl;
        pending_responses_[threat_id] = decision;
        return false;
    }

    return execute_response(decision);
}

void ImmuneEngine::update_severity_thresholds(double low_threshold, 
                                             double medium_threshold, 
                                             double high_threshold) {
    if (low_threshold >= 0.0 && low_threshold <= 1.0 &&
        medium_threshold >= 0.0 && medium_threshold <= 1.0 &&
        high_threshold >= 0.0 && high_threshold <= 1.0 &&
        low_threshold < medium_threshold && medium_threshold < high_threshold) {
        
        low_severity_threshold_ = low_threshold;
        medium_severity_threshold_ = medium_threshold;
        high_severity_threshold_ = high_threshold;
        
        std::cout << "[ImmuneEngine] Updated severity thresholds: " 
                 << low_threshold << "/" << medium_threshold << "/" << high_threshold << std::endl;
    } else {
        std::cerr << "[ImmuneEngine] Invalid severity thresholds" << std::endl;
    }
}

void ImmuneEngine::set_auto_response_enabled(bool enabled) {
    auto_response_enabled_ = enabled;
    std::cout << "[ImmuneEngine] Auto-response " << (enabled ? "enabled" : "disabled") << std::endl;
}

void ImmuneEngine::set_max_concurrent_responses(size_t max_concurrent) {
    max_concurrent_responses_ = max_concurrent;
    std::cout << "[ImmuneEngine] Max concurrent responses set to " << max_concurrent << std::endl;
}

void ImmuneEngine::threat_processing_loop() {
    while (running_.load()) {
        try {
            std::unique_lock<std::mutex> lock(threats_mutex_);
            
            // Wait for threats or timeout
            threat_condition_.wait_for(lock, PROCESSING_INTERVAL, 
                                     [this] { return !threat_queue_.empty() || !running_.load(); });
            
            if (!running_.load()) {
                break;
            }

            // Process all queued threats
            while (!threat_queue_.empty() && running_.load()) {
                ThreatEvent threat = threat_queue_.front();
                threat_queue_.pop();

                // Check if we already have too many active threats
                if (active_threats_.size() >= MAX_ACTIVE_THREATS) {
                    cleanup_expired_threats();
                    if (active_threats_.size() >= MAX_ACTIVE_THREATS) {
                        std::cerr << "[ImmuneEngine] Too many active threats, dropping: " 
                                 << threat.threat_id << std::endl;
                        continue;
                    }
                }

                // Add to active threats
                active_threats_[threat.threat_id] = threat;
                total_threats_processed_++;

                lock.unlock(); // Release lock for assessment and response

                try {
                    // Assess threat and determine response
                    ResponseDecision decision = assess_threat(threat);

                    // Execute response if auto-response is enabled and conditions are met
                    if (auto_response_enabled_ && !decision.requires_human_approval &&
                        active_response_count_.load() < max_concurrent_responses_) {
                        
                        execute_response(decision);
                    } else if (!auto_response_enabled_ || decision.requires_human_approval) {
                        // Store for manual approval
                        std::lock_guard<std::mutex> pending_lock(threats_mutex_);
                        pending_responses_[threat.threat_id] = decision;
                        
                        std::cout << "[ImmuneEngine] Response for " << threat.threat_id 
                                 << " requires " << (decision.requires_human_approval ? 
                                    "human approval" : "manual trigger") << std::endl;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "[ImmuneEngine] Error processing threat " 
                             << threat.threat_id << ": " << e.what() << std::endl;
                }

                lock.lock(); // Reacquire lock for next iteration
            }

            lock.unlock();

            // Update health metrics periodically
            auto now = std::chrono::system_clock::now();
            if ((now - last_health_update_) >= HEALTH_UPDATE_INTERVAL) {
                update_health_metrics();
                last_health_update_ = now;
            }

            // Cleanup expired threats
            cleanup_expired_threats();

        } catch (const std::exception& e) {
            std::cerr << "[ImmuneEngine] Error in processing loop: " << e.what() << std::endl;
            std::this_thread::sleep_for(PROCESSING_INTERVAL);
        }
    }
}

ResponseDecision ImmuneEngine::assess_threat(const ThreatEvent& threat) {
    ResponseDecision decision;
    decision.threat_id = threat.threat_id;
    decision.decision_time = std::chrono::system_clock::now();
    
    // Calculate final severity considering multiple factors
    double severity = calculate_threat_severity(threat);
    decision.confidence_level = std::min(1.0, threat.anomaly_score + 0.2);

    // Determine response actions based on severity
    decision.actions_to_execute = determine_response_actions(threat, severity);

    // Build rationale
    std::ostringstream rationale;
    rationale << "Threat type: " << threat.threat_type 
             << ", Severity: " << std::fixed << std::setprecision(2) << severity
             << ", Anomaly score: " << threat.anomaly_score
             << ", Process: " << threat.source_process;
    decision.rationale = rationale.str();

    // Determine if human approval is required
    decision.requires_human_approval = (severity >= high_severity_threshold_) ||
                                      (threat.threat_type == "privilege_elevation" && severity >= medium_severity_threshold_) ||
                                      (decision.actions_to_execute.size() > 2);

    return decision;
}

bool ImmuneEngine::execute_response(const ResponseDecision& decision) {
    if (decision.actions_to_execute.empty()) {
        return true; // Nothing to execute
    }

    active_response_count_++;
    total_responses_executed_++;

    std::cout << "[ImmuneEngine] Executing response for " << decision.threat_id 
             << " with " << decision.actions_to_execute.size() << " actions" << std::endl;

    bool overall_success = true;
    size_t successful_actions = 0;

    // Find the threat to get context
    response::ActionContext context;
    {
        std::lock_guard<std::mutex> lock(threats_mutex_);
        auto it = active_threats_.find(decision.threat_id);
        if (it != active_threats_.end()) {
            const ThreatEvent& threat = it->second;
            context.threat_description = threat.description;
            context.target_process = threat.source_process;
            context.target_pid = threat.source_pid;
            context.target_ip = threat.source_ip;
            context.target_file = threat.source_file;
            context.threat_severity = threat.severity_score;
            context.detected_at = threat.detected_at;
            context.detection_source = "immune_engine";
        }
    }

    // Execute each action
    for (const std::string& action : decision.actions_to_execute) {
        try {
            auto result = response_manager_->execute_action(action, context);
            if (result.success) {
                successful_actions++;
                std::cout << "[ImmuneEngine] Action '" << action << "' completed successfully" << std::endl;
            } else {
                std::cerr << "[ImmuneEngine] Action '" << action << "' failed: " << result.error_message << std::endl;
                overall_success = false;
            }
        } catch (const std::exception& e) {
            std::cerr << "[ImmuneEngine] Exception executing action '" << action << "': " << e.what() << std::endl;
            overall_success = false;
        }
    }

    if (overall_success) {
        successful_responses_++;
    }

    active_response_count_--;

    std::cout << "[ImmuneEngine] Response execution completed for " << decision.threat_id 
             << " (" << successful_actions << "/" << decision.actions_to_execute.size() 
             << " actions successful)" << std::endl;

    return overall_success;
}

double ImmuneEngine::calculate_threat_severity(const ThreatEvent& threat) {
    double severity = threat.anomaly_score;

    // Adjust severity based on threat type
    if (threat.threat_type == "privilege_elevation") {
        severity += 0.3; // High concern for privilege escalation
    } else if (threat.threat_type == "suspicious_command_execution") {
        severity += 0.4; // Very high concern for suspicious commands
    } else if (threat.threat_type == "resource_abuse") {
        severity += 0.2; // Moderate concern for resource abuse
    } else if (threat.threat_type == "network_anomaly") {
        severity += 0.25; // Moderate-high concern for network anomalies
    }

    // Adjust based on process behavior
    if (threat.triggering_pattern.cpu_usage > 80.0) {
        severity += 0.1;
    }
    if (threat.triggering_pattern.memory_usage > 1000.0) { // > 1GB
        severity += 0.1;
    }
    if (threat.triggering_pattern.network_connections.size() > 5) {
        severity += 0.15;
    }

    // Consider system context
    {
        std::lock_guard<std::mutex> lock(health_mutex_);
        if (health_metrics_.overall_threat_level > 0.7) {
            severity += 0.1; // System under high threat - be more aggressive
        }
    }

    return std::min(1.0, severity);
}

std::vector<std::string> ImmuneEngine::determine_response_actions(const ThreatEvent& threat, 
                                                                 double severity) {
    std::vector<std::string> actions;

    // Always alert for any threat
    actions.push_back("alert");

    if (severity >= low_severity_threshold_) {
        // Low severity - monitor more closely
        if (threat.threat_type == "resource_abuse") {
            actions.push_back("isolate"); // Limit resource usage
        }
    }

    if (severity >= medium_severity_threshold_) {
        // Medium severity - more aggressive response
        if (threat.threat_type == "suspicious_command_execution") {
            actions.push_back("suspend"); // Stop suspicious execution
        } else if (threat.threat_type == "network_anomaly") {
            actions.push_back("block"); // Block network access
        } else if (threat.threat_type == "privilege_elevation") {
            actions.push_back("isolate"); // Contain privileged process
        }
    }

    if (severity >= high_severity_threshold_) {
        // High severity - terminate threats
        if (threat.threat_type == "suspicious_command_execution" || 
            threat.threat_type == "privilege_elevation") {
            actions.push_back("terminate"); // Stop dangerous process
        }
        
        // Quarantine any suspicious files
        if (!threat.source_file.empty()) {
            actions.push_back("quarantine");
        }
    }

    return actions;
}

void ImmuneEngine::update_health_metrics() {
    std::lock_guard<std::mutex> health_lock(health_mutex_);
    std::lock_guard<std::mutex> threats_lock(threats_mutex_);

    health_metrics_.active_threats = active_threats_.size();
    health_metrics_.responses_executed = total_responses_executed_.load();
    health_metrics_.successful_responses = successful_responses_.load();

    // Calculate overall threat level
    double threat_level = 0.0;
    for (const auto& [id, threat] : active_threats_) {
        threat_level += threat.severity_score;
    }
    
    if (!active_threats_.empty()) {
        threat_level /= active_threats_.size();
    }
    health_metrics_.overall_threat_level = threat_level;

    // Calculate false positive rate (simplified)
    if (health_metrics_.responses_executed > 0) {
        health_metrics_.false_positive_rate = 
            1.0 - (double(health_metrics_.successful_responses) / double(health_metrics_.responses_executed));
    }

    // Estimate system load impact (placeholder)
    health_metrics_.system_load_impact = std::min(1.0, double(active_threats_.size()) / 50.0);

    health_metrics_.last_updated = std::chrono::system_clock::now();
}

std::string ImmuneEngine::generate_threat_id() {
    static std::atomic<size_t> counter(0);
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    
    std::ostringstream oss;
    oss << "THREAT_" << timestamp << "_" << counter.fetch_add(1);
    return oss.str();
}

void ImmuneEngine::cleanup_expired_threats() {
    auto now = std::chrono::system_clock::now();
    
    for (auto it = active_threats_.begin(); it != active_threats_.end();) {
        if ((now - it->second.detected_at) > THREAT_EXPIRY_TIME) {
            std::cout << "[ImmuneEngine] Removing expired threat: " << it->first << std::endl;
            pending_responses_.erase(it->first);
            it = active_threats_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace core
} // namespace genesis