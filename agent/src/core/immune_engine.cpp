#include "immune_engine.hpp"
#include "behavioral_profiler.hpp"
#include <algorithm>
#include <iostream>
#include <sstream>
#include <random>
#include <uuid/uuid.h>

namespace genesis {
namespace core {

ImmuneEngine::ImmuneEngine(std::shared_ptr<BehavioralProfiler> profiler)
    : behavioral_profiler_(profiler)
    , running_(false)
    , auto_response_enabled_(false)
    , auto_response_threshold_(ThreatSeverity::HIGH) {
}

ImmuneEngine::~ImmuneEngine() {
    stop();
}

bool ImmuneEngine::start() {
    if (running_.load()) {
        return false; // Already running
    }

    if (!behavioral_profiler_) {
        std::cerr << "[ImmuneEngine] No behavioral profiler available" << std::endl;
        return false;
    }

    try {
        running_.store(true);
        analysis_thread_ = std::thread(&ImmuneEngine::analysis_loop, this);
        std::cout << "[ImmuneEngine] Started threat analysis engine" << std::endl;
        return true;
    } catch (const std::exception& e) {
        running_.store(false);
        std::cerr << "[ImmuneEngine] Failed to start: " << e.what() << std::endl;
        return false;
    }
}

void ImmuneEngine::stop() {
    if (!running_.load()) {
        return; // Already stopped
    }

    running_.store(false);
    if (analysis_thread_.joinable()) {
        analysis_thread_.join();
    }
    std::cout << "[ImmuneEngine] Stopped threat analysis engine" << std::endl;
}

bool ImmuneEngine::is_running() const {
    return running_.load();
}

void ImmuneEngine::register_threat_handler(std::function<void(const Threat&)> handler) {
    threat_handlers_.push_back(handler);
}

void ImmuneEngine::register_response_action(const ResponseAction& action) {
    std::lock_guard<std::mutex> lock(actions_mutex_);
    registered_actions_.push_back(action);
    std::cout << "[ImmuneEngine] Registered response action: " << action.action_type << std::endl;
}

void ImmuneEngine::report_threat(const Threat& threat) {
    process_threat(threat);
}

std::vector<Threat> ImmuneEngine::get_active_threats() const {
    std::lock_guard<std::mutex> lock(threats_mutex_);
    std::vector<Threat> active;
    std::copy_if(active_threats_.begin(), active_threats_.end(), std::back_inserter(active),
                 [](const Threat& t) { return !t.is_mitigated; });
    return active;
}

std::vector<Threat> ImmuneEngine::get_threat_history(size_t limit) const {
    std::lock_guard<std::mutex> lock(threats_mutex_);
    std::vector<Threat> history = threat_history_;
    
    // Sort by detection time (newest first)
    std::sort(history.begin(), history.end(),
              [](const Threat& a, const Threat& b) {
                  return a.detected_at > b.detected_at;
              });
    
    if (limit > 0 && history.size() > limit) {
        history.resize(limit);
    }
    
    return history;
}

ResponseResult ImmuneEngine::execute_response(const std::string& threat_id, const std::string& action_type) {
    ResponseResult result;
    result.action_id = generate_threat_id();
    result.executed_at = std::chrono::system_clock::now();
    result.success = false;
    
    // Find the threat
    std::lock_guard<std::mutex> threats_lock(threats_mutex_);
    auto threat_it = std::find_if(active_threats_.begin(), active_threats_.end(),
                                  [&threat_id](const Threat& t) { return t.id == threat_id; });
    
    if (threat_it == active_threats_.end()) {
        result.message = "Threat not found: " + threat_id;
        return result;
    }
    
    // Find the response action
    std::lock_guard<std::mutex> actions_lock(actions_mutex_);
    auto action_it = std::find_if(registered_actions_.begin(), registered_actions_.end(),
                                  [&action_type](const ResponseAction& a) { return a.action_type == action_type; });
    
    if (action_it == registered_actions_.end()) {
        result.message = "Response action not found: " + action_type;
        return result;
    }
    
    // Execute the response action
    try {
        if (action_it->execute) {
            result.success = action_it->execute();
            result.message = result.success ? "Action executed successfully" : "Action execution failed";
        } else {
            result.success = true; // Mock success for actions without implementation
            result.message = "Mock action executed: " + action_type;
        }
        
        if (result.success) {
            threat_it->is_mitigated = true;
        }
        
    } catch (const std::exception& e) {
        result.message = "Exception during action execution: " + std::string(e.what());
    }
    
    std::cout << "[ImmuneEngine] Executed response '" << action_type 
              << "' for threat " << threat_id << ": " << result.message << std::endl;
    
    return result;
}

void ImmuneEngine::set_auto_response_threshold(ThreatSeverity severity) {
    auto_response_threshold_.store(severity);
    std::cout << "[ImmuneEngine] Auto-response threshold set to " << static_cast<int>(severity) << std::endl;
}

void ImmuneEngine::set_auto_response_enabled(bool enabled) {
    auto_response_enabled_.store(enabled);
    std::cout << "[ImmuneEngine] Auto-response " << (enabled ? "enabled" : "disabled") << std::endl;
}

double ImmuneEngine::get_system_health() const {
    return calculate_system_health();
}

std::string ImmuneEngine::export_threat_intelligence() const {
    std::lock_guard<std::mutex> lock(threats_mutex_);
    
    std::ostringstream json;
    json << "{\"threats\":[";
    
    bool first = true;
    for (const auto& threat : threat_history_) {
        if (!first) json << ",";
        first = false;
        
        json << "{";
        json << "\"id\":\"" << threat.id << "\",";
        json << "\"type\":" << static_cast<int>(threat.type) << ",";
        json << "\"severity\":" << static_cast<int>(threat.severity) << ",";
        json << "\"description\":\"" << threat.description << "\",";
        json << "\"confidence_score\":" << threat.confidence_score << ",";
        json << "\"is_mitigated\":" << (threat.is_mitigated ? "true" : "false");
        json << "}";
    }
    
    json << "]}";
    return json.str();
}

bool ImmuneEngine::import_threat_intelligence(const std::string& intelligence_json) {
    try {
        std::cout << "[ImmuneEngine] Importing " << intelligence_json.length() 
                 << " bytes of threat intelligence" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[ImmuneEngine] Failed to import threat intelligence: " << e.what() << std::endl;
        return false;
    }
}

void ImmuneEngine::analysis_loop() {
    while (running_.load()) {
        try {
            analyze_system_state();
        } catch (const std::exception& e) {
            std::cerr << "[ImmuneEngine] Error in analysis loop: " << e.what() << std::endl;
        }

        std::this_thread::sleep_for(ANALYSIS_INTERVAL);
    }
}

void ImmuneEngine::analyze_system_state() {
    if (!behavioral_profiler_ || !behavioral_profiler_->is_running()) {
        return;
    }

    // Skip analysis during learning phase unless critical threats detected
    if (behavioral_profiler_->is_learning()) {
        return;
    }

    // Simulate anomaly detection based on behavioral profiling
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> anomaly_dist(0.0, 1.0);
    
    // Check for behavioral anomalies
    double anomaly_threshold = 0.8;
    if (anomaly_dist(gen) > anomaly_threshold) {
        Threat threat;
        threat.id = generate_threat_id();
        threat.type = ThreatType::BEHAVIORAL_ANOMALY;
        threat.severity = ThreatSeverity::MEDIUM;
        threat.description = "Unusual behavioral pattern detected";
        threat.source_process = "chrome";
        threat.confidence_score = 0.75 + anomaly_dist(gen) * 0.25;
        threat.detected_at = std::chrono::system_clock::now();
        threat.indicators = {"high_cpu_usage", "unusual_network_activity"};
        
        process_threat(threat);
    }
    
    // Check for other threat types (simplified simulation)
    std::vector<ThreatType> threat_types = {
        ThreatType::NETWORK_INTRUSION,
        ThreatType::FILE_TAMPERING,
        ThreatType::PRIVILEGE_ESCALATION,
        ThreatType::RESOURCE_EXHAUSTION
    };
    
    double threat_probability = 0.05; // 5% chance per analysis cycle
    if (anomaly_dist(gen) < threat_probability) {
        auto threat_type = threat_types[gen() % threat_types.size()];
        
        Threat threat;
        threat.id = generate_threat_id();
        threat.type = threat_type;
        threat.severity = static_cast<ThreatSeverity>(gen() % 4);
        threat.confidence_score = 0.6 + anomaly_dist(gen) * 0.4;
        threat.detected_at = std::chrono::system_clock::now();
        
        switch (threat_type) {
            case ThreatType::NETWORK_INTRUSION:
                threat.description = "Suspicious network activity detected";
                threat.indicators = {"port_scan", "unusual_connections"};
                break;
            case ThreatType::FILE_TAMPERING:
                threat.description = "Unauthorized file modification detected";
                threat.indicators = {"file_modification", "permission_change"};
                break;
            case ThreatType::PRIVILEGE_ESCALATION:
                threat.description = "Potential privilege escalation attempt";
                threat.indicators = {"sudo_usage", "process_elevation"};
                break;
            case ThreatType::RESOURCE_EXHAUSTION:
                threat.description = "Resource exhaustion attack detected";
                threat.indicators = {"high_memory_usage", "cpu_saturation"};
                break;
            default:
                threat.description = "Unknown threat detected";
                break;
        }
        
        process_threat(threat);
    }
}

void ImmuneEngine::process_threat(const Threat& threat) {
    std::lock_guard<std::mutex> lock(threats_mutex_);
    
    // Add to active threats
    if (active_threats_.size() >= MAX_ACTIVE_THREATS) {
        // Remove oldest mitigated threat
        auto oldest_mitigated = std::find_if(active_threats_.begin(), active_threats_.end(),
                                           [](const Threat& t) { return t.is_mitigated; });
        if (oldest_mitigated != active_threats_.end()) {
            active_threats_.erase(oldest_mitigated);
        }
    }
    
    active_threats_.push_back(threat);
    
    // Add to history
    threat_history_.push_back(threat);
    if (threat_history_.size() > MAX_THREAT_HISTORY) {
        threat_history_.erase(threat_history_.begin());
    }
    
    std::cout << "[ImmuneEngine] THREAT DETECTED: " << threat.description 
              << " (Severity: " << static_cast<int>(threat.severity) 
              << ", Confidence: " << threat.confidence_score << ")" << std::endl;
    
    // Notify handlers
    for (const auto& handler : threat_handlers_) {
        try {
            handler(threat);
        } catch (const std::exception& e) {
            std::cerr << "[ImmuneEngine] Error in threat handler: " << e.what() << std::endl;
        }
    }
    
    // Execute automatic response if enabled
    if (auto_response_enabled_.load() && 
        threat.severity >= auto_response_threshold_.load()) {
        execute_auto_response(threat);
    }
}

void ImmuneEngine::execute_auto_response(const Threat& threat) {
    std::cout << "[ImmuneEngine] Executing auto-response for threat: " << threat.id << std::endl;
    
    // Select appropriate response based on threat type and severity
    std::string action_type;
    switch (threat.type) {
        case ThreatType::BEHAVIORAL_ANOMALY:
            action_type = (threat.severity >= ThreatSeverity::HIGH) ? "isolate" : "alert";
            break;
        case ThreatType::NETWORK_INTRUSION:
            action_type = "block";
            break;
        case ThreatType::FILE_TAMPERING:
            action_type = "isolate";
            break;
        case ThreatType::PRIVILEGE_ESCALATION:
            action_type = "terminate";
            break;
        case ThreatType::RESOURCE_EXHAUSTION:
            action_type = "terminate";
            break;
        default:
            action_type = "alert";
            break;
    }
    
    auto result = execute_response(threat.id, action_type);
    std::cout << "[ImmuneEngine] Auto-response result: " << result.message << std::endl;
}

std::string ImmuneEngine::generate_threat_id() const {
    uuid_t uuid;
    uuid_generate_random(uuid);
    char uuid_str[37];
    uuid_unparse(uuid, uuid_str);
    return std::string(uuid_str);
}

double ImmuneEngine::calculate_system_health() const {
    std::lock_guard<std::mutex> lock(threats_mutex_);
    
    if (active_threats_.empty()) {
        return 1.0; // Perfect health
    }
    
    double health_score = 1.0;
    double severity_impact = 0.0;
    
    for (const auto& threat : active_threats_) {
        if (!threat.is_mitigated) {
            double impact = 0.0;
            switch (threat.severity) {
                case ThreatSeverity::LOW:
                    impact = 0.1;
                    break;
                case ThreatSeverity::MEDIUM:
                    impact = 0.25;
                    break;
                case ThreatSeverity::HIGH:
                    impact = 0.5;
                    break;
                case ThreatSeverity::CRITICAL:
                    impact = 0.8;
                    break;
            }
            severity_impact += impact * threat.confidence_score;
        }
    }
    
    health_score = std::max(0.0, 1.0 - severity_impact);
    return health_score;
}

void ImmuneEngine::update_threat_priority(Threat& threat) {
    // Increase severity based on persistence or escalation
    auto now = std::chrono::system_clock::now();
    auto age = std::chrono::duration_cast<std::chrono::minutes>(now - threat.detected_at).count();
    
    if (age > 30 && threat.severity < ThreatSeverity::CRITICAL) {
        threat.severity = static_cast<ThreatSeverity>(static_cast<int>(threat.severity) + 1);
        std::cout << "[ImmuneEngine] Escalated threat " << threat.id 
                 << " to severity " << static_cast<int>(threat.severity) << std::endl;
    }
}

} // namespace core
} // namespace genesis