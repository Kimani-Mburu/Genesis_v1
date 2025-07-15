#include "core/system_monitor.hpp"
#include "core/behavioral_profiler.hpp"
#include "core/immune_engine.hpp"
#include "response/response_actions.hpp"
#include <iostream>
#include <memory>
#include <signal.h>
#include <unistd.h>
#include <chrono>
#include <thread>

using namespace genesis;

// Global flag for graceful shutdown
std::atomic<bool> shutdown_requested(false);

// Signal handler for graceful shutdown
void signal_handler(int signal) {
    std::cout << "\n[GENESIS] Received signal " << signal << ", initiating graceful shutdown..." << std::endl;
    shutdown_requested.store(true);
}

// Configuration structure
struct GenesisConfig {
    bool dry_run_mode = false;
    bool auto_response_enabled = true;
    std::string log_level = "INFO";
    size_t max_concurrent_responses = 5;
    double low_severity_threshold = 0.3;
    double medium_severity_threshold = 0.6;
    double high_severity_threshold = 0.8;
    std::chrono::seconds status_report_interval{30};
};

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --help              Show this help message" << std::endl;
    std::cout << "  --dry-run           Run in dry-run mode (no actual responses)" << std::endl;
    std::cout << "  --no-auto-response  Disable automatic threat response" << std::endl;
    std::cout << "  --monitor-only      Only monitor, don't respond to threats" << std::endl;
    std::cout << "  --low-threshold T   Set low severity threshold (0.0-1.0)" << std::endl;
    std::cout << "  --med-threshold T   Set medium severity threshold (0.0-1.0)" << std::endl;
    std::cout << "  --high-threshold T  Set high severity threshold (0.0-1.0)" << std::endl;
    std::cout << "  --max-responses N   Maximum concurrent responses" << std::endl;
    std::cout << "  --status-interval S Status report interval in seconds" << std::endl;
}

GenesisConfig parse_arguments(int argc, char* argv[]) {
    GenesisConfig config;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--help") {
            print_usage(argv[0]);
            exit(0);
        } else if (arg == "--dry-run") {
            config.dry_run_mode = true;
        } else if (arg == "--no-auto-response" || arg == "--monitor-only") {
            config.auto_response_enabled = false;
        } else if (arg == "--low-threshold" && i + 1 < argc) {
            config.low_severity_threshold = std::stod(argv[++i]);
        } else if (arg == "--med-threshold" && i + 1 < argc) {
            config.medium_severity_threshold = std::stod(argv[++i]);
        } else if (arg == "--high-threshold" && i + 1 < argc) {
            config.high_severity_threshold = std::stod(argv[++i]);
        } else if (arg == "--max-responses" && i + 1 < argc) {
            config.max_concurrent_responses = std::stoul(argv[++i]);
        } else if (arg == "--status-interval" && i + 1 < argc) {
            config.status_report_interval = std::chrono::seconds(std::stoi(argv[++i]));
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            print_usage(argv[0]);
            exit(1);
        }
    }
    
    return config;
}

void print_status_report(const std::shared_ptr<core::BehavioralProfiler>& profiler,
                        const std::shared_ptr<core::ImmuneEngine>& immune_engine,
                        const std::shared_ptr<response::ResponseActionsManager>& response_manager) {
    
    std::cout << "\n=== GENESIS Status Report ===" << std::endl;
    
    // Behavioral Profiler Status
    if (profiler && profiler->is_running()) {
        std::cout << "Behavioral Profiler: RUNNING" << std::endl;
        std::cout << "  Monitored Processes: " << profiler->get_monitored_process_count() << std::endl;
        std::cout << "  Learning Mode: " << (profiler->is_learning() ? "YES" : "NO") << std::endl;
    } else {
        std::cout << "Behavioral Profiler: STOPPED" << std::endl;
    }
    
    // Immune Engine Status
    if (immune_engine && immune_engine->is_running()) {
        auto health = immune_engine->get_system_health();
        auto active_threats = immune_engine->get_active_threats();
        
        std::cout << "Immune Engine: RUNNING" << std::endl;
        std::cout << "  Active Threats: " << health.active_threats << std::endl;
        std::cout << "  Overall Threat Level: " << std::fixed << std::setprecision(2) 
                 << health.overall_threat_level << std::endl;
        std::cout << "  Responses Executed: " << health.responses_executed << std::endl;
        std::cout << "  Success Rate: " << std::fixed << std::setprecision(1) 
                 << (health.responses_executed > 0 ? 
                     (double(health.successful_responses) / health.responses_executed * 100.0) : 0.0) 
                 << "%" << std::endl;
        
        if (!active_threats.empty()) {
            std::cout << "  Recent Threats:" << std::endl;
            for (const auto& threat : active_threats) {
                std::cout << "    - " << threat.threat_type << " (severity: " 
                         << std::fixed << std::setprecision(2) << threat.severity_score << ")" << std::endl;
            }
        }
    } else {
        std::cout << "Immune Engine: STOPPED" << std::endl;
    }
    
    // Response Actions Status
    if (response_manager) {
        auto stats = response_manager->get_action_statistics();
        std::cout << "Response Actions: AVAILABLE" << std::endl;
        std::cout << "  Available Actions: " << stats.size() << std::endl;
        
        for (const auto& [action, stat] : stats) {
            if (stat.first > 0) { // Only show actions that have been used
                std::cout << "    " << action << ": " << stat.first << " executions, " 
                         << stat.second << " successful" << std::endl;
            }
        }
    }
    
    std::cout << "=============================\n" << std::endl;
}

int main(int argc, char* argv[]) {
    std::cout << "=== GENESIS Agent v1.0 ===" << std::endl;
    std::cout << "Adaptive Cybersecurity System" << std::endl;
    std::cout << "===========================\n" << std::endl;
    
    // Parse command line arguments
    GenesisConfig config = parse_arguments(argc, argv);
    
    // Set up signal handlers for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    try {
        std::cout << "[GENESIS] Initializing system components..." << std::endl;
        
        // Initialize System Monitor
        auto system_monitor = std::make_shared<core::SystemMonitor>();
        if (!system_monitor->initialize()) {
            std::cerr << "[GENESIS] Failed to initialize system monitor" << std::endl;
            return 1;
        }
        std::cout << "[GENESIS] System monitor initialized" << std::endl;
        
        // Initialize Behavioral Profiler
        auto behavioral_profiler = std::make_shared<core::BehavioralProfiler>(24, 0.1);
        if (!behavioral_profiler->start()) {
            std::cerr << "[GENESIS] Failed to start behavioral profiler" << std::endl;
            return 1;
        }
        std::cout << "[GENESIS] Behavioral profiler started" << std::endl;
        
        // Initialize Response Actions Manager
        auto response_manager = std::make_shared<response::ResponseActionsManager>();
        if (!response_manager->initialize_actions()) {
            std::cerr << "[GENESIS] Failed to initialize response actions" << std::endl;
            return 1;
        }
        
        // Configure response manager
        response_manager->set_dry_run_mode(config.dry_run_mode);
        if (config.dry_run_mode) {
            std::cout << "[GENESIS] Running in DRY-RUN mode - no actual responses will be executed" << std::endl;
        }
        
        std::cout << "[GENESIS] Response actions initialized" << std::endl;
        
        // Initialize Immune Engine
        auto immune_engine = std::make_shared<core::ImmuneEngine>(behavioral_profiler, response_manager);
        immune_engine->update_severity_thresholds(config.low_severity_threshold,
                                                  config.medium_severity_threshold,
                                                  config.high_severity_threshold);
        immune_engine->set_auto_response_enabled(config.auto_response_enabled);
        immune_engine->set_max_concurrent_responses(config.max_concurrent_responses);
        
        if (!immune_engine->start()) {
            std::cerr << "[GENESIS] Failed to start immune engine" << std::endl;
            return 1;
        }
        std::cout << "[GENESIS] Immune engine started" << std::endl;
        
        // Drop privileges if running as root (for security)
        if (getuid() == 0) {
            std::cout << "[GENESIS] Warning: Running as root. Consider dropping privileges in production." << std::endl;
            // response_manager->drop_privileges("genesis", "genesis");
        }
        
        std::cout << "\n[GENESIS] System fully operational!" << std::endl;
        std::cout << "[GENESIS] Monitoring system behavior and threats..." << std::endl;
        std::cout << "[GENESIS] Press Ctrl+C to shutdown gracefully\n" << std::endl;
        
        // Main monitoring loop with integrated threat detection
        auto last_status_report = std::chrono::steady_clock::now();
        
        while (!shutdown_requested.load()) {
            try {
                // Check for anomalous behavior and report to immune engine
                auto processes = system_monitor->get_process_info();
                
                for (const auto& process : processes) {
                    // Convert ProcessInfo to BehaviorPattern
                    core::BehaviorPattern pattern;
                    pattern.process_name = process.name;
                    pattern.cpu_usage = process.cpu_percent;
                    pattern.memory_usage = static_cast<double>(process.memory_bytes) / (1024.0 * 1024.0); // MB
                    pattern.syscall_frequency = process.syscall_count;
                    pattern.timestamp = std::chrono::system_clock::now();
                    
                    // Add network connections
                    pattern.network_connections = process.network_connections;
                    
                    // Add file accesses
                    pattern.file_accesses = process.open_files;
                    
                    // Add security context flags
                    if (process.effective_uid == 0) {
                        pattern.file_accesses.push_back("ROOT_PROCESS");
                    }
                    if (process.uid != process.effective_uid) {
                        pattern.file_accesses.push_back("SUID_PROCESS");
                    }
                    
                    // Check for suspicious command patterns
                    std::vector<std::string> suspicious_patterns = {
                        "sh -c", "bash -c", "eval", "curl", "wget", "nc ", "netcat",
                        "python -c", "perl -e", "ruby -e", "base64", "chmod +x"
                    };
                    
                    for (const auto& suspicious : suspicious_patterns) {
                        if (process.command_line.find(suspicious) != std::string::npos) {
                            pattern.file_accesses.push_back("SUSPICIOUS_CMD:" + suspicious);
                        }
                    }
                    
                    // Feed pattern to behavioral profiler
                    behavioral_profiler->add_behavior_pattern(pattern);
                    
                    // Calculate anomaly score and report threats
                    double anomaly_score = behavioral_profiler->calculate_anomaly_score(pattern);
                    
                    // Report significant anomalies to immune engine
                    if (anomaly_score > 0.5) { // Threshold for reporting
                        std::string threat_id = immune_engine->report_threat(pattern, anomaly_score, "main_monitor");
                        if (!threat_id.empty()) {
                            std::cout << "[GENESIS] Reported threat: " << threat_id 
                                     << " (anomaly: " << std::fixed << std::setprecision(2) << anomaly_score << ")" << std::endl;
                        }
                    }
                }
                
                // Print periodic status reports
                auto now = std::chrono::steady_clock::now();
                if ((now - last_status_report) >= config.status_report_interval) {
                    print_status_report(behavioral_profiler, immune_engine, response_manager);
                    last_status_report = now;
                }
                
                // Sleep before next monitoring cycle
                std::this_thread::sleep_for(std::chrono::seconds(5));
                
            } catch (const std::exception& e) {
                std::cerr << "[GENESIS] Error in main loop: " << e.what() << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
        
        std::cout << "\n[GENESIS] Shutting down system components..." << std::endl;
        
        // Graceful shutdown
        immune_engine->stop();
        behavioral_profiler->stop();
        
        std::cout << "[GENESIS] Shutdown complete" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "[GENESIS] Fatal error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}