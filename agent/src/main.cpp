#include <iostream>
#include <memory>
#include <signal.h>
#include <thread>
#include <chrono>

#include "core/behavioral_profiler.hpp"
#include "core/immune_engine.hpp"

using namespace genesis::core;

// Global flag for graceful shutdown
std::atomic<bool> shutdown_requested(false);

// Signal handler for graceful shutdown
void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nShutdown signal received. Initiating graceful shutdown..." << std::endl;
        shutdown_requested.store(true);
    }
}

void print_banner() {
    std::cout << R"(
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                            GENESIS v1.0                          ║
    ║              Biologically-Inspired Cybersecurity Agent           ║
    ║                                                                   ║
    ║  Adaptive • Decentralized • Intelligent • Collaborative          ║
    ╚═══════════════════════════════════════════════════════════════════╝
    )" << std::endl;
}

void setup_default_response_actions(std::shared_ptr<ImmuneEngine> immune_engine) {
    // Register default response actions
    ResponseAction alert_action;
    alert_action.action_id = "alert";
    alert_action.action_type = "alert";
    alert_action.description = "Send alert notification";
    alert_action.execute = []() -> bool {
        std::cout << "[ResponseAction] ALERT: Threat detected and logged" << std::endl;
        return true;
    };
    
    ResponseAction isolate_action;
    isolate_action.action_id = "isolate";
    isolate_action.action_type = "isolate";
    isolate_action.description = "Isolate suspicious process";
    isolate_action.execute = []() -> bool {
        std::cout << "[ResponseAction] ISOLATE: Process isolated from network" << std::endl;
        return true;
    };
    
    ResponseAction block_action;
    block_action.action_id = "block";
    block_action.action_type = "block";
    block_action.description = "Block network connection";
    block_action.execute = []() -> bool {
        std::cout << "[ResponseAction] BLOCK: Network connection blocked" << std::endl;
        return true;
    };
    
    ResponseAction terminate_action;
    terminate_action.action_id = "terminate";
    terminate_action.action_type = "terminate";
    terminate_action.description = "Terminate malicious process";
    terminate_action.execute = []() -> bool {
        std::cout << "[ResponseAction] TERMINATE: Malicious process terminated" << std::endl;
        return true;
    };
    
    immune_engine->register_response_action(alert_action);
    immune_engine->register_response_action(isolate_action);
    immune_engine->register_response_action(block_action);
    immune_engine->register_response_action(terminate_action);
}

void setup_threat_handlers(std::shared_ptr<ImmuneEngine> immune_engine) {
    // Register threat detection handler
    immune_engine->register_threat_handler([](const Threat& threat) {
        std::cout << "\n🚨 THREAT ALERT 🚨" << std::endl;
        std::cout << "ID: " << threat.id << std::endl;
        std::cout << "Type: " << static_cast<int>(threat.type) << std::endl;
        std::cout << "Severity: " << static_cast<int>(threat.severity) << std::endl;
        std::cout << "Description: " << threat.description << std::endl;
        std::cout << "Confidence: " << (threat.confidence_score * 100) << "%" << std::endl;
        std::cout << "Source Process: " << threat.source_process << std::endl;
        
        if (!threat.indicators.empty()) {
            std::cout << "Indicators: ";
            for (const auto& indicator : threat.indicators) {
                std::cout << indicator << " ";
            }
            std::cout << std::endl;
        }
        std::cout << std::endl;
    });
}

void print_system_status(std::shared_ptr<BehavioralProfiler> profiler, 
                        std::shared_ptr<ImmuneEngine> immune_engine) {
    std::cout << "\n═══════════════ SYSTEM STATUS ═══════════════" << std::endl;
    std::cout << "Behavioral Profiler: " << (profiler->is_running() ? "ACTIVE" : "INACTIVE") << std::endl;
    std::cout << "Immune Engine: " << (immune_engine->is_running() ? "ACTIVE" : "INACTIVE") << std::endl;
    std::cout << "Learning Mode: " << (profiler->is_learning() ? "YES" : "NO") << std::endl;
    std::cout << "Monitored Processes: " << profiler->get_monitored_process_count() << std::endl;
    
    auto active_threats = immune_engine->get_active_threats();
    std::cout << "Active Threats: " << active_threats.size() << std::endl;
    
    double health = immune_engine->get_system_health();
    std::cout << "System Health: " << (health * 100) << "%" << std::endl;
    
    if (health >= 0.8) {
        std::cout << "Status: 🟢 HEALTHY" << std::endl;
    } else if (health >= 0.6) {
        std::cout << "Status: 🟡 DEGRADED" << std::endl;
    } else if (health >= 0.3) {
        std::cout << "Status: 🟠 WARNING" << std::endl;
    } else {
        std::cout << "Status: 🔴 CRITICAL" << std::endl;
    }
    std::cout << "═══════════════════════════════════════════════" << std::endl;
}

int main(int argc, char* argv[]) {
    // Set up signal handlers for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    print_banner();
    
    std::cout << "Initializing GENESIS Agent..." << std::endl;
    
    try {
        // Create behavioral profiler with 24-hour learning window and 10% adaptation rate
        auto behavioral_profiler = std::make_shared<BehavioralProfiler>(24, 0.1);
        
        // Create immune engine
        auto immune_engine = std::make_shared<ImmuneEngine>(behavioral_profiler);
        
        // Setup response actions and threat handlers
        setup_default_response_actions(immune_engine);
        setup_threat_handlers(immune_engine);
        
        // Configure automatic responses
        immune_engine->set_auto_response_threshold(ThreatSeverity::HIGH);
        immune_engine->set_auto_response_enabled(true);
        
        std::cout << "Starting behavioral profiler..." << std::endl;
        if (!behavioral_profiler->start()) {
            std::cerr << "Failed to start behavioral profiler" << std::endl;
            return 1;
        }
        
        std::cout << "Starting immune engine..." << std::endl;
        if (!immune_engine->start()) {
            std::cerr << "Failed to start immune engine" << std::endl;
            behavioral_profiler->stop();
            return 1;
        }
        
        std::cout << "\n✅ GENESIS Agent is now running!" << std::endl;
        std::cout << "Learning phase will last 24 hours. Press Ctrl+C to shutdown gracefully.\n" << std::endl;
        
        // Main monitoring loop
        auto last_status_print = std::chrono::steady_clock::now();
        while (!shutdown_requested.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            
            // Print status every 60 seconds
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_status_print).count() >= 60) {
                print_system_status(behavioral_profiler, immune_engine);
                last_status_print = now;
            }
        }
        
        std::cout << "\nShutting down GENESIS Agent..." << std::endl;
        
        // Graceful shutdown
        immune_engine->stop();
        behavioral_profiler->stop();
        
        std::cout << "✅ GENESIS Agent shutdown complete." << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}