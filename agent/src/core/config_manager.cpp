#include "config_manager.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdlib>

namespace genesis {
namespace core {

ConfigManager::ConfigManager() {
    setup_defaults();
}

ConfigManager::~ConfigManager() = default;

void ConfigManager::setup_defaults() {
    // Behavioral Profiler defaults
    defaults_["profiler.learning_window_hours"] = 24;
    defaults_["profiler.adaptation_rate"] = 0.1;
    defaults_["profiler.monitoring_interval_seconds"] = 5;
    defaults_["profiler.anomaly_threshold"] = 0.7;
    defaults_["profiler.max_pattern_history"] = 1000;
    
    // Immune Engine defaults
    defaults_["immune.analysis_interval_seconds"] = 2;
    defaults_["immune.auto_response_enabled"] = true;
    defaults_["immune.auto_response_threshold"] = 2; // HIGH severity
    defaults_["immune.max_active_threats"] = 100;
    defaults_["immune.max_threat_history"] = 1000;
    defaults_["immune.confidence_threshold"] = 0.6;
    
    // System Monitor defaults
    defaults_["monitor.check_privileges"] = true;
    defaults_["monitor.collect_network_data"] = true;
    defaults_["monitor.collect_file_data"] = true;
    defaults_["monitor.max_processes"] = 500;
    
    // Logging defaults
    defaults_["logging.level"] = std::string("INFO");
    defaults_["logging.file"] = std::string("/var/log/genesis/agent.log");
    defaults_["logging.max_file_size_mb"] = 100;
    defaults_["logging.max_files"] = 10;
    defaults_["logging.console"] = true;
    
    // Security defaults
    defaults_["security.drop_privileges"] = true;
    defaults_["security.run_user"] = std::string("genesis");
    defaults_["security.run_group"] = std::string("genesis");
    defaults_["security.validate_inputs"] = true;
    
    // General defaults
    defaults_["general.data_dir"] = std::string("/var/lib/genesis");
    defaults_["general.config_dir"] = std::string("/etc/genesis");
    defaults_["general.pid_file"] = std::string("/var/run/genesis.pid");
    defaults_["general.status_interval_seconds"] = 60;
    
    // Copy defaults to config
    config_ = defaults_;
}

bool ConfigManager::load_from_file(const std::string& config_file) {
    std::ifstream file(config_file);
    if (!file.is_open()) {
        std::cerr << "[ConfigManager] Cannot open config file: " << config_file << std::endl;
        return false;
    }

    std::string line;
    int line_number = 0;
    
    while (std::getline(file, line)) {
        line_number++;
        
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        if (!parse_config_line(line)) {
            std::cerr << "[ConfigManager] Error parsing line " << line_number 
                      << " in " << config_file << ": " << line << std::endl;
        }
    }
    
    std::cout << "[ConfigManager] Loaded configuration from " << config_file << std::endl;
    return true;
}

void ConfigManager::load_from_environment() {
    // Check for environment variables with GENESIS_ prefix
    std::vector<std::string> env_keys = {
        "GENESIS_PROFILER_LEARNING_WINDOW_HOURS",
        "GENESIS_PROFILER_ADAPTATION_RATE",
        "GENESIS_PROFILER_MONITORING_INTERVAL_SECONDS",
        "GENESIS_IMMUNE_AUTO_RESPONSE_ENABLED",
        "GENESIS_IMMUNE_AUTO_RESPONSE_THRESHOLD",
        "GENESIS_LOGGING_LEVEL",
        "GENESIS_LOGGING_FILE",
        "GENESIS_SECURITY_DROP_PRIVILEGES",
        "GENESIS_GENERAL_DATA_DIR",
        "GENESIS_GENERAL_CONFIG_DIR"
    };
    
    std::unordered_map<std::string, std::string> env_mapping = {
        {"GENESIS_PROFILER_LEARNING_WINDOW_HOURS", "profiler.learning_window_hours"},
        {"GENESIS_PROFILER_ADAPTATION_RATE", "profiler.adaptation_rate"},
        {"GENESIS_PROFILER_MONITORING_INTERVAL_SECONDS", "profiler.monitoring_interval_seconds"},
        {"GENESIS_IMMUNE_AUTO_RESPONSE_ENABLED", "immune.auto_response_enabled"},
        {"GENESIS_IMMUNE_AUTO_RESPONSE_THRESHOLD", "immune.auto_response_threshold"},
        {"GENESIS_LOGGING_LEVEL", "logging.level"},
        {"GENESIS_LOGGING_FILE", "logging.file"},
        {"GENESIS_SECURITY_DROP_PRIVILEGES", "security.drop_privileges"},
        {"GENESIS_GENERAL_DATA_DIR", "general.data_dir"},
        {"GENESIS_GENERAL_CONFIG_DIR", "general.config_dir"}
    };
    
    for (const auto& env_key : env_keys) {
        std::string value = get_env_var(env_key);
        if (!value.empty()) {
            auto it = env_mapping.find(env_key);
            if (it != env_mapping.end()) {
                std::string config_key = it->second;
                
                // Try to determine the type based on the default value
                auto default_it = defaults_.find(config_key);
                if (default_it != defaults_.end()) {
                    if (std::holds_alternative<int>(default_it->second)) {
                        config_[config_key] = std::stoi(value);
                    } else if (std::holds_alternative<double>(default_it->second)) {
                        config_[config_key] = std::stod(value);
                    } else if (std::holds_alternative<bool>(default_it->second)) {
                        config_[config_key] = (value == "true" || value == "1" || value == "yes");
                    } else {
                        config_[config_key] = value;
                    }
                    
                    std::cout << "[ConfigManager] Set " << config_key 
                              << " from environment: " << value << std::endl;
                }
            }
        }
    }
}

bool ConfigManager::parse_command_line(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            print_help();
            return false;
        } else if (arg == "--config" || arg == "-c") {
            if (i + 1 < argc) {
                return load_from_file(argv[++i]);
            } else {
                std::cerr << "Error: --config requires a file path" << std::endl;
                return false;
            }
        } else if (arg.find("--") == 0) {
            // Parse --key=value format
            size_t eq_pos = arg.find('=');
            if (eq_pos != std::string::npos) {
                std::string key = arg.substr(2, eq_pos - 2);
                std::string value = arg.substr(eq_pos + 1);
                
                // Convert -- format to . format
                std::replace(key.begin(), key.end(), '-', '.');
                
                // Set the value (as string for now)
                config_[key] = value;
                
                std::cout << "[ConfigManager] Set " << key << " from command line: " << value << std::endl;
            } else {
                std::cerr << "Error: Invalid option format: " << arg << std::endl;
                return false;
            }
        }
    }
    
    return true;
}

void ConfigManager::set(const std::string& key, const ConfigValue& value) {
    config_[key] = value;
}

bool ConfigManager::save_to_file(const std::string& config_file) const {
    std::ofstream file(config_file);
    if (!file.is_open()) {
        std::cerr << "[ConfigManager] Cannot write to config file: " << config_file << std::endl;
        return false;
    }
    
    file << "# GENESIS Agent Configuration File" << std::endl;
    file << "# Generated automatically" << std::endl << std::endl;
    
    for (const auto& [key, value] : config_) {
        file << key << " = ";
        
        std::visit([&file](const auto& v) {
            if constexpr (std::is_same_v<std::decay_t<decltype(v)>, bool>) {
                file << (v ? "true" : "false");
            } else {
                file << v;
            }
        }, value);
        
        file << std::endl;
    }
    
    return true;
}

bool ConfigManager::validate() const {
    bool valid = true;
    
    // Validate profiler settings
    auto learning_window = get<int>("profiler.learning_window_hours");
    if (learning_window && (*learning_window < 1 || *learning_window > 168)) {
        std::cerr << "[ConfigManager] Invalid learning window: " << *learning_window 
                  << " (must be 1-168 hours)" << std::endl;
        valid = false;
    }
    
    auto adaptation_rate = get<double>("profiler.adaptation_rate");
    if (adaptation_rate && (*adaptation_rate < 0.01 || *adaptation_rate > 1.0)) {
        std::cerr << "[ConfigManager] Invalid adaptation rate: " << *adaptation_rate 
                  << " (must be 0.01-1.0)" << std::endl;
        valid = false;
    }
    
    auto monitoring_interval = get<int>("profiler.monitoring_interval_seconds");
    if (monitoring_interval && (*monitoring_interval < 1 || *monitoring_interval > 3600)) {
        std::cerr << "[ConfigManager] Invalid monitoring interval: " << *monitoring_interval 
                  << " (must be 1-3600 seconds)" << std::endl;
        valid = false;
    }
    
    // Validate immune engine settings
    auto auto_threshold = get<int>("immune.auto_response_threshold");
    if (auto_threshold && (*auto_threshold < 0 || *auto_threshold > 3)) {
        std::cerr << "[ConfigManager] Invalid auto response threshold: " << *auto_threshold 
                  << " (must be 0-3)" << std::endl;
        valid = false;
    }
    
    // Validate logging level
    auto log_level = get<std::string>("logging.level");
    if (log_level) {
        std::vector<std::string> valid_levels = {"DEBUG", "INFO", "WARN", "ERROR", "FATAL"};
        if (std::find(valid_levels.begin(), valid_levels.end(), *log_level) == valid_levels.end()) {
            std::cerr << "[ConfigManager] Invalid logging level: " << *log_level << std::endl;
            valid = false;
        }
    }
    
    return valid;
}

void ConfigManager::print_help() const {
    std::cout << "GENESIS Agent - Biologically-Inspired Cybersecurity System\n" << std::endl;
    std::cout << "Usage: genesis-agent [OPTIONS]\n" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help                    Show this help message" << std::endl;
    std::cout << "  -c, --config FILE             Load configuration from file" << std::endl;
    std::cout << "  --profiler-learning-window=N  Set learning window (hours, default: 24)" << std::endl;
    std::cout << "  --profiler-adaptation-rate=X  Set adaptation rate (0.01-1.0, default: 0.1)" << std::endl;
    std::cout << "  --immune-auto-response=BOOL   Enable auto response (true/false, default: true)" << std::endl;
    std::cout << "  --logging-level=LEVEL         Set log level (DEBUG/INFO/WARN/ERROR/FATAL)" << std::endl;
    std::cout << "  --general-data-dir=DIR        Set data directory (default: /var/lib/genesis)" << std::endl;
    std::cout << std::endl;
    std::cout << "Environment Variables:" << std::endl;
    std::cout << "  GENESIS_PROFILER_LEARNING_WINDOW_HOURS" << std::endl;
    std::cout << "  GENESIS_PROFILER_ADAPTATION_RATE" << std::endl;
    std::cout << "  GENESIS_IMMUNE_AUTO_RESPONSE_ENABLED" << std::endl;
    std::cout << "  GENESIS_LOGGING_LEVEL" << std::endl;
    std::cout << "  GENESIS_GENERAL_DATA_DIR" << std::endl;
    std::cout << std::endl;
    std::cout << "Configuration File Format:" << std::endl;
    std::cout << "  # Comments start with #" << std::endl;
    std::cout << "  profiler.learning_window_hours = 24" << std::endl;
    std::cout << "  profiler.adaptation_rate = 0.1" << std::endl;
    std::cout << "  immune.auto_response_enabled = true" << std::endl;
    std::cout << "  logging.level = INFO" << std::endl;
}

std::vector<std::string> ConfigManager::get_all_keys() const {
    std::vector<std::string> keys;
    for (const auto& [key, value] : config_) {
        keys.push_back(key);
    }
    std::sort(keys.begin(), keys.end());
    return keys;
}

bool ConfigManager::parse_config_line(const std::string& line) {
    size_t eq_pos = line.find('=');
    if (eq_pos == std::string::npos) {
        return false;
    }
    
    std::string key = line.substr(0, eq_pos);
    std::string value = line.substr(eq_pos + 1);
    
    // Trim whitespace
    key.erase(0, key.find_first_not_of(" \t"));
    key.erase(key.find_last_not_of(" \t") + 1);
    value.erase(0, value.find_first_not_of(" \t"));
    value.erase(value.find_last_not_of(" \t") + 1);
    
    // Determine type based on default value if it exists
    auto default_it = defaults_.find(key);
    if (default_it != defaults_.end()) {
        if (std::holds_alternative<int>(default_it->second)) {
            try {
                config_[key] = std::stoi(value);
            } catch (const std::exception&) {
                return false;
            }
        } else if (std::holds_alternative<double>(default_it->second)) {
            try {
                config_[key] = std::stod(value);
            } catch (const std::exception&) {
                return false;
            }
        } else if (std::holds_alternative<bool>(default_it->second)) {
            std::string lower_value = value;
            std::transform(lower_value.begin(), lower_value.end(), lower_value.begin(), ::tolower);
            config_[key] = (lower_value == "true" || lower_value == "1" || lower_value == "yes");
        } else {
            config_[key] = value;
        }
    } else {
        // Unknown key, store as string
        config_[key] = value;
    }
    
    return true;
}

std::string ConfigManager::get_env_var(const std::string& name) const {
    const char* value = std::getenv(name.c_str());
    return value ? std::string(value) : std::string();
}

} // namespace core
} // namespace genesis