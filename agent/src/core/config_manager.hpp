#pragma once

#include <string>
#include <unordered_map>
#include <variant>
#include <optional>

namespace genesis {
namespace core {

/**
 * @brief Configuration manager for GENESIS agent
 */
class ConfigManager {
public:
    using ConfigValue = std::variant<std::string, int, double, bool>;
    
    ConfigManager();
    ~ConfigManager();

    /**
     * @brief Load configuration from file
     * @param config_file Path to configuration file
     * @return true if successful, false otherwise
     */
    bool load_from_file(const std::string& config_file);

    /**
     * @brief Load configuration from environment variables
     */
    void load_from_environment();

    /**
     * @brief Parse command line arguments
     * @param argc Argument count
     * @param argv Argument values
     * @return true if successful, false otherwise
     */
    bool parse_command_line(int argc, char* argv[]);

    /**
     * @brief Get configuration value
     * @param key Configuration key
     * @return Optional configuration value
     */
    template<typename T>
    std::optional<T> get(const std::string& key) const {
        auto it = config_.find(key);
        if (it != config_.end()) {
            try {
                return std::get<T>(it->second);
            } catch (const std::bad_variant_access&) {
                return std::nullopt;
            }
        }
        return std::nullopt;
    }

    /**
     * @brief Get configuration value with default
     * @param key Configuration key
     * @param default_value Default value if key not found
     * @return Configuration value or default
     */
    template<typename T>
    T get_or_default(const std::string& key, const T& default_value) const {
        auto value = get<T>(key);
        return value.value_or(default_value);
    }

    /**
     * @brief Set configuration value
     * @param key Configuration key
     * @param value Configuration value
     */
    void set(const std::string& key, const ConfigValue& value);

    /**
     * @brief Save current configuration to file
     * @param config_file Path to configuration file
     * @return true if successful, false otherwise
     */
    bool save_to_file(const std::string& config_file) const;

    /**
     * @brief Validate configuration
     * @return true if configuration is valid, false otherwise
     */
    bool validate() const;

    /**
     * @brief Print help text for command line options
     */
    void print_help() const;

    /**
     * @brief Get all configuration keys
     * @return Vector of configuration keys
     */
    std::vector<std::string> get_all_keys() const;

private:
    std::unordered_map<std::string, ConfigValue> config_;
    std::unordered_map<std::string, ConfigValue> defaults_;
    
    void setup_defaults();
    bool parse_config_line(const std::string& line);
    std::string get_env_var(const std::string& name) const;
};

} // namespace core
} // namespace genesis