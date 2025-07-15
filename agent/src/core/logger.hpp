#pragma once

#include <string>
#include <fstream>
#include <memory>
#include <mutex>
#include <thread>
#include <queue>
#include <atomic>
#include <condition_variable>

namespace genesis {
namespace core {

/**
 * @brief Log levels for structured logging
 */
enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
    FATAL = 4
};

/**
 * @brief Log entry structure
 */
struct LogEntry {
    LogLevel level;
    std::string timestamp;
    std::string component;
    std::string message;
    std::string thread_id;
    std::string file;
    int line;
};

/**
 * @brief Thread-safe, production-ready logger
 */
class Logger {
public:
    static Logger& instance();
    
    /**
     * @brief Initialize logger with configuration
     * @param log_file Path to log file
     * @param level Minimum log level
     * @param console_output Enable console output
     * @param max_file_size_mb Maximum file size before rotation
     * @param max_files Maximum number of rotated files
     * @return true if successful, false otherwise
     */
    bool initialize(const std::string& log_file, 
                   LogLevel level = LogLevel::INFO,
                   bool console_output = true,
                   size_t max_file_size_mb = 100,
                   size_t max_files = 10);

    /**
     * @brief Shutdown logger and flush all pending entries
     */
    void shutdown();

    /**
     * @brief Log a message
     * @param level Log level
     * @param component Component name
     * @param message Log message
     * @param file Source file (optional)
     * @param line Source line (optional)
     */
    void log(LogLevel level, const std::string& component, 
             const std::string& message, 
             const std::string& file = "", int line = 0);

    /**
     * @brief Check if log level is enabled
     * @param level Log level to check
     * @return true if enabled, false otherwise
     */
    bool is_enabled(LogLevel level) const;

    /**
     * @brief Set log level
     * @param level New minimum log level
     */
    void set_level(LogLevel level);

    /**
     * @brief Get current log level
     * @return Current log level
     */
    LogLevel get_level() const;

    /**
     * @brief Force flush of pending log entries
     */
    void flush();

private:
    Logger() = default;
    ~Logger();

    // Disable copy/move
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void worker_thread();
    void write_entry(const LogEntry& entry);
    void rotate_log_file();
    std::string get_timestamp() const;
    std::string get_thread_id() const;
    std::string level_to_string(LogLevel level) const;
    bool should_rotate() const;

private:
    std::atomic<bool> initialized_{false};
    std::atomic<bool> shutdown_requested_{false};
    std::atomic<LogLevel> min_level_{LogLevel::INFO};
    
    std::string log_file_path_;
    bool console_output_{true};
    size_t max_file_size_bytes_{100 * 1024 * 1024}; // 100MB
    size_t max_files_{10};
    
    std::ofstream log_file_;
    std::mutex file_mutex_;
    
    // Async logging
    std::queue<LogEntry> log_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::thread worker_thread_;
};

// Convenience macros for logging
#define LOG_DEBUG(component, message) \
    do { \
        if (genesis::core::Logger::instance().is_enabled(genesis::core::LogLevel::DEBUG)) { \
            genesis::core::Logger::instance().log(genesis::core::LogLevel::DEBUG, component, message, __FILE__, __LINE__); \
        } \
    } while (0)

#define LOG_INFO(component, message) \
    do { \
        if (genesis::core::Logger::instance().is_enabled(genesis::core::LogLevel::INFO)) { \
            genesis::core::Logger::instance().log(genesis::core::LogLevel::INFO, component, message, __FILE__, __LINE__); \
        } \
    } while (0)

#define LOG_WARN(component, message) \
    do { \
        if (genesis::core::Logger::instance().is_enabled(genesis::core::LogLevel::WARN)) { \
            genesis::core::Logger::instance().log(genesis::core::LogLevel::WARN, component, message, __FILE__, __LINE__); \
        } \
    } while (0)

#define LOG_ERROR(component, message) \
    do { \
        if (genesis::core::Logger::instance().is_enabled(genesis::core::LogLevel::ERROR)) { \
            genesis::core::Logger::instance().log(genesis::core::LogLevel::ERROR, component, message, __FILE__, __LINE__); \
        } \
    } while (0)

#define LOG_FATAL(component, message) \
    do { \
        genesis::core::Logger::instance().log(genesis::core::LogLevel::FATAL, component, message, __FILE__, __LINE__); \
        genesis::core::Logger::instance().flush(); \
    } while (0)

} // namespace core
} // namespace genesis