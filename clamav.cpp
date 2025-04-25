/**
 * Enhanced Virus Scanner using ClamAV definitions
 * 
 * This program demonstrates how to use the ClamAV library to scan files
 * for malware with additional features like quarantine and reporting.
 * 
 * Dependencies:
 * - libclamav-dev (ClamAV development library)
 * - Boost filesystem (for older C++ standards)
 * 
 * Compile with:
 * g++ -o enhanced_scanner enhanced_scanner.cpp -lclamav -lboost_filesystem -lboost_system -std=c++17
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <thread>
#include <mutex>
#include <atomic>
#include <clamav.h>
#include <cstring>

namespace fs = std::filesystem;

// Simple thread-safe logger
class Logger {
private:
    std::mutex log_mutex;
    std::ofstream log_file;
    bool console_output;

public:
    enum LogLevel {
        DEBUG,
        INFO,
        WARNING,
        ERROR,
        CRITICAL
    };

    Logger(const std::string& log_path, bool console = true) : console_output(console) {
        log_file.open(log_path, std::ios::app);
    }

    ~Logger() {
        if (log_file.is_open()) {
            log_file.close();
        }
    }

    void log(LogLevel level, const std::string& message) {
        std::lock_guard<std::mutex> lock(log_mutex);
        
        // Get current time
        auto now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);
        
        // Format timestamp
        char timestr[26];
        ctime_r(&time, timestr);
        timestr[24] = '\0'; // Remove newline
        
        // Convert log level to string
        std::string level_str;
        switch (level) {
            case DEBUG:   level_str = "DEBUG"; break;
            case INFO:    level_str = "INFO"; break;
            case WARNING: level_str = "WARNING"; break;
            case ERROR:   level_str = "ERROR"; break;
            case CRITICAL:level_str = "CRITICAL"; break;
        }
        
        // Format log message
        std::string formatted_msg = std::string(timestr) + " [" + level_str + "] " + message;
        
        // Write to file
        if (log_file.is_open()) {
            log_file << formatted_msg << std::endl;
        }
        
        // Write to console if enabled
        if (console_output) {
            std::cout << formatted_msg << std::endl;
        }
    }
};

// Quarantine manager
class QuarantineManager {
private:
    std::string quarantine_path;
    std::mutex quarantine_mutex;
    Logger& logger;
    
    std::string getQuarantineFilename(const std::string& original_path) {
        // Generate a unique filename for the quarantined file
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << "quarantined_" << time << "_" << fs::path(original_path).filename().string();
        return ss.str();
    }

public:
    QuarantineManager(const std::string& qpath, Logger& log) 
        : quarantine_path(qpath), logger(log) {
        // Ensure quarantine directory exists
        if (!fs::exists(quarantine_path)) {
            try {
                fs::create_directories(quarantine_path);
                logger.log(Logger::INFO, "Created quarantine directory: " + quarantine_path);
            } catch (const std::exception& e) {
                logger.log(Logger::ERROR, "Failed to create quarantine directory: " + 
                                        std::string(e.what()));
            }
        }
    }
    
    bool quarantineFile(const std::string& file_path) {
        std::lock_guard<std::mutex> lock(quarantine_mutex);
        
        try {
            // Check if file exists
            if (!fs::exists(file_path)) {
                logger.log(Logger::ERROR, "Cannot quarantine: File does not exist: " + file_path);
                return false;
            }
            
            // Generate quarantine filename
            std::string qfile = quarantine_path + "/" + getQuarantineFilename(file_path);
            
            // Move file to quarantine
            fs::copy(file_path, qfile);
            fs::remove(file_path);
            
            logger.log(Logger::INFO, "Quarantined file: " + file_path + " -> " + qfile);
            return true;
        } catch (const std::exception& e) {
            logger.log(Logger::ERROR, "Failed to quarantine file " + file_path + 
                                    ": " + std::string(e.what()));
            return false;
        }
    }
    
    std::vector<std::string> listQuarantinedFiles() {
        std::vector<std::string> files;
        for (const auto& entry : fs::directory_iterator(quarantine_path)) {
            if (fs::is_regular_file(entry)) {
                files.push_back(entry.path().string());
            }
        }
        return files;
    }
    
    bool restoreFile(const std::string& quarantine_file, const std::string& restore_path) {
        std::lock_guard<std::mutex> lock(quarantine_mutex);
        
        try {
            // Check if file exists in quarantine
            if (!fs::exists(quarantine_file)) {
                logger.log(Logger::ERROR, "Cannot restore: File does not exist in quarantine: " + quarantine_file);
                return false;
            }
            
            // Move file from quarantine to restore path
            fs::copy(quarantine_file, restore_path);
            fs::remove(quarantine_file);
            
            logger.log(Logger::INFO, "Restored file: " + quarantine_file + " -> " + restore_path);
            return true;
        } catch (const std::exception& e) {
            logger.log(Logger::ERROR, "Failed to restore file " + quarantine_file + 
                                    ": " + std::string(e.what()));
            return false;
        }
    }
    
    bool deleteQuarantinedFile(const std::string& quarantine_file) {
        std::lock_guard<std::mutex> lock(quarantine_mutex);
        
        try {
            // Check if file exists in quarantine
            if (!fs::exists(quarantine_file)) {
                logger.log(Logger::ERROR, "Cannot delete: File does not exist in quarantine: " + quarantine_file);
                return false;
            }
            
            // Delete file from quarantine
            fs::remove(quarantine_file);
            
            logger.log(Logger::INFO, "Deleted quarantined file: " + quarantine_file);
            return true;
        } catch (const std::exception& e) {
            logger.log(Logger::ERROR, "Failed to delete quarantined file " + quarantine_file + 
                                    ": " + std::string(e.what()));
            return false;
        }
    }
};

// Report generator
class ReportGenerator {
private:
    struct ScanResult {
        std::string filepath;
        std::string virus_name;
        std::time_t timestamp;
        bool quarantined;
    };
    
    std::vector<ScanResult> scan_results;
    std::mutex results_mutex;
    
public:
    void addResult(const std::string& filepath, const std::string& virus_name, bool quarantined) {
        std::lock_guard<std::mutex> lock(results_mutex);
        
        ScanResult result;
        result.filepath = filepath;
        result.virus_name = virus_name;
        result.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        result.quarantined = quarantined;
        
        scan_results.push_back(result);
    }
    
    bool generateTextReport(const std::string& report_path) {
        std::lock_guard<std::mutex> lock(results_mutex);
        
        try {
            std::ofstream report(report_path);
            if (!report.is_open()) {
                return false;
            }
            
            report << "========================" << std::endl;
            report << " Virus Scan Report" << std::endl;
            report << "========================" << std::endl;
            report << "Date: " << std::ctime(nullptr);
            report << "Total files infected: " << scan_results.size() << std::endl;
            report << std::endl;
            
            report << "Infected Files:" << std::endl;
            report << "-------------------" << std::endl;
            
            for (const auto& result : scan_results) {
                char timestr[26];
                ctime_r(&result.timestamp, timestr);
                timestr[24] = '\0'; // Remove newline
                
                report << "File: " << result.filepath << std::endl;
                report << "Virus: " << result.virus_name << std::endl;
                report << "Detected: " << timestr << std::endl;
                report << "Action: " << (result.quarantined ? "Quarantined" : "None") << std::endl;
                report << std::endl;
            }
            
            report << "========================" << std::endl;
            report.close();
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }
    
    bool generateCSVReport(const std::string& report_path) {
        std::lock_guard<std::mutex> lock(results_mutex);
        
        try {
            std::ofstream report(report_path);
            if (!report.is_open()) {
                return false;
            }
            
            // Write header
            report << "File,Virus,Timestamp,Quarantined" << std::endl;
            
            // Write data
            for (const auto& result : scan_results) {
                report << result.filepath << ","
                       << result.virus_name << ","
                       << result.timestamp << ","
                       << (result.quarantined ? "Yes" : "No") << std::endl;
            }
            
            report.close();
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }
    
    int getTotalInfected() const {
        return scan_results.size();
    }
};

// Multi-threaded scanner using ClamAV
class ClamAVScanner {
private:
    struct cl_engine* engine;
    unsigned int signature_count;
    struct cl_scan_options scan_options;
    Logger& logger;
    QuarantineManager& quarantine;
    ReportGenerator& report;
    std::atomic<int> files_scanned;
    std::atomic<int> infected_count;
    std::mutex engine_mutex;
    std::atomic<unsigned long long> total_bytes_scanned = 0;
    // Worker thread function
    void scanWorker(const std::vector<std::string>& files, bool auto_quarantine) {
        for (const auto& file : files) {
            try {
                auto [infected, virus_name] = scanSingleFile(file);
                files_scanned++;
                
                if (infected) {
                    infected_count++;
                    logger.log(Logger::WARNING, "VIRUS FOUND: " + file + " - " + virus_name);
                    
                    bool quarantined = false;
                    if (auto_quarantine) {
                        quarantined = quarantine.quarantineFile(file);
                    }
                    
                    report.addResult(file, virus_name, quarantined);
                }
            } catch (const std::exception& e) {
                logger.log(Logger::ERROR, "Error scanning file " + file + ": " + e.what());
            }
        }
    }
    
    // Distribute files among worker threads
    std::vector<std::vector<std::string>> distributeFiles(const std::vector<std::string>& files, int num_threads) {
        std::vector<std::vector<std::string>> distributed(num_threads);
        
        for (size_t i = 0; i < files.size(); i++) {
            distributed[i % num_threads].push_back(files[i]);
        }
        
        return distributed;
    }

public:
    ClamAVScanner(Logger& log, QuarantineManager& qm, ReportGenerator& rep) 
        : engine(nullptr), signature_count(0), logger(log), quarantine(qm), report(rep), 
          files_scanned(0), infected_count(0) {
        
        // Initialize ClamAV library
        if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS) {
            throw std::runtime_error("ClamAV initialization failed");
        }
        
        // Create new engine
        engine = cl_engine_new();
        if (engine == nullptr) {
            throw std::runtime_error("Could not create new ClamAV engine");
        }
        
        // Set up default scan options
        memset(&scan_options, 0, sizeof(scan_options));
        scan_options.parse = CL_SCAN_PARSE_ARCHIVE; // Parse archives
        scan_options.general = CL_SCAN_GENERAL_ALLMATCHES; // Report all matches
        
        logger.log(Logger::INFO, "ClamAV scanner initialized");
    }
    
    ~ClamAVScanner() {
        // Free the engine when done
        if (engine != nullptr) {
            cl_engine_free(engine);
            logger.log(Logger::INFO, "ClamAV engine freed");
        }
    }
    
    bool loadDatabase(const std::string& db_path) {
        std::lock_guard<std::mutex> lock(engine_mutex);
        
        logger.log(Logger::INFO, "Loading virus database from: " + db_path);
        
        int ret = cl_load(db_path.c_str(), engine, &signature_count, CL_DB_STDOPT);
        if (ret != CL_SUCCESS) {
            logger.log(Logger::ERROR, "Error loading database: " + std::string(cl_strerror((cl_error_t)ret)));
            return false;
        }
        
        // Compile the loaded database
        if ((ret = cl_engine_compile(engine)) != CL_SUCCESS) {
            logger.log(Logger::ERROR, "Engine compilation error: " + std::string(cl_strerror((cl_error_t)ret)));
            return false;
        }
        
        logger.log(Logger::INFO, "Loaded " + std::to_string(signature_count) + " virus signatures");
        return true;
    }
    
std::pair<bool, std::string> scanSingleFile(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(engine_mutex);
    
    const size_t CHUNK_SIZE = 30 * 1024 * 1024; // 30 MB chunks
    const size_t OVERLAP_SIZE = 15 * 1024 * 1024; // 15 MB overlap
    
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        logger.log(Logger::ERROR, "Could not open file for scanning: " + filepath);
        return {false, "error: file could not be opened"};
    }
    
    // Get file size
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // If file is small enough, scan directly
    if (fileSize <= CHUNK_SIZE) {
        const char* virus_name = nullptr;
        unsigned long scanned = 0;
        int scan_result = cl_scanfile(filepath.c_str(), &virus_name, &scanned, engine, &scan_options);
        
        // Add to total bytes counter
        total_bytes_scanned += scanned;
        
        // Log the total bytes scanned after each file
        logger.log(Logger::DEBUG, "Total bytes scanned so far: " + 
                   std::to_string(total_bytes_scanned) + " bytes (" + 
                   std::to_string(total_bytes_scanned / (1024.0 * 1024.0)) + " MB)");
        
        if (scan_result == CL_VIRUS) {
            return {true, virus_name ? virus_name : "unknown virus"};
        } else if (scan_result != CL_CLEAN) {
            return {false, std::string("Error scanning file: ") + cl_strerror((cl_error_t)scan_result)};
        }
        
        return {false, "clean"};
    }
    
    // For larger files, use chunked scanning with overlap
    logger.log(Logger::INFO, "Large file detected, using chunked scanning: " + filepath);
    
    std::vector<char> buffer(CHUNK_SIZE);
    size_t position = 0;
    
    while (position < fileSize) {
        size_t bytesToRead = std::min(CHUNK_SIZE, fileSize - position);
        
        // Read chunk into memory
        file.seekg(position);
        file.read(buffer.data(), bytesToRead);
        
        // Create a temporary file for this chunk
        std::string tempFilename = std::tmpnam(nullptr);
        std::ofstream tempFile(tempFilename, std::ios::binary);
        if (!tempFile) {
            logger.log(Logger::ERROR, "Could not create temporary file for chunk scanning");
            return {false, "error: could not create temporary chunk file"};
        }
        
        tempFile.write(buffer.data(), bytesToRead);
        tempFile.close();
        
        // Scan the chunk
        const char* virus_name = nullptr;
        unsigned long scanned = 0;
        int scan_result = cl_scanfile(tempFilename.c_str(), &virus_name, &scanned, engine, &scan_options);
        
        // Clean up temporary file
        std::remove(tempFilename.c_str());
        
        // Add to total bytes counter
        total_bytes_scanned += scanned;
        
        // Log progress
        logger.log(Logger::DEBUG, "Scanned chunk " + std::to_string(position / OVERLAP_SIZE) + 
                   " of file: " + filepath + " (" + 
                   std::to_string(position / (1024.0 * 1024.0)) + " MB - " + 
                   std::to_string((position + bytesToRead) / (1024.0 * 1024.0)) + " MB)");
        
        // If virus found, return immediately
        if (scan_result == CL_VIRUS) {
            logger.log(Logger::WARNING, "Virus found in chunk at position " + 
                       std::to_string(position) + " of file: " + filepath);
            return {true, virus_name ? virus_name : "unknown virus"};
        } else if (scan_result != CL_CLEAN) {
            logger.log(Logger::ERROR, "Error scanning chunk of file: " + 
                       std::string(cl_strerror((cl_error_t)scan_result)));
            // Continue with other chunks even if one fails
        }
        
        // Move to next position with overlap
        // If we're at the beginning, move by OVERLAP_SIZE
        // Otherwise, move by CHUNK_SIZE - OVERLAP_SIZE
        if (position == 0) {
            position = OVERLAP_SIZE;
        } else {
            position += (CHUNK_SIZE - OVERLAP_SIZE);
        }
    }
    
    // If we got here, no virus was found
    logger.log(Logger::INFO, "Completed chunked scan of file: " + filepath + 
               " (" + std::to_string(fileSize / (1024.0 * 1024.0)) + " MB)");
    
    return {false, "clean"};
}
    
    void scanFiles(const std::vector<std::string>& files, bool auto_quarantine = false, int num_threads = 4) {
        // Reset counters
        files_scanned = 0;
        infected_count = 0;
        
        logger.log(Logger::INFO, "Starting scan of " + std::to_string(files.size()) + 
                              " files using " + std::to_string(num_threads) + " threads");
        
        // Distribute files among threads
        auto distributed_files = distributeFiles(files, num_threads);
        
        // Create and start worker threads
        std::vector<std::thread> threads;
        for (int i = 0; i < num_threads; i++) {
            if (!distributed_files[i].empty()) {
                threads.emplace_back(&ClamAVScanner::scanWorker, this, distributed_files[i], auto_quarantine);
            }
        }
        
        // Wait for all threads to finish
        for (auto& thread : threads) {
            thread.join();
        }
        
        logger.log(Logger::INFO, "Scan completed. Scanned " + std::to_string(files_scanned) + 
                              " files, found " + std::to_string(infected_count) + " infections");
    }
    
    void scanDirectory(const std::string& directory_path, bool recursive = false, 
                      bool auto_quarantine = false, int num_threads = 4) {
        std::vector<std::string> files_to_scan;
        
        logger.log(Logger::INFO, "Collecting files from directory: " + directory_path + 
                              (recursive ? " (recursively)" : ""));
        
        try {
            if (recursive) {
                for (const auto& entry : fs::recursive_directory_iterator(directory_path)) {
                    if (fs::is_regular_file(entry)) {
                        files_to_scan.push_back(entry.path().string());
                    }
                }
            } else {
                for (const auto& entry : fs::directory_iterator(directory_path)) {
                    if (fs::is_regular_file(entry)) {
                        files_to_scan.push_back(entry.path().string());
                    }
                }
            }
            
            logger.log(Logger::INFO, "Found " + std::to_string(files_to_scan.size()) + " files to scan");
            
            // Start scanning files
            scanFiles(files_to_scan, auto_quarantine, num_threads);
            
        } catch (const std::exception& e) {
            logger.log(Logger::ERROR, "Error scanning directory: " + std::string(e.what()));
        }
    }
    
    int getScannedCount() const {
        return files_scanned;
    }
    
    int getInfectedCount() const {
        return infected_count;
    }
};

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [OPTIONS] [PATH]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help          Show this help message" << std::endl;
    std::cout << "  -r, --recursive     Scan directories recursively" << std::endl;
    std::cout << "  -d, --database      Specify ClamAV database directory (default: /var/lib/clamav)" << std::endl;
    std::cout << "  -f, --file          Scan a single file" << std::endl;
    std::cout << "  -q, --quarantine    Auto-quarantine infected files" << std::endl;
    std::cout << "  -t, --threads       Number of scanner threads (default: 4)" << std::endl;
    std::cout << "  -l, --log           Log file path (default: scanner.log)" << std::endl;
    std::cout << "  --quarantine-dir    Quarantine directory (default: ./quarantine)" << std::endl;
    std::cout << "  --report-txt        Generate text report file" << std::endl;
    std::cout << "  --report-csv        Generate CSV report file" << std::endl;
}

int main(int argc, char* argv[]) {
    std::string scan_path = ".";
    std::string db_path = "/var/lib/clamav";
    std::string log_path = "scanner.log";
    std::string quarantine_dir = "./quarantine";
    std::string text_report_path;
    std::string csv_report_path;
    bool recursive = false;
    bool scan_single_file = false;
    bool auto_quarantine = false;
    int num_threads = 4;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        } else if (arg == "-r" || arg == "--recursive") {
            recursive = true;
        } else if (arg == "-d" || arg == "--database") {
            if (i + 1 < argc) {
                db_path = argv[++i];
            } else {
                std::cerr << "Missing database path argument" << std::endl;
                return 1;
            }
        } else if (arg == "-f" || arg == "--file") {
            scan_single_file = true;
            if (i + 1 < argc) {
                scan_path = argv[++i];
            } else {
                std::cerr << "Missing file path argument" << std::endl;
                return 1;
            }
        } else if (arg == "-q" || arg == "--quarantine") {
            auto_quarantine = true;
        } else if (arg == "-t" || arg == "--threads") {
            if (i + 1 < argc) {
                num_threads = std::stoi(argv[++i]);
                if (num_threads < 1) num_threads = 1;
            } else {
                std::cerr << "Missing threads argument" << std::endl;
                return 1;
            }
        } else if (arg == "-l" || arg == "--log") {
            if (i + 1 < argc) {
                log_path = argv[++i];
            } else {
                std::cerr << "Missing log path argument" << std::endl;
                return 1;
            }
        } else if (arg == "--quarantine-dir") {
            if (i + 1 < argc) {
                quarantine_dir = argv[++i];
            } else {
                std::cerr << "Missing quarantine directory argument" << std::endl;
                return 1;
            }
        } else if (arg == "--report-txt") {
            if (i + 1 < argc) {
                text_report_path = argv[++i];
            } else {
                std::cerr << "Missing text report path argument" << std::endl;
                return 1;
            }
        } else if (arg == "--report-csv") {
            if (i + 1 < argc) {
                csv_report_path = argv[++i];
            } else {
                std::cerr << "Missing CSV report path argument" << std::endl;
                return 1;
            }
        } else if (arg[0] != '-') {
            scan_path = arg;
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }

    try {
        // Initialize logger
        Logger logger(log_path);
        logger.log(Logger::INFO, "Scanner started");
        
        // Initialize quarantine manager
        QuarantineManager quarantine(quarantine_dir, logger);
        
        // Initialize report generator
        ReportGenerator report;
        
        // Initialize scanner
        ClamAVScanner scanner(logger, quarantine, report);
        
        // Load virus database
        logger.log(Logger::INFO, "Loading virus database from: " + db_path);
        if (!scanner.loadDatabase(db_path)) {
            logger.log(Logger::CRITICAL, "Failed to load virus database.");
            return 1;
        }
        
        // Scan files
        if (scan_single_file) {
            if (!fs::exists(scan_path)) {
                logger.log(Logger::ERROR, "File not found: " + scan_path);
                return 1;
            }
            
            logger.log(Logger::INFO, "Scanning file: " + scan_path);
            auto [infected, virus_name] = scanner.scanSingleFile(scan_path);
            
            if (infected) {
                logger.log(Logger::WARNING, "VIRUS FOUND: " + scan_path + " - " + virus_name);
                report.addResult(scan_path, virus_name, false);
                
                if (auto_quarantine) {
                    bool quarantined = quarantine.quarantineFile(scan_path);
                    if (quarantined) {
                        logger.log(Logger::INFO, "File quarantined: " + scan_path);
                    }
                }
                
                // Generate reports if requested
                if (!text_report_path.empty()) {
                    if (report.generateTextReport(text_report_path)) {
                        logger.log(Logger::INFO, "Text report generated: " + text_report_path);
                    } else {
                        logger.log(Logger::ERROR, "Failed to generate text report");
                    }
                }
                
                if (!csv_report_path.empty()) {
                    if (report.generateCSVReport(csv_report_path)) {
                        logger.log(Logger::INFO, "CSV report generated: " + csv_report_path);
                    } else {
                        logger.log(Logger::ERROR, "Failed to generate CSV report");
                    }
                }
                
                return 2; // Return code for virus found
            } else if (virus_name != "clean") {
                logger.log(Logger::ERROR, "Error scanning file: " + scan_path + " - " + virus_name);
                return 1;
            } else {
                logger.log(Logger::INFO, "CLEAN: " + scan_path);
                return 0;
            }
        } else {
            if (!fs::exists(scan_path)) {
                logger.log(Logger::ERROR, "Directory not found: " + scan_path);
                return 1;
            }
            
            logger.log(Logger::INFO, "Scanning directory: " + scan_path + 
                                  (recursive ? " (recursively)" : "") + 
                                  (auto_quarantine ? " with auto-quarantine" : ""));
            
            scanner.scanDirectory(scan_path, recursive, auto_quarantine, num_threads);
            
            // Generate reports if requested
            if (!text_report_path.empty()) {
                if (report.generateTextReport(text_report_path)) {
                    logger.log(Logger::INFO, "Text report generated: " + text_report_path);
                } else {
                    logger.log(Logger::ERROR, "Failed to generate text report");
                }
            }
            
            if (!csv_report_path.empty()) {
                if (report.generateCSVReport(csv_report_path)) {
                    logger.log(Logger::INFO, "CSV report generated: " + csv_report_path);
                } else {
                    logger.log(Logger::ERROR, "Failed to generate CSV report");
                }
            }
            
            logger.log(Logger::INFO, "Scan completed. Scanned " + std::to_string(scanner.getScannedCount()) + 
                                  " files, found " + std::to_string(scanner.getInfectedCount()) + " infections");
            
            return scanner.getInfectedCount() > 0 ? 2 : 0;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
