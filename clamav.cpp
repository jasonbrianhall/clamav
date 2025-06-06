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
 * g++ -o enhanced_scanner enhanced_scanner.cpp -lclamav -lboost_filesystem
 * -lboost_system -std=c++17
 */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <clamav.h>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>
#include <functional>

namespace fs = std::filesystem;

std::string createTempFile();

std::string createTempFile() {
  char tempFilenameTemplate[] = "/tmp/tempfileXXXXXX";
  int fd = mkstemp(tempFilenameTemplate);

  if (fd == -1) {
    perror("mkstemp failed");
    return "";
  }

  close(fd); // Close the file descriptor, leaving the temporary file.
  return std::string(tempFilenameTemplate); // The unique temporary filename.
}

// Simple thread-safe logger
class Logger {
private:
  std::mutex log_mutex;
  std::ofstream log_file;
  bool console_output;

public:
  enum LogLevel { DEBUG, INFO, WARNING, ERROR, CRITICAL };

  Logger(const std::string &log_path, bool console = true)
      : console_output(console) {
    log_file.open(log_path, std::ios::app);
  }

  ~Logger() {
    if (log_file.is_open()) {
      log_file.close();
    }
  }

  void log(LogLevel level, const std::string &message) {
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
    case DEBUG:
      level_str = "DEBUG";
      break;
    case INFO:
      level_str = "INFO";
      break;
    case WARNING:
      level_str = "WARNING";
      break;
    case ERROR:
      level_str = "ERROR";
      break;
    case CRITICAL:
      level_str = "CRITICAL";
      break;
    }

    // Format log message
    std::string formatted_msg =
        std::string(timestr) + " [" + level_str + "] " + message;

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
  Logger &logger;

  std::string getQuarantineFilename(const std::string &original_path) {
    // Generate a unique filename for the quarantined file
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << "quarantined_" << time << "_"
       << fs::path(original_path).filename().string();
    return ss.str();
  }

public:
  QuarantineManager(const std::string &qpath, Logger &log)
      : quarantine_path(qpath), logger(log) {
    // Ensure quarantine directory exists
    if (!fs::exists(quarantine_path)) {
      try {
        fs::create_directories(quarantine_path);
        logger.log(Logger::INFO,
                   "Created quarantine directory: " + quarantine_path);
      } catch (const std::exception &e) {
        logger.log(Logger::ERROR, "Failed to create quarantine directory: " +
                                      std::string(e.what()));
      }
    }
  }

  bool quarantineFile(const std::string &file_path) {
    std::lock_guard<std::mutex> lock(quarantine_mutex);

    try {
      // Check if file exists
      if (!fs::exists(file_path)) {
        logger.log(Logger::ERROR,
                   "Cannot quarantine: File does not exist: " + file_path);
        return false;
      }

      // Generate quarantine filename
      std::string qfile =
          quarantine_path + "/" + getQuarantineFilename(file_path);

      // Move file to quarantine
      fs::copy(file_path, qfile);
      fs::remove(file_path);

      logger.log(Logger::INFO,
                 "Quarantined file: " + file_path + " -> " + qfile);
      return true;
    } catch (const std::exception &e) {
      logger.log(Logger::ERROR, "Failed to quarantine file " + file_path +
                                    ": " + std::string(e.what()));
      return false;
    }
  }

  std::vector<std::string> listQuarantinedFiles() {
    std::vector<std::string> files;
    for (const auto &entry : fs::directory_iterator(quarantine_path)) {
      if (fs::is_regular_file(entry)) {
        files.push_back(entry.path().string());
      }
    }
    return files;
  }

  bool restoreFile(const std::string &quarantine_file,
                   const std::string &restore_path) {
    std::lock_guard<std::mutex> lock(quarantine_mutex);

    try {
      // Check if file exists in quarantine
      if (!fs::exists(quarantine_file)) {
        logger.log(Logger::ERROR,
                   "Cannot restore: File does not exist in quarantine: " +
                       quarantine_file);
        return false;
      }

      // Move file from quarantine to restore path
      fs::copy(quarantine_file, restore_path);
      fs::remove(quarantine_file);

      logger.log(Logger::INFO,
                 "Restored file: " + quarantine_file + " -> " + restore_path);
      return true;
    } catch (const std::exception &e) {
      logger.log(Logger::ERROR, "Failed to restore file " + quarantine_file +
                                    ": " + std::string(e.what()));
      return false;
    }
  }

  bool deleteQuarantinedFile(const std::string &quarantine_file) {
    std::lock_guard<std::mutex> lock(quarantine_mutex);

    try {
      // Check if file exists in quarantine
      if (!fs::exists(quarantine_file)) {
        logger.log(Logger::ERROR,
                   "Cannot delete: File does not exist in quarantine: " +
                       quarantine_file);
        return false;
      }

      // Delete file from quarantine
      fs::remove(quarantine_file);

      logger.log(Logger::INFO, "Deleted quarantined file: " + quarantine_file);
      return true;
    } catch (const std::exception &e) {
      logger.log(Logger::ERROR, "Failed to delete quarantined file " +
                                    quarantine_file + ": " +
                                    std::string(e.what()));
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
  void addResult(const std::string &filepath, const std::string &virus_name,
                 bool quarantined) {
    std::lock_guard<std::mutex> lock(results_mutex);

    ScanResult result;
    result.filepath = filepath;
    result.virus_name = virus_name;
    result.timestamp =
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    result.quarantined = quarantined;

    scan_results.push_back(result);
  }

  bool generateTextReport(const std::string &report_path) {
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

      for (const auto &result : scan_results) {
        char timestr[26];
        ctime_r(&result.timestamp, timestr);
        timestr[24] = '\0'; // Remove newline

        report << "File: " << result.filepath << std::endl;
        report << "Virus: " << result.virus_name << std::endl;
        report << "Detected: " << timestr << std::endl;
        report << "Action: " << (result.quarantined ? "Quarantined" : "None")
               << std::endl;
        report << std::endl;
      }

      report << "========================" << std::endl;
      report.close();
      return true;
    } catch (const std::exception &) {
      return false;
    }
  }

  bool generateCSVReport(const std::string &report_path) {
    std::lock_guard<std::mutex> lock(results_mutex);

    try {
      std::ofstream report(report_path);
      if (!report.is_open()) {
        return false;
      }

      // Write header
      report << "File,Virus,Timestamp,Quarantined" << std::endl;

      // Write data
      for (const auto &result : scan_results) {
        report << result.filepath << "," << result.virus_name << ","
               << result.timestamp << "," << (result.quarantined ? "Yes" : "No")
               << std::endl;
      }

      report.close();
      return true;
    } catch (const std::exception &) {
      return false;
    }
  }

  int getTotalInfected() const { return scan_results.size(); }
};

// Multi-threaded scanner using ClamAV
class ClamAVScanner {
private:
  struct cl_engine *engine;
  unsigned int signature_count;
  struct cl_scan_options scan_options;
  Logger &logger;
  QuarantineManager &quarantine;
  ReportGenerator &report;
  std::atomic<int> files_scanned;
  std::atomic<int> infected_count;
  std::mutex engine_mutex;
  std::atomic<unsigned long long> total_bytes_scanned = 0;
  // Worker thread function
  void scanWorker(const std::vector<std::string> &files, bool auto_quarantine) {
    for (const auto &file : files) {
      try {
        auto [infected, virus_name] = scanSingleFile(file);
        files_scanned++;

        if (infected) {
          infected_count++;
          logger.log(Logger::WARNING,
                     "VIRUS FOUND: " + file + " - " + virus_name);

          bool quarantined = false;
          if (auto_quarantine) {
            quarantined = quarantine.quarantineFile(file);
          }

          report.addResult(file, virus_name, quarantined);
        }
      } catch (const std::exception &e) {
        logger.log(Logger::ERROR,
                   "Error scanning file " + file + ": " + e.what());
      }
    }
  }

  // Distribute files among worker threads
  std::vector<std::vector<std::string>>
  distributeFiles(const std::vector<std::string> &files, int num_threads) {
    std::vector<std::vector<std::string>> distributed(num_threads);

    for (size_t i = 0; i < files.size(); i++) {
      distributed[i % num_threads].push_back(files[i]);
    }

    return distributed;
  }

public:
  ClamAVScanner(Logger &log, QuarantineManager &qm, ReportGenerator &rep)
      : engine(nullptr), signature_count(0), logger(log), quarantine(qm),
        report(rep), files_scanned(0), infected_count(0) {

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
    scan_options.parse = CL_SCAN_PARSE_ARCHIVE;        // Parse archives
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

  bool loadDatabase(const std::string &db_path) {
    std::lock_guard<std::mutex> lock(engine_mutex);

    logger.log(Logger::INFO, "Loading virus database from: " + db_path);

    int ret = cl_load(db_path.c_str(), engine, &signature_count, CL_DB_STDOPT);
    if (ret != CL_SUCCESS) {
      logger.log(Logger::ERROR, "Error loading database: " +
                                    std::string(cl_strerror((cl_error_t)ret)));
      return false;
    }

    // Compile the loaded database
    if ((ret = cl_engine_compile(engine)) != CL_SUCCESS) {
      logger.log(Logger::ERROR, "Engine compilation error: " +
                                    std::string(cl_strerror((cl_error_t)ret)));
      return false;
    }

    logger.log(Logger::INFO, "Loaded " + std::to_string(signature_count) +
                                 " virus signatures");
    return true;
  }

std::pair<bool, std::string> scanSingleFile(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(engine_mutex);
    
    const size_t CHUNK_SIZE = 30 * 1024 * 1024; // 30 MB chunks
    const size_t OVERLAP_SIZE = 15 * 1024 * 1024; // 15 MB overlap
    
    // Check if file exists and can be opened
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        logger.log(Logger::ERROR, "Could not open file for scanning: " + filepath);
        return {false, "error: file could not be opened"};
    }
    
    // Get file size
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    file.close(); // Close the file after checking size
    
    logger.log(Logger::INFO, "Determining file type for: " + filepath);
    
    // Get file extension as a fallback
    std::string ext = fs::path(filepath).extension().string();
    for(char& c : ext) {
        c = std::tolower(c);
    }
    
    // Check file signature (magic numbers) to determine file type
    std::ifstream magicFile(filepath, std::ios::binary);
    if (!magicFile) {
        logger.log(Logger::ERROR, "Could not open file for type detection: " + filepath);
        return {false, "error: file could not be opened for type detection"};
    }
    
    // Use a larger buffer for detecting signatures deeper in the file (like ISO9660)
    unsigned char header[32774] = {0}; 
    
    // Read the first part of the file (or the whole file if it's smaller)
    std::streamsize bytes_read = 0;
    try {
        magicFile.read(reinterpret_cast<char*>(header), sizeof(header));
        bytes_read = magicFile.gcount();
        magicFile.close();
        
        if (bytes_read < 8) {
            logger.log(Logger::WARNING, "File too small for reliable format detection: " + filepath);
        }
    } catch (const std::exception& e) {
        magicFile.close();
        logger.log(Logger::ERROR, "Error reading file header: " + std::string(e.what()));
        // Continue with what we have
    }
    
    // Detect archive types by magic numbers
    bool isTarArchive = false;
    bool isZipArchive = false;
    bool isGzipArchive = false;
    bool isBzip2Archive = false;
    bool isRarArchive = false;
    bool is7zArchive = false;
    bool isArchive = false;
    std::string detectedFileType = "unknown";
    
    // ZIP: starts with "PK\x03\x04"
    if (header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04) {
        isZipArchive = true;
        isArchive = true;
        detectedFileType = "ZIP archive";
    }
    // GZIP: starts with "\x1F\x8B"
    else if (header[0] == 0x1F && header[1] == 0x8B) {
        isGzipArchive = true;
        isArchive = true;
        detectedFileType = "GZIP archive";
    }
    // BZIP2: starts with "BZh"
    else if (header[0] == 0x42 && header[1] == 0x5A && header[2] == 0x68) {
        isBzip2Archive = true;
        isArchive = true;
        detectedFileType = "BZIP2 archive";
    }
    // RAR: starts with "Rar!\x1A\x07\x00" or "Rar!\x1A\x07\x01"
    else if (header[0] == 0x52 && header[1] == 0x61 && header[2] == 0x72 && 
             header[3] == 0x21 && header[4] == 0x1A && header[5] == 0x07 &&
             (header[6] == 0x00 || header[6] == 0x01)) {
        isRarArchive = true;
        isArchive = true;
        detectedFileType = "RAR archive";
    }
    // 7Z: starts with "7z\xBC\xAF\x27\x1C"
    else if (header[0] == 0x37 && header[1] == 0x7A && header[2] == 0xBC && 
             header[3] == 0xAF && header[4] == 0x27 && header[5] == 0x1C) {
        is7zArchive = true;
        isArchive = true;
        detectedFileType = "7Z archive";
    }
    // TAR: check for "ustar" at offset 257
    else if (header[257] == 'u' && header[258] == 's' && header[259] == 't' && 
             header[260] == 'a' && header[261] == 'r') {
        isTarArchive = true;
        isArchive = true;
        detectedFileType = "TAR archive";
    }
    
    // If we didn't detect by magic but the extension suggests an archive, log it and try anyway
    if (!isArchive && (ext == ".tar" || ext == ".tgz" || ext == ".tbz" || ext == ".tbz2" || 
                       ext == ".zip" || ext == ".gz" || ext == ".bz2" || 
                       ext == ".rar" || ext == ".7z")) {
        logger.log(Logger::WARNING, "File has archive-like extension but signature not detected: " + filepath);
        
        // Trust the extension for these common types
        if (ext == ".tar") {
            isTarArchive = true;
            isArchive = true;
            detectedFileType = "TAR archive (by extension)";
        }
        else if (ext == ".tgz") {
            isGzipArchive = true;
            isArchive = true;
            detectedFileType = "GZIP compressed TAR (by extension)";
        }
        else if (ext == ".tbz" || ext == ".tbz2") {
            isBzip2Archive = true;
            isArchive = true;
            detectedFileType = "BZIP2 compressed TAR (by extension)";
        }
        else if (ext == ".zip") {
            isZipArchive = true;
            isArchive = true;
            detectedFileType = "ZIP archive (by extension)";
        }
        else if (ext == ".gz") {
            isGzipArchive = true;
            isArchive = true;
            detectedFileType = "GZIP archive (by extension)";
        }
        else if (ext == ".bz2") {
            isBzip2Archive = true;
            isArchive = true;
            detectedFileType = "BZIP2 archive (by extension)";
        }
        else if (ext == ".rar") {
            isRarArchive = true;
            isArchive = true;
            detectedFileType = "RAR archive (by extension)";
        }
        else if (ext == ".7z") {
            is7zArchive = true;
            isArchive = true;
            detectedFileType = "7Z archive (by extension)";
        }
    }
    
    // Special case for .img files: Try to determine actual type by content
    if (!isArchive && ext == ".img") {
        logger.log(Logger::INFO, "Found .img file, attempting detailed format detection: " + filepath);
        
        // First check if it might be a TAR by looking for "ustar" at offset 257
        if (header[257] == 'u' && header[258] == 's' && header[259] == 't' && 
            header[260] == 'a' && header[261] == 'r') {
            isTarArchive = true;
            isArchive = true;
            detectedFileType = "TAR archive in .img file";
            logger.log(Logger::INFO, "Detected TAR format inside .img file");
        }
        // Check for ISO9660 signature (if we read enough bytes)
        else if (bytes_read >= 32774 && 
                 header[32769] == 'C' && header[32770] == 'D' && header[32771] == '0' && 
                 header[32772] == '0' && header[32773] == '1') {
            // It's an ISO image, which isn't a standard archive format ClamAV handles well
            // We'll use direct scanning but not extraction
            isArchive = false;
            detectedFileType = "ISO9660 disk image";
            logger.log(Logger::INFO, "Detected ISO9660 format in .img file");
        }
        else {
            detectedFileType = "Unknown binary (.img)";
            logger.log(Logger::INFO, "Unknown binary format in .img file, will use default scanning");
        }
    }
    
    // Log the detected file type
    logger.log(Logger::INFO, "File type detected: " + detectedFileType + " for file: " + filepath);
    
    // For small files or already established archives, use direct scanning
    if (fileSize <= CHUNK_SIZE || isArchive) {
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
    
    // For archives, try to extract and scan content
    if (isArchive) {
        logger.log(Logger::INFO, "Archive detected, extracting and scanning content: " + filepath);
        
        // Create a temporary directory for extraction
        char tempDirTemplate[] = "/tmp/clamav_scan_XXXXXX";
        char* tempDirPath = mkdtemp(tempDirTemplate);
        if (tempDirPath == nullptr) {
            logger.log(Logger::ERROR, "Failed to create temporary directory for archive extraction");
            return {false, "error: could not create temporary extraction directory"};
        }
        
        std::string tempDir(tempDirPath);
        logger.log(Logger::DEBUG, "Created temporary directory: " + tempDir);
        
        bool extractionSuccess = false;
        
        // Extract files based on archive type
        if (isTarArchive) {
            // Extract tar using tar command
            std::string extractCmd = "tar -xf \"" + filepath + "\" -C \"" + tempDir + "\"";
            logger.log(Logger::DEBUG, "Executing: " + extractCmd);
            int result = system(extractCmd.c_str());
            extractionSuccess = (result == 0);
        } else if (isZipArchive) {
            // Extract zip using unzip command
            std::string extractCmd = "unzip -q \"" + filepath + "\" -d \"" + tempDir + "\"";
            logger.log(Logger::DEBUG, "Executing: " + extractCmd);
            int result = system(extractCmd.c_str());
            extractionSuccess = (result == 0);
        } else if (isGzipArchive) {
            // For .gz files (single file compression)
            std::string basename = fs::path(filepath).filename().string();
            // Remove .gz extension if present
            if (basename.length() > 3 && basename.substr(basename.length() - 3) == ".gz") {
                basename = basename.substr(0, basename.length() - 3);
            }
            
            std::string outputFile = tempDir + "/" + basename;
            std::string extractCmd = "gzip -dc \"" + filepath + "\" > \"" + outputFile + "\"";
            logger.log(Logger::DEBUG, "Executing: " + extractCmd);
            int result = system(extractCmd.c_str());
            extractionSuccess = (result == 0);
        } else if (isBzip2Archive) {
            // For .bz2 files (single file compression)
            std::string basename = fs::path(filepath).filename().string();
            // Remove .bz2 extension if present
            if (basename.length() > 4 && basename.substr(basename.length() - 4) == ".bz2") {
                basename = basename.substr(0, basename.length() - 4);
            }
            
            std::string outputFile = tempDir + "/" + basename;
            std::string extractCmd = "bzip2 -dc \"" + filepath + "\" > \"" + outputFile + "\"";
            logger.log(Logger::DEBUG, "Executing: " + extractCmd);
            int result = system(extractCmd.c_str());
            extractionSuccess = (result == 0);
        } else {
            // For other archive types, use libarchive directly or fall back to ClamAV's built-in extraction
            logger.log(Logger::INFO, "Using ClamAV's built-in extraction for " + ext + " archive");
            
            const char* virus_name = nullptr;
            unsigned long scanned = 0;
            
            struct cl_scan_options archive_options = scan_options;
            archive_options.parse |= CL_SCAN_PARSE_ARCHIVE | CL_SCAN_PARSE_OLE2 | 
                                    CL_SCAN_PARSE_PDF | CL_SCAN_PARSE_HTML |
                                    CL_SCAN_PARSE_MAIL;
            
            int scan_result = cl_scanfile(filepath.c_str(), &virus_name, &scanned, engine, &archive_options);
            
            // Clean up temp dir (though it might be empty in this case)
            std::string rmCmd = "rm -rf \"" + tempDir + "\"";
            system(rmCmd.c_str());
            
            // Add to total bytes counter
            total_bytes_scanned += scanned;
            
            if (scan_result == CL_VIRUS) {
                return {true, virus_name ? virus_name : "unknown virus"};
            } else if (scan_result != CL_CLEAN) {
                return {false, std::string("Error scanning archive: ") + cl_strerror((cl_error_t)scan_result)};
            }
            
            return {false, "clean"};
        }
        
        if (!extractionSuccess) {
            logger.log(Logger::ERROR, "Failed to extract archive: " + filepath);
            
            // Clean up temp dir
            std::string rmCmd = "rm -rf \"" + tempDir + "\"";
            system(rmCmd.c_str());
            
            // Fall back to direct scanning with ClamAV's built-in extraction
            logger.log(Logger::INFO, "Falling back to ClamAV's built-in extraction");
            const char* virus_name = nullptr;
            unsigned long scanned = 0;
            
            struct cl_scan_options archive_options = scan_options;
            archive_options.parse |= CL_SCAN_PARSE_ARCHIVE | CL_SCAN_PARSE_OLE2 | 
                                    CL_SCAN_PARSE_PDF | CL_SCAN_PARSE_HTML |
                                    CL_SCAN_PARSE_MAIL;
            
            int scan_result = cl_scanfile(filepath.c_str(), &virus_name, &scanned, engine, &archive_options);
            
            // Add to total bytes counter
            total_bytes_scanned += scanned;
            
            if (scan_result == CL_VIRUS) {
                return {true, virus_name ? virus_name : "unknown virus"};
            } else if (scan_result != CL_CLEAN) {
                return {false, std::string("Error scanning archive: ") + cl_strerror((cl_error_t)scan_result)};
            }
            
            return {false, "clean"};
        }
        
        // Scan each extracted file with recursive handling for nested archives
        std::vector<std::string> extracted_files;
        bool virus_found = false;
        std::string virus_name_str;
        
        // Function for recursive scanning of extracted archives
        std::function<std::pair<bool, std::string>(const std::string&, int)> scanRecursively = 
            [&](const std::string& file_path, int depth) -> std::pair<bool, std::string> {
                // Prevent infinite recursion - limit depth to 10 layers
                if (depth > 10) {
                    logger.log(Logger::WARNING, "Maximum archive recursion depth (10) reached for: " + file_path);
                    return {false, "recursion_limit"};
                }
                
                logger.log(Logger::DEBUG, "Recursive scan level " + std::to_string(depth) + ": " + file_path);
                
                // Get file size
                std::error_code ec;
                uintmax_t fileSize = fs::file_size(file_path, ec);
                if (ec) {
                    logger.log(Logger::ERROR, "Could not get file size: " + file_path + " - " + ec.message());
                    return {false, "file_error"};
                }
                
                // Determine file type
                std::string ext = fs::path(file_path).extension().string();
                for(char& c : ext) {
                    c = std::tolower(c);
                }
                
                // Check file signature
                std::ifstream magicFile(file_path, std::ios::binary);
                if (!magicFile) {
                    logger.log(Logger::ERROR, "Could not open file for type detection: " + file_path);
                    return {false, "error: file could not be opened for type detection"};
                }
                
                unsigned char header[512] = {0};
                std::streamsize bytes_read = 0;
                try {
                    magicFile.read(reinterpret_cast<char*>(header), sizeof(header));
                    bytes_read = magicFile.gcount();
                    magicFile.close();
                } catch (const std::exception& e) {
                    magicFile.close();
                    logger.log(Logger::ERROR, "Error reading file header: " + std::string(e.what()));
                }
                
                // Detect archive types by magic numbers
                bool isNestedArchive = false;
                bool isTarArchive = false;
                bool isZipArchive = false;
                bool isGzipArchive = false;
                bool isBzip2Archive = false;
                bool isRarArchive = false;
                bool is7zArchive = false;
                
                // ZIP: starts with "PK\x03\x04"
                if (bytes_read >= 4 && header[0] == 0x50 && header[1] == 0x4B && 
                    header[2] == 0x03 && header[3] == 0x04) {
                    isZipArchive = true;
                    isNestedArchive = true;
                    logger.log(Logger::INFO, "Found nested ZIP archive: " + file_path);
                }
                // GZIP: starts with "\x1F\x8B"
                else if (bytes_read >= 2 && header[0] == 0x1F && header[1] == 0x8B) {
                    isGzipArchive = true;
                    isNestedArchive = true;
                    logger.log(Logger::INFO, "Found nested GZIP archive: " + file_path);
                }
                // BZIP2: starts with "BZh"
                else if (bytes_read >= 3 && header[0] == 0x42 && header[1] == 0x5A && header[2] == 0x68) {
                    isBzip2Archive = true;
                    isNestedArchive = true;
                    logger.log(Logger::INFO, "Found nested BZIP2 archive: " + file_path);
                }
                // RAR: starts with "Rar!\x1A\x07\x00" or "Rar!\x1A\x07\x01"
                else if (bytes_read >= 7 && header[0] == 0x52 && header[1] == 0x61 && 
                         header[2] == 0x72 && header[3] == 0x21 && header[4] == 0x1A && 
                         header[5] == 0x07 && (header[6] == 0x00 || header[6] == 0x01)) {
                    isRarArchive = true;
                    isNestedArchive = true;
                    logger.log(Logger::INFO, "Found nested RAR archive: " + file_path);
                }
                // 7Z: starts with "7z\xBC\xAF\x27\x1C"
                else if (bytes_read >= 6 && header[0] == 0x37 && header[1] == 0x7A && 
                         header[2] == 0xBC && header[3] == 0xAF && header[4] == 0x27 && 
                         header[5] == 0x1C) {
                    is7zArchive = true;
                    isNestedArchive = true;
                    logger.log(Logger::INFO, "Found nested 7Z archive: " + file_path);
                }
                // TAR: check for "ustar" at offset 257
                else if (bytes_read >= 262 && header[257] == 'u' && header[258] == 's' && 
                         header[259] == 't' && header[260] == 'a' && header[261] == 'r') {
                    isTarArchive = true;
                    isNestedArchive = true;
                    logger.log(Logger::INFO, "Found nested TAR archive: " + file_path);
                }
                
                // Also check by extension if signature check failed
                if (!isNestedArchive && (ext == ".tar" || ext == ".tgz" || ext == ".tbz" || 
                                     ext == ".tbz2" || ext == ".zip" || ext == ".gz" || 
                                     ext == ".bz2" || ext == ".rar" || ext == ".7z")) {
                    // Trust the extension for common types
                    if (ext == ".tar") {
                        isTarArchive = true;
                        isNestedArchive = true;
                    }
                    else if (ext == ".zip") {
                        isZipArchive = true;
                        isNestedArchive = true;
                    }
                    else if (ext == ".gz" || ext == ".tgz") {
                        isGzipArchive = true;
                        isNestedArchive = true;
                    }
                    else if (ext == ".bz2" || ext == ".tbz" || ext == ".tbz2") {
                        isBzip2Archive = true;
                        isNestedArchive = true;
                    }
                    else if (ext == ".rar") {
                        isRarArchive = true;
                        isNestedArchive = true;
                    }
                    else if (ext == ".7z") {
                        is7zArchive = true;
                        isNestedArchive = true;
                    }
                    
                    if (isNestedArchive) {
                        logger.log(Logger::INFO, "Found nested archive by extension: " + file_path);
                    }
                }
                
                // If this is a nested archive, extract and scan its contents
                if (isNestedArchive) {
                    // Create a temporary directory for nested extraction
                    char nestedTempDir[] = "/tmp/clamav_nested_XXXXXX";
                    char* nestedDirPath = mkdtemp(nestedTempDir);
                    if (nestedDirPath == nullptr) {
                        logger.log(Logger::ERROR, "Failed to create temp dir for nested archive: " + file_path);
                        // Fall back to direct scanning
                        goto direct_scan;
                    }
                    
                    std::string nestedDir(nestedDirPath);
                    logger.log(Logger::DEBUG, "Created nested temporary directory: " + nestedDir);
                    
                    bool extractionSuccess = false;
                    
                    // Extract files based on archive type
                    if (isTarArchive) {
                        std::string extractCmd = "tar -xf \"" + file_path + "\" -C \"" + nestedDir + "\"";
                        logger.log(Logger::DEBUG, "Executing: " + extractCmd);
                        int result = system(extractCmd.c_str());
                        extractionSuccess = (result == 0);
                    } else if (isZipArchive) {
                        std::string extractCmd = "unzip -q \"" + file_path + "\" -d \"" + nestedDir + "\"";
                        logger.log(Logger::DEBUG, "Executing: " + extractCmd);
                        int result = system(extractCmd.c_str());
                        extractionSuccess = (result == 0);
                    } else if (isGzipArchive) {
                        std::string basename = fs::path(file_path).filename().string();
                        if (basename.length() > 3 && basename.substr(basename.length() - 3) == ".gz") {
                            basename = basename.substr(0, basename.length() - 3);
                        }
                        
                        std::string outputFile = nestedDir + "/" + basename;
                        std::string extractCmd = "gzip -dc \"" + file_path + "\" > \"" + outputFile + "\"";
                        logger.log(Logger::DEBUG, "Executing: " + extractCmd);
                        int result = system(extractCmd.c_str());
                        extractionSuccess = (result == 0);
                    } else if (isBzip2Archive) {
                        std::string basename = fs::path(file_path).filename().string();
                        if (basename.length() > 4 && basename.substr(basename.length() - 4) == ".bz2") {
                            basename = basename.substr(0, basename.length() - 4);
                        }
                        
                        std::string outputFile = nestedDir + "/" + basename;
                        std::string extractCmd = "bzip2 -dc \"" + file_path + "\" > \"" + outputFile + "\"";
                        logger.log(Logger::DEBUG, "Executing: " + extractCmd);
                        int result = system(extractCmd.c_str());
                        extractionSuccess = (result == 0);
                    } else if (isRarArchive) {
                        std::string extractCmd = "unrar x -o+ \"" + file_path + "\" \"" + nestedDir + "\"";
                        logger.log(Logger::DEBUG, "Executing: " + extractCmd);
                        int result = system(extractCmd.c_str());
                        extractionSuccess = (result == 0);
                    } else if (is7zArchive) {
                        std::string extractCmd = "7z x -o\"" + nestedDir + "\" \"" + file_path + "\"";
                        logger.log(Logger::DEBUG, "Executing: " + extractCmd);
                        int result = system(extractCmd.c_str());
                        extractionSuccess = (result == 0);
                    }
                    
                    if (extractionSuccess) {
                        std::vector<std::string> nested_files;
                        
                        // List all files in the nested extraction directory
                        try {
                            for (const auto& entry : fs::recursive_directory_iterator(nestedDir)) {
                                if (fs::is_regular_file(entry)) {
                                    nested_files.push_back(entry.path().string());
                                }
                            }
                            
                            logger.log(Logger::INFO, "Extracted " + std::to_string(nested_files.size()) + 
                                      " files from nested archive: " + file_path);
                            
                            // Recursive scan each extracted file
                            for (const auto& nested_file : nested_files) {
                                // Use recursion to handle nested archives
                                auto [nested_infected, nested_virus] = scanRecursively(nested_file, depth + 1);
                                
                                if (nested_infected) {
                                    logger.log(Logger::WARNING, "Virus found in nested archive: " + 
                                              nested_file + " (from " + file_path + ") - " + nested_virus);
                                    
                                    // Clean up before returning
                                    std::string rmCmd = "rm -rf \"" + nestedDir + "\"";
                                    system(rmCmd.c_str());
                                    
                                    return {true, nested_virus};
                                }
                            }
                            
                            // If we get here, no virus was found in the nested archive
                            logger.log(Logger::DEBUG, "No virus found in nested archive: " + file_path);
                            
                            // Clean up the temporary directory
                            std::string rmCmd = "rm -rf \"" + nestedDir + "\"";
                            system(rmCmd.c_str());
                            
                            return {false, "clean"};
                            
                        } catch (const std::exception& e) {
                            logger.log(Logger::ERROR, "Error processing nested archive: " + 
                                      std::string(e.what()));
                            
                            // Clean up and fall back to direct scanning
                            std::string rmCmd = "rm -rf \"" + nestedDir + "\"";
                            system(rmCmd.c_str());
                        }
                    } else {
                        logger.log(Logger::WARNING, "Failed to extract nested archive: " + file_path);
                        
                        // Clean up
                        std::string rmCmd = "rm -rf \"" + nestedDir + "\"";
                        system(rmCmd.c_str());
                    }
                }
                
                // If we couldn't process as an archive or it's not an archive, scan directly
            direct_scan:
                const char* virus_name = nullptr;
                unsigned long scanned = 0;
                int scan_result = cl_scanfile(file_path.c_str(), &virus_name, &scanned, engine, &scan_options);
                
                // Add to total bytes counter
                total_bytes_scanned += scanned;
                
                if (scan_result == CL_VIRUS) {
                    logger.log(Logger::WARNING, "Virus found in file: " + file_path);
                    return {true, virus_name ? virus_name : "unknown virus"};
                } else if (scan_result != CL_CLEAN) {
                    logger.log(Logger::ERROR, "Error scanning file: " + 
                              std::string(cl_strerror((cl_error_t)scan_result)));
                }
                
                return {false, "clean"};
            };
        
        try {
            // Recursively list all files in the extraction directory
            for (const auto& entry : fs::recursive_directory_iterator(tempDir)) {
                if (fs::is_regular_file(entry)) {
                    extracted_files.push_back(entry.path().string());
                }
            }
            
            logger.log(Logger::INFO, "Extracted " + std::to_string(extracted_files.size()) + 
                      " files from archive");
            
            // Scan each extracted file
            for (const auto& extracted_file : extracted_files) {
                logger.log(Logger::DEBUG, "Scanning extracted file: " + extracted_file);
                
                // Use recursive scanning to handle nested archives
                auto [file_infected, file_virus] = scanRecursively(extracted_file, 1);
                
                if (file_infected) {
                    logger.log(Logger::WARNING, "Virus found in extracted file: " + 
                               extracted_file + " - " + file_virus);
                    virus_found = true;
                    virus_name_str = file_virus;
                    break; // Stop scanning as soon as a virus is found
                }
            }
        } catch (const std::exception& e) {
            logger.log(Logger::ERROR, "Error processing extracted files: " + std::string(e.what()));
        }
        
        // Clean up the temporary directory
        logger.log(Logger::DEBUG, "Cleaning up temporary directory: " + tempDir);
        std::string rmCmd = "rm -rf \"" + tempDir + "\"";
        system(rmCmd.c_str());
        
        // Return result
        if (virus_found) {
            return {true, virus_name_str};
        }
        
        return {false, "clean"};
    }
    
    // For large files that aren't archives, explicitly state we can't determine file type
    if (fileSize > CHUNK_SIZE && !isArchive) {
        // Try with ClamAV's built-in detection capabilities first
        printf("Large file, but could not determine specific archive type.  Attempting direct scan with ClamAV first\n");
                  
        const char* virus_name = nullptr;
        unsigned long scanned = 0;
        
        // Use comprehensive scan options to let ClamAV try to determine file type
        struct cl_scan_options comprehensive_options = scan_options;
        comprehensive_options.parse |= CL_SCAN_PARSE_ARCHIVE | CL_SCAN_PARSE_OLE2 | 
                                     CL_SCAN_PARSE_PDF | CL_SCAN_PARSE_HTML |
                                     CL_SCAN_PARSE_MAIL;
        
        // Try direct scanning first
        int scan_result = cl_scanfile(filepath.c_str(), &virus_name, &scanned, engine, 
                                     &comprehensive_options);
        
        // Add to total bytes counter
        total_bytes_scanned += scanned;
        
        // If ClamAV could process it successfully, we're done
        if (scan_result == CL_VIRUS) {
            logger.log(Logger::WARNING, "Virus found by direct ClamAV scan: " + filepath);
            return {true, virus_name ? virus_name : "unknown virus"};
        } else if (scan_result == CL_CLEAN) {
            logger.log(Logger::INFO, "File scanned clean by direct ClamAV scan: " + filepath);
            return {false, "clean"};
        }
        
        // If ClamAV couldn't handle it, fall back to chunked scanning as last resort
        logger.log(Logger::WARNING, "ClamAV could not determine file type. Falling back to chunked scanning as last resort: " + filepath);
    }
    
    std::vector<char> buffer(CHUNK_SIZE);
    size_t position = 0;
    
    std::ifstream largeFile(filepath, std::ios::binary);
    if (!largeFile) {
        logger.log(Logger::ERROR, "Could not reopen file for chunk scanning: " + filepath);
        return {false, "error: file could not be reopened for chunk scanning"};
    }
    
    while (position < fileSize) {
        size_t bytesToRead = std::min(CHUNK_SIZE, fileSize - position);
        
        // Read chunk into memory
        largeFile.seekg(position);
        largeFile.read(buffer.data(), bytesToRead);
        
        // Create a temporary file for this chunk
        std::string tempFilename = createTempFile();
        if (tempFilename.empty()) {
            logger.log(Logger::ERROR, "Could not create temporary file for chunk scanning");
            return {false, "error: could not create temporary chunk file"};
        }
        
        std::ofstream tempFile(tempFilename, std::ios::binary);
        if (!tempFile) {
            logger.log(Logger::ERROR, "Could not open temporary file for writing");
            std::remove(tempFilename.c_str());
            return {false, "error: could not open temporary file for writing"};
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
    
    // Close the large file after scanning all chunks
    largeFile.close();
    
    // If we got here, no virus was found
    logger.log(Logger::INFO, "Completed chunked scan of file: " + filepath + 
               " (" + std::to_string(fileSize / (1024.0 * 1024.0)) + " MB)");
    
    return {false, "clean"};
}

  void scanFiles(const std::vector<std::string> &files,
                 bool auto_quarantine = false, int num_threads = 4) {
    // Reset counters
    files_scanned = 0;
    infected_count = 0;

    logger.log(Logger::INFO,
               "Starting scan of " + std::to_string(files.size()) +
                   " files using " + std::to_string(num_threads) + " threads");

    // Distribute files among threads
    auto distributed_files = distributeFiles(files, num_threads);

    // Create and start worker threads
    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; i++) {
      if (!distributed_files[i].empty()) {
        threads.emplace_back(&ClamAVScanner::scanWorker, this,
                             distributed_files[i], auto_quarantine);
      }
    }

    // Wait for all threads to finish
    for (auto &thread : threads) {
      thread.join();
    }

    logger.log(Logger::INFO,
               "Scan completed. Scanned " + std::to_string(files_scanned) +
                   " files, found " + std::to_string(infected_count) +
                   " infections");
  }

  void scanDirectory(const std::string &directory_path, bool recursive = false,
                     bool auto_quarantine = false, int num_threads = 4) {
    std::vector<std::string> files_to_scan;

    logger.log(Logger::INFO,
               "Collecting files from directory: " + directory_path +
                   (recursive ? " (recursively)" : ""));

    try {
      if (recursive) {
        for (const auto &entry :
             fs::recursive_directory_iterator(directory_path)) {
          if (fs::is_regular_file(entry)) {
            files_to_scan.push_back(entry.path().string());
          }
        }
      } else {
        for (const auto &entry : fs::directory_iterator(directory_path)) {
          if (fs::is_regular_file(entry)) {
            files_to_scan.push_back(entry.path().string());
          }
        }
      }

      logger.log(Logger::INFO, "Found " + std::to_string(files_to_scan.size()) +
                                   " files to scan");

      // Start scanning files
      scanFiles(files_to_scan, auto_quarantine, num_threads);

    } catch (const std::exception &e) {
      logger.log(Logger::ERROR,
                 "Error scanning directory: " + std::string(e.what()));
    }
  }

  int getScannedCount() const { return files_scanned; }

  int getInfectedCount() const { return infected_count; }
};

void printUsage(const char *programName) {
  std::cout << "Usage: " << programName << " [OPTIONS] [PATH]" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -h, --help          Show this help message" << std::endl;
  std::cout << "  -r, --recursive     Scan directories recursively"
            << std::endl;
  std::cout << "  -d, --database      Specify ClamAV database directory "
               "(default: /var/lib/clamav)"
            << std::endl;
  std::cout << "  -f, --file          Scan a single file" << std::endl;
  std::cout << "  -q, --quarantine    Auto-quarantine infected files"
            << std::endl;
  std::cout << "  -t, --threads       Number of scanner threads (default: 4)"
            << std::endl;
  std::cout << "  -l, --log           Log file path (default: scanner.log)"
            << std::endl;
  std::cout
      << "  --quarantine-dir    Quarantine directory (default: ./quarantine)"
      << std::endl;
  std::cout << "  --report-txt        Generate text report file" << std::endl;
  std::cout << "  --report-csv        Generate CSV report file" << std::endl;
}

int main(int argc, char *argv[]) {
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
        if (num_threads < 1)
          num_threads = 1;
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
        logger.log(Logger::WARNING,
                   "VIRUS FOUND: " + scan_path + " - " + virus_name);
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
            logger.log(Logger::INFO,
                       "Text report generated: " + text_report_path);
          } else {
            logger.log(Logger::ERROR, "Failed to generate text report");
          }
        }

        if (!csv_report_path.empty()) {
          if (report.generateCSVReport(csv_report_path)) {
            logger.log(Logger::INFO,
                       "CSV report generated: " + csv_report_path);
          } else {
            logger.log(Logger::ERROR, "Failed to generate CSV report");
          }
        }

        return 2; // Return code for virus found
      } else if (virus_name != "clean") {
        logger.log(Logger::ERROR,
                   "Error scanning file: " + scan_path + " - " + virus_name);
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

      logger.log(Logger::INFO,
                 "Scanning directory: " + scan_path +
                     (recursive ? " (recursively)" : "") +
                     (auto_quarantine ? " with auto-quarantine" : ""));

      scanner.scanDirectory(scan_path, recursive, auto_quarantine, num_threads);

      // Generate reports if requested
      if (!text_report_path.empty()) {
        if (report.generateTextReport(text_report_path)) {
          logger.log(Logger::INFO,
                     "Text report generated: " + text_report_path);
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

      logger.log(Logger::INFO, "Scan completed. Scanned " +
                                   std::to_string(scanner.getScannedCount()) +
                                   " files, found " +
                                   std::to_string(scanner.getInfectedCount()) +
                                   " infections");

      return scanner.getInfectedCount() > 0 ? 2 : 0;
    }
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
