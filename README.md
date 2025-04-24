# Enhanced Virus Scanner

A powerful, multi-threaded virus scanner built on top of the ClamAV antivirus engine with advanced features including quarantine management, detailed logging, and comprehensive reporting.

## Features

- **High Performance Scanning**: Multi-threaded architecture for optimal performance
- **Quarantine System**: Isolation of infected files with restoration capability
- **Comprehensive Logging**: Multiple logging levels with both file and console output
- **Detailed Reporting**: Generate reports in both text and CSV formats
- **Recursive Directory Scanning**: Thoroughly scan entire directory trees
- **Thread Safety**: Designed with proper synchronization for reliable parallel operation

## Requirements

- C++17 compatible compiler
- ClamAV development libraries (libclamav-dev)
- Boost libraries (filesystem, system)
- ClamAV virus definitions

## Installation

### Dependencies

#### Debian/Ubuntu
```bash
sudo apt update
sudo apt install build-essential libclamav-dev libboost-filesystem-dev libboost-system-dev clamav-freshclam
```

#### RHEL/Fedora/CentOS
```bash
sudo dnf install gcc-c++ clamav-devel boost-devel clamav-update
```

#### macOS (using Homebrew)
```bash
brew install clamav boost
```

### Building

```bash
# Clone or download the repository
git clone https://github.com/yourusername/virus-scanner.git
cd virus-scanner

# Compile
make

# Verify installation
./virus_scanner --help
```

### Installing System-wide (optional)

```bash
sudo make install
```

## Usage

```
./virus_scanner [OPTIONS] [PATH]
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message |
| `-r, --recursive` | Scan directories recursively |
| `-d, --database` | Specify ClamAV database directory (default: /var/lib/clamav) |
| `-f, --file` | Scan a single file |
| `-q, --quarantine` | Auto-quarantine infected files |
| `-t, --threads` | Number of scanner threads (default: 4) |
| `-l, --log` | Log file path (default: scanner.log) |
| `--quarantine-dir` | Quarantine directory (default: ./quarantine) |
| `--report-txt` | Generate text report file |
| `--report-csv` | Generate CSV report file |

### Example Commands

Basic scan of current directory:
```bash
./virus_scanner .
```

Recursive scan with auto-quarantine:
```bash
./virus_scanner -r -q /path/to/directory
```

Scan a specific file:
```bash
./virus_scanner -f /path/to/suspicious.file
```

Use 8 threads for faster scanning:
```bash
./virus_scanner -t 8 -r /path/to/directory
```

Generate both text and CSV reports:
```bash
./virus_scanner -r --report-txt report.txt --report-csv report.csv /path/to/directory
```

## Return Codes

| Code | Description |
|------|-------------|
| 0 | Success (no viruses found) |
| 1 | Error occurred |
| 2 | Virus found |

## Quarantine Management

The quarantine system safely isolates infected files while maintaining information about their original location and detection time. Quarantined files can be:

- Listed using the quarantine manager
- Restored to their original or alternate location
- Deleted permanently when no longer needed

## Updating Virus Definitions

For the scanner to be effective, virus definitions should be kept up to date:

```bash
# Update ClamAV virus definitions
sudo freshclam
```

## Logging

The scanner provides detailed logging with configurable levels (DEBUG, INFO, WARNING, ERROR, CRITICAL). Logs are written to both the console and a log file by default.

## Performance Tips

- Adjust the number of threads (`-t`) based on your system's CPU cores
- For large file systems, consider scanning specific directories rather than using recursive mode on top-level directories
- Regularly update virus definitions for optimal detection

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- [ClamAV](https://www.clamav.net/) for the powerful open-source antivirus eng
