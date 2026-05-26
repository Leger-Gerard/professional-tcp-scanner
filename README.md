# TCP Port Scanner

A professional TCP port scanner built with Python Typer and Rich for security assessments and network diagnostics.

## Features

- 🔍 **Professional CLI**: Built with Typer for intuitive command-line interface
- 🎨 **Rich Output**: Beautiful, colorful terminal output with progress bars and tables
- ⚡ **Concurrent Scanning**: Multi-threaded scanning with configurable thread pools
- 📊 **Multiple Output Formats**: Human-readable tables and JSON export with flexible file output
- 🔍 **Enhanced Service Detection**: Identifies services based on well-known port numbers
- 💾 **Professional Report Export**: Export JSON reports to custom paths with automatic directory creation
- 🛡️ **Security Focused**: Input validation, stealth mode, and proper error handling
- 📝 **Professional Logging**: Rotating logs with different verbosity levels
- 🧪 **Well Tested**: Comprehensive unit tests with >80% code coverage
- 🐳 **Container Ready**: Dockerfile included for easy deployment
- 🔧 **DevOps Friendly**: Makefile and GitHub Actions CI configuration

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd tp-cyber

# Install in development mode
pip install -e .

# Install with development dependencies
pip install -e ".[dev]"
```

## Usage

### Basic Scanning

```bash
# Scan common ports on localhost
port-scanner scan --host 127.0.0.1

# Scan specific ports
port-scanner scan --host example.com --ports 80,443,8080

# Scan a port range
port-scanner scan --host 192.168.1.1 --ports 1-1000
```

### Advanced Options

```bash
# Adjust timeout and threading
port-scanner scan --host target.com --ports 80,443 --timeout 2.0 --threads 50

# Enable JSON output for integration with other tools
port-scanner scan --host target.com --json-output --output results.json

# JSON output with auto-generated filename in reports/ directory
port-scanner scan --host target.com --json-output

# Use stealth mode for security assessments (slower, less detectable)
port-scanner scan --host target.com --stealth --threads 30

# Enable verbose logging for debugging
port-scanner scan --host target.com --verbose

# Disable banner (useful for scripting)
port-scanner scan --host target.com --no-banner
```

### Examples

```bash
# Quick scan of web ports
port-scanner scan --host scanme.nmap.org --ports 80,443,8080,8443

# Full TCP SYN scan equivalent (well-known ports)
port-scanner scan --host 10.0.0.1 --ports 1-1024 --timeout 1.0

# Comprehensive scan with JSON output for later analysis
port-scanner scan --host 192.168.1.100 --ports 1-65535 --json-output --output full-scan.json --threads 200

# Stealth scan for red team operations
port-scanner scan --host target.internal --stealth --threads 20 --timeout 5.0

# Scan with service detection (shows service names in output)
port-scanner scan --host 127.0.0.1 --ports 22,80,443,3306
```

## Architecture

```
src/
└── scanner/
    ├── cli/           # Command-line interface (Typer + Rich)
    ├── core/          # Core scanning logic
    ├── services/      # Service detection and enrichment
    ├── utils/         # Utility functions
    ├── models/        # Data models and schemas
    ├── config/        # Configuration management
    └── reports/       # Report generation and export
```

## Security Considerations

- **Input Validation**: All user inputs are strictly validated
- **No Shell Injection**: Pure Python implementation without subprocess calls
- **Error Handling**: Comprehensive exception handling prevents information leakage
- **Rate Limiting**: Configurable thread counts and timeouts prevent network flooding
- **Logging Security**: Logs are sanitized and stored securely
- **DNS Safety**: Proper timeout handling for DNS resolution

## Development

### Running Tests

```bash
# Run all tests
python -m pytest

# Run tests with coverage
python -m pytest --cov=src --cov-report=term-missing

# Run specific test suites
python -m pytest tests/unit/
```

### Code Quality

```bash
# Check code style
ruff check src

# Fix code style issues
ruff check --fix src

# Type checking
mypy src
```

### Building

```bash
# Build distributable package
python -m build

# Check built packages
twine check dist/*
```

## Docker Usage

```bash
# Build the Docker image
docker build -t port-scanner .

# Run a scan
docker run --rm port-scanner scan --host 127.0.0.1 --ports 80,443

# Scan with JSON output and save to host machine
docker run --rm -v $(pwd)/results:/app/results port-scanner scan \
    --host example.com --json-output --output /app/results/scan.json
```

## Limitations

- **TCP Connect Scans**: Uses TCP connect() scanning rather than raw packet SYN scans (requires root for SYN scans)
- **No UDP Support**: Currently TCP-only (UDP scanning planned for future versions)
- **Basic Service Detection**: Service detection is based on port numbers only
- **Evasion Limitations**: Stealth mode provides basic timing randomization but is not equivalent to advanced evasion techniques

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. 
Users must obtain proper authorization before scanning any networks or systems.
Unauthorized scanning may be illegal in your jurisdiction.
The authors are not liable for any misuse or damage caused by this software.