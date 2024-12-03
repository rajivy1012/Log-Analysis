# Log Analyzer 🕵️‍♂️🔍

## Overview

The Web Server Log Analyzer is a powerful Python script designed to extract valuable insights from web server log files. It provides comprehensive analysis of server request patterns, helps identify potential security threats, and generates detailed reports.

## Features

✨ **Comprehensive Log Analysis**
- Detailed request tracking per IP address
- Identification of most frequently accessed endpoints
- Advanced suspicious activity detection
- Easy-to-read CSV export

### Key Capabilities

1. 📊 **Detailed Request Tracking**
   - Count requests for each unique IP address
   - Identify usage patterns and traffic sources
   - Highlight most active clients

2. 🔒 **Security Threat Detection**
   - Monitor failed login attempts
   - Flag potentially malicious IP addresses
   - Early warning system for potential security risks

3. 📈 **Flexible Reporting**
   - Console summary output
   - Comprehensive CSV report generation
   - Easy data visualization and further analysis

## Prerequisites

### Requirements
- Python 3.x
- No external library dependencies
- Web server log file in standard format

### Supported Log Formats
- Compatible with standard web server log formats
- Supports parsing of:
  - IP Addresses
  - HTTP Methods
  - Endpoints
  - Status Codes

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/web-server-log-analyzer.git
   cd web-server-log-analyzer
   ```

2. Ensure you have Python 3.x installed:
   ```bash
   python --version
   ```

## Usage

### Quick Start

1. Place your log file (e.g., `sample.log`) in the script directory

2. Run the script:
   ```bash
   python log_analysis.py
   ```

### Customization

- Modify `suspicious_threshold` in the script to adjust sensitivity of suspicious activity detection
- Change log file path in the `main()` function

## Example Output

### Console Summary
```
--- Log Analysis Summary ---

Top 5 IP Addresses by Request Count:
192.168.1.100     45 requests
203.0.113.59      32 requests
10.0.0.271        28 requests

Most Frequently Accessed Endpoint:
/home (Accessed 6 times)

Suspicious Activity:
Potential security threats detected:
203.0.113.59     4 failed login attempts
```

### CSV Report Sections
1. IP Address Request Counts
2. Most Accessed Endpoint
3. Suspicious IP Addresses

## Advanced Configuration

### Adjusting Parameters
- `suspicious_threshold`: Control sensitivity of suspicious activity detection
- Modify regex patterns to support different log formats

## Security Considerations

- Never run on log files from untrusted sources
- Protect sensitive log files
- Regularly review and update log analysis scripts

## Contributing

Contributions are welcome! Please feel free to:
- Submit bug reports
- Suggest new features
- Send pull requests




