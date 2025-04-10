# AI_MAL - AI-Powered Penetration Testing Tool

AI_MAL is an advanced penetration testing tool that combines traditional scanning techniques with AI-powered analysis and automation. It integrates with Metasploit, supports custom script generation, and provides comprehensive vulnerability assessment capabilities.

## Features

- AI-powered analysis of scan results
- Metasploit integration for exploitation
- Custom script generation and execution
- Stealth and continuous scanning modes
- Service and version detection
- Vulnerability scanning
- DoS testing capabilities
- Data exfiltration
- Implant deployment
- Rich terminal interface
- Multiple output formats

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/AI_MAL.git
cd AI_MAL
```

2. Make the installation script executable:
```bash
chmod +x install.sh
```

3. Run the installation script:
```bash
./install.sh
```

The installation script will:
- Install required system packages
- Set up Python virtual environment
- Install Python dependencies
- Configure AI models
- Set up necessary services

## Command-Line Arguments

| Argument | Type | Default | Description | Use Case |
|----------|------|---------|-------------|----------|
| `target` | str | required | Target IP address or hostname | Basic scanning target |
| `--stealth` | flag | False | Enable stealth mode for minimal detection | Covert scanning operations |
| `--continuous` | flag | False | Run continuous scanning | Network monitoring |
| `--delay` | int | 300 | Delay between scans in seconds | Continuous monitoring with custom intervals |
| `--services` | flag | False | Enable service detection | Service enumeration |
| `--version` | flag | False | Enable version detection | Version fingerprinting |
| `--os` | flag | False | Enable OS detection | OS fingerprinting |
| `--vuln` | flag | False | Enable vulnerability scanning | Vulnerability assessment |
| `--dos` | flag | False | Enable DoS testing | Service resilience testing |
| `--msf` | flag | False | Enable Metasploit integration | Exploitation framework integration |
| `--exploit` | flag | False | Attempt exploitation of vulnerabilities | Automated exploitation |
| `--custom-scripts` | flag | False | Enable AI-powered script generation | Custom tool development |
| `--script-type` | str | python | Script language (python/bash/ruby) | Language-specific tool development |
| `--execute-scripts` | flag | False | Automatically execute generated scripts | Automated tool execution |
| `--script-output` | str | ./scripts | Output directory for generated scripts | Script management |
| `--script-format` | str | raw | Script format (raw/base64) | Script encoding options |
| `--ai-analysis` | flag | True | Enable AI analysis of results | Enhanced result interpretation |
| `--model` | str | artifish/llama3.2-uncensored | Primary AI model | Custom AI model selection |
| `--fallback-model` | str | gemma3:1b | Fallback AI model | Backup AI model selection |
| `--exfil` | flag | False | Enable data exfiltration | Data extraction operations |
| `--implant` | str | None | Path to implant script | Custom payload deployment |
| `--output-dir` | str | ./results | Output directory for results | Result management |
| `--output-format` | str | json | Output format (xml/json) | Result format selection |
| `--quiet` | flag | False | Suppress progress output | Silent operation |
| `--no-gui` | flag | False | Disable terminal GUI features | Text-only output |
| `--log-level` | str | info | Logging level (debug/info/warning/error) | Debugging and monitoring |
| `--log-file` | str | logs/AI_MAL.log | Log file path | Log management |
| `--full-auto` | flag | False | Enable full automation mode | Hands-off operation |
| `--custom-vuln` | str | None | Path to custom vulnerability definitions | Custom vulnerability testing |

## Usage Examples

### Basic Scan
```bash
AI_MAL 192.168.1.1
```

### Advanced Scanning
```bash
AI_MAL 192.168.1.1 --stealth --continuous --delay 600
```

### Service and Version Detection
```bash
AI_MAL 192.168.1.1 --services --version --os
```

### Metasploit Integration
```bash
AI_MAL 192.168.1.1 --msf --exploit --vuln
```

### Custom Script Generation
```bash
AI_MAL 192.168.1.1 --custom-scripts --script-type python --execute-scripts
```

### Full Automation
```bash
AI_MAL 192.168.1.1 --full-auto --ai-analysis --msf --exploit --vuln --custom-scripts
```

## Prerequisites

- Python 3.8+
- Nmap
- Metasploit Framework (optional)
- Ollama (for AI features)
- Required Python packages (see requirements.txt)

## Dependencies

- rich
- python-dotenv
- aiohttp
- paramiko (for SSH features)
- smbclient (for SMB features)
- Apache Benchmark (for DoS testing)
- hping3 (for DoS testing)

## Best Practices

1. Always start with basic scans before enabling advanced features
2. Use stealth mode for sensitive environments
3. Enable AI analysis for better results interpretation
4. Use custom output directories for better organization
5. Consider using continuous scanning for monitoring
6. Enable logging for debugging and analysis
7. Use custom models for specific use cases
8. Test scripts in a controlled environment before execution
9. Monitor system resources during intensive scans
10. Keep vulnerability definitions up to date

## Troubleshooting

1. If AI analysis fails, try using a different model
2. For Metasploit issues, ensure the service is running
3. Check log files for detailed error information
4. Use debug logging level for troubleshooting
5. Verify network connectivity before scanning
6. Ensure sufficient system resources are available
7. Check file permissions for output directories
8. Verify script execution permissions
9. Monitor system logs for potential issues
10. Use quiet mode for minimal output during troubleshooting

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## OpenVAS Integration

AI_MAL now includes integration with OpenVAS (Open Vulnerability Assessment System) for advanced vulnerability scanning. This feature allows you to:

- Run vulnerability scans against network targets
- Automatically analyze vulnerabilities with AI
- Generate detailed reports of security issues
- Get AI-powered recommendations for remediation

### Using OpenVAS with AI_MAL

After installation, you can use the OpenVAS scanner with the following command:

```bash
python -m AI_MAL.openvas_scan <target_ip> [options]
```

#### Example Usage

Basic scan of a target with default settings:
```bash
python -m AI_MAL.openvas_scan 192.168.1.1
```

Full scan with AI analysis:
```bash
python -m AI_MAL.openvas_scan 192.168.1.1 --scan-config full_and_very_deep --ai-analysis
```

Update OpenVAS feeds before scanning:
```bash
python -m AI_MAL.openvas_scan 192.168.1.1 --update-feeds
```

### Command-line Options

The following options are available for the OpenVAS scanner:

- `--scan-name`: Optional name for the scan
- `--scan-config`: Scan configuration (full_and_fast, full_and_very_deep, discovery, etc.)
- `--username`: OpenVAS username (default: admin)
- `--password`: OpenVAS password
- `--update-feeds`: Update OpenVAS vulnerability feeds before scanning
- `--ai-analysis`: Perform AI analysis on scan results
- `--output-dir`: Directory to save scan results (default: scan_results)
- `--cleanup`: Clean up scan task and target after scanning
- `--verbose`: Enable verbose output

### Requirements

The OpenVAS integration requires:

1. A working installation of OpenVAS/Greenbone Vulnerability Manager
2. Redis server for OpenVAS
3. Administrative access to start services

AI_MAL will attempt to install and configure OpenVAS on supported systems (Kali Linux) during installation, but you may need to manually install it on some systems.

For more information on OpenVAS, visit [the Greenbone Community website](https://community.greenbone.net/). 