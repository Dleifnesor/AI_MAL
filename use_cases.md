# AI_MAL Use Cases

This document outlines the various use cases and scenarios for the AI_MAL (AI-Powered Penetration Testing) tool.

## Table of Contents
1. [Basic Usage](#basic-usage)
2. [Advanced Scanning](#advanced-scanning)
3. [Metasploit Integration](#metasploit-integration)
4. [Custom Script Generation](#custom-script-generation)
5. [Data Exfiltration](#data-exfiltration)
6. [Implant Deployment](#implant-deployment)
7. [AI Model Configuration](#ai-model-configuration)
8. [GUI Interface Options](#gui-interface-options)
9. [Real-World Examples](#real-world-examples)
10. [Kali Linux Specific Examples](#kali-linux-specific-examples)
11. [Best Practices](#best-practices)
12. [Troubleshooting](#troubleshooting)

## Command-Line Arguments Reference

| Argument | Type | Default | Description | Use Case |
|----------|------|---------|-------------|----------|
| `target` | str | required | Target IP address or hostname | Basic scanning target |
| `--scan-type` | str | quick | Type of scan to perform (quick/full/stealth) | Defines scan thoroughness and noise level |
| `--stealth` | flag | False | Enable stealth mode for minimal detection | Covert scanning operations |
| `--continuous` | flag | False | Run continuous scanning | Network monitoring |
| `--delay` | int | 300 | Delay between scans in seconds | Continuous monitoring with custom intervals |
| `--services` | flag | False | Enable service detection | Service enumeration |
| `--version` | flag | False | Enable version detection | Version fingerprinting |
| `--os` | flag | False | Enable OS detection | OS fingerprinting |
| `--vuln` | flag | False | Enable vulnerability scanning (OpenVAS by default) | Vulnerability assessment |
| `--openvas` | flag | False | Force OpenVAS for vulnerability scanning (no fallback) | Enterprise-grade vulnerability scanning |
| `--scan-config` | str | full_and_fast | OpenVAS scan configuration type | Customizing vulnerability scan depth |
| `--use-nmap` | flag | False | Force Nmap for vulnerability scanning | Alternative vulnerability scanning |
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
| `--debug` | flag | False | Enable debug mode with verbose output | Troubleshooting and development |
| `--log-level` | str | info | Logging level (debug/info/warning/error) | Debugging and monitoring |
| `--log-file` | str | logs/AI_MAL.log | Log file path | Log management |
| `--full-auto` | flag | False | Enable full automation mode | Hands-off operation |
| `--custom-vuln` | str | None | Path to custom vulnerability definitions | Custom vulnerability testing |

## Basic Usage

### Simple Network Scan
```bash
AI_MAL 192.168.1.1
```
Performs a basic network scan on the target IP address.

### Advanced Scanning
```bash
AI_MAL 192.168.1.1 --stealth --continuous --delay 600
```
- `--stealth`: Enables stealth mode for minimal detection
- `--continuous`: Runs continuous scanning
- `--delay`: Sets delay between scans (default: 300 seconds)

### Service and Version Detection
```bash
AI_MAL 192.168.1.1 --services --version --os
```
- `--services`: Enables service detection
- `--version`: Enables version detection
- `--os`: Enables OS detection

## Metasploit Integration

### Basic Metasploit Usage
```bash
AI_MAL 192.168.1.1 --msf
```
Enables Metasploit integration for the scan.

### Exploitation
```bash
AI_MAL 192.168.1.1 --msf --exploit --vuln
```
- `--exploit`: Attempts exploitation of vulnerabilities
- `--vuln`: Enables vulnerability scanning

## Custom Script Generation

### Basic Script Generation
```bash
AI_MAL 192.168.1.1 --custom-scripts
```
Enables AI-powered script generation.

### Advanced Script Options
```bash
AI_MAL 192.168.1.1 --custom-scripts --script-type python --execute-scripts --script-output ./scripts
```
- `--script-type`: Specifies script language (python/bash/ruby)
- `--execute-scripts`: Automatically executes generated scripts
- `--script-output`: Specifies output directory for scripts
- `--script-format`: Sets script format (raw/base64)

## AI Analysis

### Basic AI Analysis
```bash
AI_MAL 192.168.1.1 --ai-analysis
```
Enables AI analysis of scan results.

### Custom AI Models
```bash
AI_MAL 192.168.1.1 --model artifish/llama3.2-uncensored --fallback-model gemma3:1b
```
- `--model`: Specifies primary AI model
- `--fallback-model`: Specifies fallback AI model

## Advanced Features

### Data Exfiltration
```bash
AI_MAL 192.168.1.1 --exfil
```
Attempts to exfiltrate files from target systems.

### Implant Deployment
```bash
AI_MAL 192.168.1.1 --implant ./payload.py
```
Deploys a custom script to target machines.

### Denial of Service
```bash
AI_MAL 192.168.1.1 --dos
```
Attempts Denial of Service attacks.

## Output Configuration

### Basic Output
```bash
AI_MAL 192.168.1.1 --output-dir ./results --output-format json
```
- `--output-dir`: Specifies output directory
- `--output-format`: Sets output format (xml/json)

### Logging Options
```bash
AI_MAL 192.168.1.1 --log-level debug --log-file ./logs/scan.log
```
- `--log-level`: Sets logging level (debug/info/warning/error)
- `--log-file`: Specifies log file path

### Quiet Mode
```bash
AI_MAL 192.168.1.1 --quiet --no-gui
```
- `--quiet`: Suppresses progress output
- `--no-gui`: Disables terminal GUI features

## Full Automation

### Complete Automated Scan
```bash
AI_MAL 192.168.1.1 --full-auto --ai-analysis --msf --exploit --vuln --custom-scripts
```
Runs a fully automated scan with all features enabled.

### Custom Vulnerability Definitions
```bash
AI_MAL 192.168.1.1 --custom-vuln ./vulnerabilities.json
```
Uses custom vulnerability definitions for scanning.

## Real-World Examples

### Web Server Assessment
```bash
AI_MAL 192.168.1.10 --services --version --vuln --custom-scripts --script-type python --ai-analysis --output-dir ./webserver-assessment
```
This command performs a comprehensive assessment of a web server, detecting services and versions, scanning for vulnerabilities, generating custom Python scripts for exploitation, and analyzing findings with AI.

### Internal Network Discovery
```bash
AI_MAL 10.0.0.0/24 --stealth --services --os --output-format json --output-dir ./internal-network-scan
```
Performs a stealthy scan of an entire internal network range, identifying active hosts, their operating systems, and running services, saving results in JSON format.

### Metasploit-Enabled Full Penetration Test
```bash
AI_MAL 192.168.1.100 --scan-type full --msf --exploit --vuln --ai-analysis --custom-scripts --execute-scripts --log-level debug
```
Conducts a full penetration test against a target, leveraging Metasploit for exploitation, running vulnerability scans, enabling AI analysis, and automatically executing generated scripts with debug-level logging.

### Continuous Security Monitoring
```bash
AI_MAL 192.168.0.0/16 --continuous --delay 3600 --services --version --vuln --ai-analysis --quiet --output-dir ./continuous-monitoring
```
Sets up continuous security monitoring of a large network range, scanning every hour (3600 seconds) for new services, versions, and vulnerabilities, with AI analysis of the findings, running quietly in the background.

### Critical Server Vulnerability Assessment
```bash
AI_MAL 192.168.1.5 --scan-type full --os --services --version --vuln --openvas --scan-config full_and_very_deep --ai-analysis --output-dir ./critical-server
```
Performs a thorough vulnerability assessment of a critical server using OpenVAS with the full_and_very_deep scan policy, determining OS details, and analyzing all findings with AI.

### Kiosk/IoT Device Testing
```bash
AI_MAL 192.168.2.50 --services --version --vuln --custom-scripts --script-type bash --model qwen2.5-coder:7b
```
Tailored for testing kiosk or IoT devices, focusing on service detection, vulnerability scanning, and using the specialized qwen2.5-coder AI model to generate bash exploitation scripts.

### External Web Application Assessment
```bash
AI_MAL example.com --stealth --vuln --custom-scripts --script-type python --ai-analysis --scan-type quick --output-dir ./external-webapp
```
Performs a stealthy, quick assessment of an external web application, scanning for vulnerabilities and generating Python scripts for potential exploits.

### Database Server Testing
```bash
AI_MAL 192.168.1.20 --services --version --vuln --msf --custom-scripts --script-type python --output-dir ./database-assessment
```
Specifically designed for testing database servers, detecting services and versions, scanning for database-related vulnerabilities, and generating appropriate exploitation scripts.

### Wireless Network Assessment
```bash
AI_MAL 192.168.3.0/24 --scan-type quick --services --vuln --stealth --output-dir ./wireless-assessment
```
Quick assessment of a wireless network subnet with stealthy scanning to minimize detection, identifying services and potential vulnerabilities.

### Advanced Threat Simulation
```bash
AI_MAL 192.168.1.0/24 --msf --exploit --exfil --custom-scripts --execute-scripts --ai-analysis --implant ./custom-implant.py
```
Simulates an advanced threat by attempting to exploit vulnerabilities, exfiltrate data, deploy a custom implant, and use AI to analyze potential attack paths.

## Kali Linux Specific Examples

### Integration with Kali Tools
```bash
AI_MAL 192.168.1.100 --msf --vuln --openvas --scan-config full_and_fast --ai-analysis --output-dir /root/engagement/target1
```
Demonstrates AI_MAL integration with core Kali Linux tools like Metasploit and OpenVAS, with results stored in a typical Kali engagement directory structure.

### Network Range with Screenshot Capture
```bash
AI_MAL 192.168.0.0/24 --services --version --script-type bash --custom-scripts --script-output /opt/AI_MAL/scripts/recon
```
Scans a network range and generates bash scripts to perform additional reconnaissance, including service screenshots and further enumeration, storing scripts in the default AI_MAL script location.

### Post-exploitation Framework Integration
```bash
AI_MAL 10.10.10.5 --msf --exploit --custom-scripts --script-type python --ai-analysis --no-gui
```
Integrates with the Metasploit Framework for exploitation while generating custom Python scripts for post-exploitation activities, running without GUI for easier integration in terminal-based workflows.

### Combination with Manual Testing
```bash
AI_MAL 192.168.1.50 --scan-type quick --services --version --output-format json --output-dir $(pwd)/target --quiet
```
Quick reconnaissance before manual testing, outputting JSON data to the current directory for easy integration with other Kali tools and manual testing workflows.

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

### Common Issues

1. **Model not found errors**
   - Error message: `"model 'xxxx' not found"`
   - Solution: Only artifish/llama3.2-uncensored and gemma:7b are auto-installed. For other models:
     - Install them manually first: `ollama pull model_name`
     - Or use one of the default models: `--model artifish/llama3.2-uncensored` or `--model gemma:7b`
   - The tool will automatically fall back to an available default model if your specified model is not found

2. **Metasploit connection issues**
   - Error message: `"Error running Metasploit"`
   - Solution: Ensure Metasploit is installed and properly configured on your system

3. **Script generation errors**
   - Error message: `"Error generating scripts"`
   - Solution: Check that the target is properly scanned before generating scripts

4. **DoS testing tool errors**
   - Error message: `"Error during [test_type] test"`
   - Solution: Ensure the required DoS testing tools (ab, hping3) are installed:
     - Install Apache Benchmark: `apt-get install apache2-utils`
     - Install hping3: `apt-get install hping3`

### Debug Mode
To troubleshoot issues, you can add the following environment variables:
```bash
export DEBUG=1
export OLLAMA_HOST=http://localhost:11434
export OLLAMA_MODEL=artifish/llama3.2-uncensored
export OLLAMA_FALLBACK_MODEL=gemma3:1b
```

### Recovery Procedures
1. If AI models fail to load, the tool will automatically:
   - Try fallback model if specified
   - Try one of the default models (artifish/llama3.2-uncensored or gemma:7b) if available
   - Use built-in fallback analysis if no models are available

2. If the GUI interface fails, use the `--no-gui` option:
   ```bash
   AI_MAL 192.168.1.1 --no-gui
   ```
   