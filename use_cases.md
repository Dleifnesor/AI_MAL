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
   
