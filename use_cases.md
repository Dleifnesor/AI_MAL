# AI_MAL Tool: Usage Guide and Examples

This document provides detailed explanations and real-world examples for all command-line arguments available in the AI_MAL tool. Each section covers specific use cases to help you understand when and how to use each option.

## Basic Usage

```bash
AI_MAL [target] [options]
```

## Target Specification

The target is an optional positional argument that specifies the IP address or hostname to scan.

```bash
# Scan a specific IP address
AI_MAL 192.168.1.100

# Scan a hostname
AI_MAL example.com
```

> **Note**: If no target is specified, you must use the `--auto-discover` option to automatically find targets on the network.

## Network Discovery Options

### --auto-discover

Automatically discovers the network and active hosts without requiring a specific target.

```bash
# Discover and scan the first host found on the network
AI_MAL --auto-discover
```

**Use case**: Ideal for initial reconnaissance when you don't know what hosts are available on the network.

### --interface INTERFACE

Specifies which network interface to use for host discovery.

```bash
# Use the eth0 interface for discovery
AI_MAL --auto-discover --interface eth0
```

**Use case**: Useful in systems with multiple network interfaces or when you want to focus on a specific network segment.

### --network CIDR

Specifies a network in CIDR notation to scan.

```bash
# Scan the 192.168.1.0/24 network
AI_MAL --auto-discover --network 192.168.1.0/24
```

**Use case**: When you know the specific network range you want to target.

### --scan-all

Scans all discovered hosts instead of just the first one.

```bash
# Discover and scan all hosts on the network
AI_MAL --scan-all
```

**Use case**: Comprehensive network assessment when you need to evaluate all devices on a network.

### --host-timeout SECONDS

Sets the timeout in seconds for host discovery (default: 1).

```bash
# Increase host discovery timeout to 3 seconds for better reliability
AI_MAL --auto-discover --host-timeout 3
```

**Use case**: Useful for slow networks or when scanning across WAN links.

## Scan Control Options

### --iterations N

Sets the maximum number of scan iterations (default: 3).

```bash
# Run up to 5 iterations of adaptive scanning
AI_MAL 192.168.1.100 --iterations 5
```

**Use case**: Deeper reconnaissance when you need more thorough information gathering.

### --continuous

Runs the scan in continuous mode until manually stopped (Ctrl+C).

```bash
# Continuously scan and adapt until manually stopped
AI_MAL 192.168.1.100 --continuous
```

**Use case**: Ongoing monitoring of a target or persistent reconnaissance during longer engagements.

### --delay SECONDS

Sets the delay in seconds between scan iterations (default: 2).

```bash
# Wait 5 seconds between scan iterations
AI_MAL 192.168.1.100 --delay 5
```

**Use case**: Avoids overwhelming the target or network with too many requests in a short time period.

### --stealth

Enables stealth mode to minimize detection risk.

```bash
# Perform a stealthy scan to avoid triggering IDS/IPS systems
AI_MAL 192.168.1.100 --stealth
```

**Use case**: Red team operations or penetration testing where avoiding detection is critical.

## Metasploit Integration

### --msf

Enables Metasploit integration for importing scan results.

```bash
# Scan a target and import results into Metasploit
AI_MAL 192.168.1.100 --msf
```

**Use case**: Prepares data for exploitation by importing scan results into Metasploit.

### --exploit

Automatically attempts exploitation using Metasploit based on scan results.

```bash
# Scan and attempt to exploit vulnerabilities
AI_MAL 192.168.1.100 --msf --exploit
```

**Use case**: Automated exploitation during penetration testing or vulnerability assessment.

### --workspace NAME

Sets the Metasploit workspace name (default: adaptive_scan).

```bash
# Use a custom Metasploit workspace
AI_MAL 192.168.1.100 --msf --workspace client_pentest
```

**Use case**: Organizing different assessments or targets within Metasploit.

### --auto-script

Automatically generates and runs Metasploit resource scripts.

```bash
# Generate and run Metasploit resource scripts automatically
AI_MAL 192.168.1.100 --msf --exploit --auto-script
```

**Use case**: Streamlines the exploitation process by automating the creation and execution of Metasploit scripts.

### --dos

Attempts to perform Denial of Service (DoS) attacks against target hosts.

```bash
# Scan and attempt DoS attacks against a target
AI_MAL 192.168.1.100 --dos
```

**Use case**: Testing network resilience and security controls by simulating denial of service conditions.

> **WARNING**: This option should only be used in controlled environments with proper authorization. Using this option against unauthorized targets may be illegal and unethical.

## AI Script Generation

### --custom-scripts

Enables AI-powered custom script generation based on scan results.

```bash
# Generate custom scripts for further analysis
AI_MAL 192.168.1.100 --custom-scripts
```

**Use case**: Automated creation of tailored scripts for specific reconnaissance or exploitation tasks.

### --script-type TYPE

Specifies the type of script to generate (bash, python, or ruby).

```bash
# Generate Python scripts instead of the default bash
AI_MAL 192.168.1.100 --custom-scripts --script-type python
```

**Use case**: When you need scripts in a specific language for compatibility with your workflow or tools.

### --execute-scripts

Automatically executes generated scripts (use with caution).

```bash
# Generate and execute custom scripts
AI_MAL 192.168.1.100 --custom-scripts --execute-scripts
```

**Use case**: Fully automated reconnaissance and exploitation pipeline, but carries additional risk.

## AI Model Options

### --model MODEL

Specifies which Ollama model to use (default: qwen2.5-coder:7b).

```bash
# Use the llama3 model instead of qwen2.5-coder:7b
AI_MAL 192.168.1.100 --model llama3
```

**Use case**: When you need to switch to a different AI model for better performance or different capabilities.

## Output Control

### --quiet

Reduces the verbosity of output.

```bash
# Run with minimal output
AI_MAL 192.168.1.100 --quiet
```

**Use case**: When running as part of automated scripts or when only critical information is needed.

### --debug

Enables detailed debug logging.

```bash
# Show detailed debug information
AI_MAL 192.168.1.100 --debug
```

**Use case**: Troubleshooting issues or understanding the detailed flow of the scanning process.

## Full Automation

### --full-auto

Enables full autonomous mode (implies --continuous --msf --exploit --auto-script --custom-scripts).

```bash
# Run in fully automated mode
AI_MAL 192.168.1.100 --full-auto
```

**Use case**: "Fire and forget" automated reconnaissance and exploitation with minimal user intervention.

## Other Options

### --version

Shows version information and exits.

```bash
# Display version information
AI_MAL --version
```

**Use case**: Checking the current version of the tool.

## Advanced Use Case Examples

### Basic Network Reconnaissance

```bash
AI_MAL --auto-discover --stealth
```
This performs a stealthy scan of automatically discovered hosts, avoiding detection while gathering basic information.

### Targeted Exploitation

```bash
AI_MAL 192.168.1.100 --msf --exploit --script-type python
```
This targets a specific host, attempts exploitation via Metasploit, and generates Python scripts for further analysis.

### Continuous Monitoring with Script Generation

```bash
AI_MAL 192.168.1.100 --continuous --delay 60 --custom-scripts --execute-scripts
```
This continuously scans a target every 60 seconds, generating and executing scripts based on findings.

### Multi-Network Assessment

```bash
AI_MAL --scan-all --network 10.0.0.0/24 --msf --iterations 2
```
This scans all hosts in the 10.0.0.0/24 network, importing results to Metasploit, with 2 iterations per host.

### Full Red Team Operation

```bash
AI_MAL --auto-discover --stealth --msf --exploit --custom-scripts --script-type bash --execute-scripts
```
This performs a complete red team operation with stealthy scanning, automatic exploitation, and custom script execution.

### Quick Security Audit

```bash
AI_MAL --auto-discover --stealth --iterations 1 --quiet
```
This performs a single-pass stealthy security audit of the network with minimal output.

### Interactive Penetration Testing

```bash
AI_MAL 192.168.1.100 --msf --workspace pentest_2024 --custom-scripts
```
This integrates with Metasploit in a specific workspace and generates scripts but doesn't execute them automatically, allowing for manual review.

### Stress Testing Network Security Controls

```bash
AI_MAL 192.168.1.100 --dos --stealth --iterations 2 --delay 10
```
This performs targeted DoS testing against a specific host with a stealthy approach, attempting 2 iterations with 10-second delays between attempts to evaluate the effectiveness of security controls. 