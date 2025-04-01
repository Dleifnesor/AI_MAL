# AI_MAL Use Cases

This document outlines the various use cases and scenarios for the AI_MAL (AI-Powered Penetration Testing) tool.

## Table of Contents
1. [Basic Usage](#basic-usage)
2. [Advanced Scanning](#advanced-scanning)
3. [Metasploit Integration](#metasploit-integration)
4. [Custom Script Generation](#custom-script-generation)
5. [AI Model Configuration](#ai-model-configuration)
6. [GUI Interface Options](#gui-interface-options)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

## Basic Usage

### Simple Network Scanning
```bash
# Basic scan of a single target
AI_MAL 192.168.1.1

# Stealth mode for minimal detection
AI_MAL 192.168.1.1 --stealth
```

### Continuous Scanning
```bash
# Run continuous scanning with 5-minute delay
AI_MAL 192.168.1.1 --continuous --delay 300
```

## Advanced Scanning

### Service Detection
```bash
# Enable service detection
AI_MAL 192.168.1.1 --services

# Enable version detection
AI_MAL 192.168.1.1 --version

# Enable OS detection
AI_MAL 192.168.1.1 --os
```

### Vulnerability Assessment
```bash
# Enable vulnerability scanning
AI_MAL 192.168.1.1 --vuln

# Combine multiple scanning options
AI_MAL 192.168.1.1 --services --version --vuln
```

### Denial of Service Testing
```bash
# Perform DoS vulnerability testing
AI_MAL 192.168.1.1 --dos

# Combined DoS testing with other scan types
AI_MAL 192.168.1.1 --services --version --dos

# Full penetration test with DoS assessment
AI_MAL 192.168.1.1 --services --version --vuln --dos --msf --exploit
```

The `--dos` option performs actual DoS vulnerability testing against discovered services:
* Uses specialized Nmap DoS-related NSE scripts
* Tests HTTP servers for Slowloris vulnerability
* Performs controlled HTTP flood testing using Apache Benchmark
* Conducts SYN flood testing using hping3
* Verifies service responsiveness after each test
* Provides a detailed vulnerability report for each service

## Metasploit Integration

### Basic Metasploit Usage
```bash
# Enable Metasploit integration
AI_MAL 192.168.1.1 --msf

# Run Metasploit exploits
AI_MAL 192.168.1.1 --msf --exploit
```

### Full Automated Exploitation
```bash
# Full automation with Metasploit exploitation
AI_MAL 192.168.1.1 --msf --exploit --full-auto

# Comprehensive scan with all options
AI_MAL 192.168.1.1 --services --version --os --vuln --msf --exploit --full-auto
```

## Custom Script Generation

### Basic Script Generation
```bash
# Generate custom scripts
AI_MAL 192.168.1.1 --custom-scripts

# Generate Python scripts
AI_MAL 192.168.1.1 --custom-scripts --script-type python

# Generate Bash scripts
AI_MAL 192.168.1.1 --custom-scripts --script-type bash

# Generate Ruby scripts
AI_MAL 192.168.1.1 --custom-scripts --script-type ruby
```

### Script Execution
```bash
# Generate and execute custom scripts
AI_MAL 192.168.1.1 --custom-scripts --execute-scripts

# Generate and execute Python scripts
AI_MAL 192.168.1.1 --custom-scripts --script-type python --execute-scripts
```

## AI Model Configuration

### Model Selection
```bash
# Use default model (qwen2.5-coder:7b)
AI_MAL 192.168.1.1 --model qwen2.5-coder:7b

# Use lightweight model (gemma:7b)
AI_MAL 192.168.1.1 --model gemma:7b

# Use any other pre-installed Ollama model
AI_MAL 192.168.1.1 --model mistral:7b

# Specify fallback model
AI_MAL 192.168.1.1 --model qwen2.5-coder:7b --fallback-model gemma:7b
```

### AI Analysis
```bash
# Explicitly enable AI analysis (enabled by default)
AI_MAL 192.168.1.1 --ai-analysis
```

## GUI Interface Options

### Rich Terminal Interface
```bash
# Default rich interface
AI_MAL 192.168.1.1

# Disable GUI interface (text-only output)
AI_MAL 192.168.1.1 --no-gui

# Suppress progress output
AI_MAL 192.168.1.1 --quiet
```

### Output Options
```bash
# Set custom output directory
AI_MAL 192.168.1.1 --output-dir /path/to/results

# Set output format to JSON (default)
AI_MAL 192.168.1.1 --output-format json

# Set output format to XML
AI_MAL 192.168.1.1 --output-format xml
```

## Best Practices

### Security Considerations
1. Always run with proper authorization
2. Use stealth mode when appropriate
3. Limit scan intensity on production networks
4. Follow responsible disclosure practices
5. Document all testing activities
6. **Special Caution with DoS Testing**: The `--dos` option performs actual denial of service testing that could impact production systems

### Performance Optimization
1. Choose appropriate model based on system resources
   - For systems with >8GB RAM: `--model qwen2.5-coder:7b`
   - For systems with <8GB RAM: `--model gemma:7b`
2. Use stealth mode for initial reconnaissance
3. When generating scripts, start with Python for maximum compatibility
4. Specify fallback models in case primary models are unavailable

### Example Recommended Workflows

#### Basic Security Assessment
```bash
# Basic security assessment with AI analysis
AI_MAL 192.168.1.1 --services --version --os
```

#### Vulnerability Assessment
```bash
# Vulnerability assessment with service detection
AI_MAL 192.168.1.1 --services --version --vuln
```

#### Penetration Testing
```bash
# Full penetration testing workflow
AI_MAL 192.168.1.1 --services --version --os --vuln --msf --exploit --custom-scripts
```

#### Automated Red Team
```bash
# Fully automated red team engagement
AI_MAL 192.168.1.1 --msf --exploit --full-auto --custom-scripts --execute-scripts
```

#### DoS Vulnerability Assessment
```bash
# Focused DoS testing with minimal scanning
AI_MAL 192.168.1.1 --services --dos
```

## Command-Line Arguments Reference

The following table provides a comprehensive list of all available command-line arguments in AI_MAL:

| Argument | Description | Default | Example |
|----------|-------------|---------|---------|
| `--stealth` | Enables stealth mode to minimize detection | False | `AI_MAL 192.168.1.1 --stealth` |
| `--continuous` | Runs scan in continuous mode until stopped | False | `AI_MAL 192.168.1.1 --continuous` |
| `--delay` | Sets delay between scan iterations in seconds | 300 | `AI_MAL 192.168.1.1 --delay 600` |
| `--services` | Enables detailed service detection | False | `AI_MAL 192.168.1.1 --services` |
| `--version` | Enables version detection | False | `AI_MAL 192.168.1.1 --version` |
| `--os` | Enables OS detection | False | `AI_MAL 192.168.1.1 --os` |
| `--vuln` | Enables vulnerability scanning | False | `AI_MAL 192.168.1.1 --vuln` |
| `--dos` | Performs denial of service vulnerability testing | False | `AI_MAL 192.168.1.1 --dos` |
| `--msf` | Enables Metasploit integration | False | `AI_MAL 192.168.1.1 --msf` |
| `--exploit` | Attempts exploitation of vulnerabilities | False | `AI_MAL 192.168.1.1 --exploit` |
| `--custom-scripts` | Enables AI-powered script generation | False | `AI_MAL 192.168.1.1 --custom-scripts` |
| `--script-type` | Specifies script generation type | python | `AI_MAL 192.168.1.1 --script-type bash` |
| `--execute-scripts` | Automatically executes generated scripts | False | `AI_MAL 192.168.1.1 --execute-scripts` |
| `--model` | Specifies Ollama model to use | qwen2.5-coder:7b | `AI_MAL 192.168.1.1 --model gemma:7b` |
| `--fallback-model` | Specifies fallback Ollama model | gemma:7b | `AI_MAL 192.168.1.1 --fallback-model gemma:7b` |
| `--full-auto` | Enables full autonomous mode | False | `AI_MAL 192.168.1.1 --full-auto` |
| `--output-dir` | Sets output directory for results | scan_results | `AI_MAL 192.168.1.1 --output-dir ./results` |
| `--output-format` | Sets output format for scan results | json | `AI_MAL 192.168.1.1 --output-format xml` |
| `--iterations` | Sets number of scan iterations | 1 | `AI_MAL 192.168.1.1 --iterations 3` |
| `--ai-analysis` | Enables AI analysis of results | True | `AI_MAL 192.168.1.1 --ai-analysis` |
| `--quiet` | Suppresses progress output and logging to console | False | `AI_MAL 192.168.1.1 --quiet` |
| `--no-gui` | Disables the terminal GUI interface | False | `AI_MAL 192.168.1.1 --no-gui` |
| `--custom-vuln` | Path to custom vulnerability definitions | None | `AI_MAL 192.168.1.1 --custom-vuln vuln.json` |

### Notes:
- Multiple arguments can be combined in a single command
- Some arguments may have dependencies on others (e.g., `--exploit` requires `--msf`)
- By default, only `qwen2.5-coder:7b` and `gemma:7b` will be auto-installed if needed
- Any other Ollama model can be used with `--model` if already installed on your system
- The tool will automatically choose the best available model if your specified model is not available

### DoS Testing Prerequisites
To fully utilize the DoS testing capabilities (`--dos`), you need:
- Nmap with NSE scripts (including http-slowloris, syn-flood)
- Apache Benchmark (ab) for HTTP flood testing
- hping3 for SYN flood testing

## Troubleshooting

### Common Issues

1. **Model not found errors**
   - Error message: `"model 'xxxx' not found"`
   - Solution: Only qwen2.5-coder:7b and gemma:7b are auto-installed. For other models:
     - Install them manually first: `ollama pull model_name`
     - Or use one of the default models: `--model qwen2.5-coder:7b` or `--model gemma:7b`
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
export OLLAMA_MODEL=qwen2.5-coder:7b
export OLLAMA_FALLBACK_MODEL=gemma:7b
```

### Recovery Procedures
1. If AI models fail to load, the tool will automatically:
   - Try fallback model if specified
   - Try one of the default models (qwen2.5-coder:7b or gemma:7b) if available
   - Use built-in fallback analysis if no models are available

2. If the GUI interface fails, use the `--no-gui` option:
   ```bash
   AI_MAL 192.168.1.1 --no-gui
   ```
   