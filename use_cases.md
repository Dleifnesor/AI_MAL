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

# Enable DoS testing
AI_MAL 192.168.1.1 --dos
```

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

# Use lightweight model
AI_MAL 192.168.1.1 --model gemma:7b

# Specify fallback model
AI_MAL 192.168.1.1 --model qwen2.5-coder:7b --fallback-model mistral:7b
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

### Performance Optimization
1. Choose appropriate model based on system resources
   - For systems with >8GB RAM: `--model qwen2.5-coder:7b`
   - For systems with <8GB RAM: `--model gemma:7b` or `--model phi:latest`
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
| `--dos` | Attempts Denial of Service attacks | False | `AI_MAL 192.168.1.1 --dos` |
| `--msf` | Enables Metasploit integration | False | `AI_MAL 192.168.1.1 --msf` |
| `--exploit` | Attempts exploitation of vulnerabilities | False | `AI_MAL 192.168.1.1 --exploit` |
| `--custom-scripts` | Enables AI-powered script generation | False | `AI_MAL 192.168.1.1 --custom-scripts` |
| `--script-type` | Specifies script generation type | python | `AI_MAL 192.168.1.1 --script-type bash` |
| `--execute-scripts` | Automatically executes generated scripts | False | `AI_MAL 192.168.1.1 --execute-scripts` |
| `--model` | Specifies Ollama model to use | qwen2.5-coder:7b | `AI_MAL 192.168.1.1 --model gemma:7b` |
| `--fallback-model` | Specifies fallback Ollama model | mistral:7b | `AI_MAL 192.168.1.1 --fallback-model llama3:8b` |
| `--full-auto` | Enables full autonomous mode | False | `AI_MAL 192.168.1.1 --full-auto` |
| `--output-dir` | Sets output directory for results | scan_results | `AI_MAL 192.168.1.1 --output-dir ./results` |
| `--output-format` | Sets output format for scan results | json | `AI_MAL 192.168.1.1 --output-format xml` |
| `--iterations` | Sets number of scan iterations | 1 | `AI_MAL 192.168.1.1 --iterations 3` |
| `--ai-analysis` | Enables AI analysis of results | True | `AI_MAL 192.168.1.1 --ai-analysis` |
| `--quiet` | Suppresses progress output and logging to console | False | `AI_MAL 192.168.1.1 --quiet` |
| `--no-gui` | Disables the terminal GUI interface | False | `AI_MAL 192.168.1.1 --no-gui` |

### Notes:
- Multiple arguments can be combined in a single command
- Some arguments may have dependencies on others (e.g., `--exploit` requires `--msf`)
- The `--model` argument supports any model available in Ollama
- Tool will attempt to download models if they don't exist and fallback gracefully

## Troubleshooting

### Common Issues

1. **Model not found errors**
   - Error message: `"model 'gemma3:1b' not found"`
   - Solution: Check available models with `ollama list` or try another model with `--model`
   - The tool will automatically attempt to use available models or fallback to built-in analysis

2. **Metasploit connection issues**
   - Error message: `"Error running Metasploit"`
   - Solution: Ensure Metasploit is installed and properly configured on your system

3. **Script generation errors**
   - Error message: `"Error generating scripts"`
   - Solution: Check that the target is properly scanned before generating scripts

### Debug Mode
To troubleshoot issues, you can add the following environment variables:
```bash
export DEBUG=1
export OLLAMA_HOST=http://localhost:11434
export OLLAMA_MODEL=qwen2.5-coder:7b
export OLLAMA_FALLBACK_MODEL=mistral:7b
```

### Recovery Procedures
1. If AI models fail to load, the tool will automatically:
   - Try fallback model
   - Try backup models (llama3:8b, gemma:7b, phi:latest, tinyllama:latest)
   - Use built-in fallback analysis if all models fail

2. If the GUI interface fails, use the `--no-gui` option:
   ```bash
   AI_MAL 192.168.1.1 --no-gui
   ```
   