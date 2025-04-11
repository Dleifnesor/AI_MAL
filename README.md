# AI_MAL - AI-Powered Penetration Testing Tool

AI_MAL is an advanced penetration testing tool that combines traditional scanning techniques with AI-powered analysis and automation. It integrates with Metasploit for exploitation and supports custom script generation for specialized attack scenarios.

![AI_MAL Logo](https://img.shields.io/badge/AI__MAL-v1.0.0-red)

## Features

- **Network Scanning**: Fast and comprehensive network reconnaissance with stealth options
- **Service Detection**: Identify running services and their versions
- **Vulnerability Scanning**: Integration with OpenVAS and nmap NSE scripts
- **Metasploit Integration**: Automated exploitation of discovered vulnerabilities
- **Custom Script Generation**: AI-powered creation of exploitation and enumeration scripts
- **AI Analysis**: Intelligent analysis of scan results with explanation of findings
- **Comprehensive Reporting**: Detailed reports in multiple formats

## Installation

### Easy Install (One-Liner)

For a quick setup on Kali Linux, first switch to root and then use this one-liner to clone the repository and run the installation script:

```bash
sudo su
git clone https://github.com/yourusername/AI_MAL.git && cd AI_MAL && bash install.sh
```

This command will switch to root privileges, clone the repository, navigate to the project directory, and run the installation script.

> **IMPORTANT**: During the OpenVAS setup, the installer will generate an admin password. Make sure to save this password as you'll need it to access the OpenVAS interface. Look for a line like: `[*] User created with password '4a1efbf3-e920-4ea8-aca1-a3824b17ccd9'`.

### Recommended: Kali Linux

AI_MAL is designed to work best on Kali Linux, which has most required tools pre-installed.

```bash
# Switch to root (recommended for full functionality)
sudo su

# Clone the repository
git clone https://github.com/yourusername/AI_MAL.git
cd AI_MAL

# Run the installation script
bash install.sh
```

The installation script will:
- Install all required Python dependencies
- Install system tools (nmap, Metasploit, etc.)
- Install and configure OpenVAS for vulnerability scanning
- Install Ollama for AI functionality
- Make AI_MAL available as a system command
- Fix line ending issues (if cloned from Windows)
- Create bash aliases for common scan types
- Set up command completion
- Create desktop shortcut

> **OpenVAS Setup Note**: During installation, when OpenVAS is being configured, an admin password will be generated and displayed in the terminal. Be sure to copy and save this password, as it will be required for OpenVAS access. The password will appear in a line similar to:
> ```
> [*] User created with password '4a1efbf3-e920-4ea8-aca1-a3824b17ccd9'.
> ```

> **Note**: If you're experiencing issues with line endings (e.g., errors like `/usr/bin/env: 'python3\r': No such file or directory`), the installation script automatically handles this by installing and running `dos2unix` on all scripts.

### Troubleshooting Ollama Issues

If you encounter errors related to Ollama not being able to connect during installation or when running AI_MAL, you may need to manually start the Ollama service:

1. Start the Ollama service in a terminal:
   ```bash
   ollama serve
   ```

2. In another terminal, pull the required models:
   ```bash
   ollama pull artifish/llama3.2-uncensored
   ollama pull gemma3:1b
   ```

3. Verify the Ollama service is running:
   ```bash
   curl http://localhost:11434/api/version
   ```

The installation script attempts to automatically start and verify the Ollama service, but in some environments, manual intervention may be needed.

### Manual Installation

If you prefer to install manually:

1. Switch to root for full functionality:
   ```bash
   sudo su
   ```

2. Install system dependencies:
   ```bash
   apt-get update
   apt-get install -y nmap metasploit-framework hping3 apache2-utils dos2unix
   ```

3. Fix line endings if cloned from Windows:
   ```bash
   find . -type f -name "*.py" -exec dos2unix {} \;
   find . -type f -name "*.sh" -exec dos2unix {} \;
   ```

4. Install OpenVAS (optional but recommended for vulnerability scanning):
   ```bash
   apt-get install -y openvas gvm
   gvm-setup
   gvm-start
   ```
   
   > **Important**: During the OpenVAS setup, an admin password will be generated. Make sure to save this password - you'll need it for vulnerability scanning.

5. Install Python dependencies:
   ```bash
   pip3 install requests python-nmap pymetasploit3 ollama rich pyfiglet prettytable xmltodict cryptography python-dateutil numpy pyyaml colorama jinja2
   ```

6. Install Ollama for AI functionality:
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ollama serve &  # Start the Ollama service
   sleep 10  # Wait for the service to initialize
   ollama pull artifish/llama3.2-uncensored
   ollama pull gemma3:1b
   ```

7. Make AI_MAL.py executable:
   ```bash
   chmod +x AI_MAL.py
   ```

8. Create a symbolic link:
   ```bash
   ln -sf "$(pwd)/AI_MAL.py" /usr/local/bin/AI_MAL
   ```

## Basic Usage

```bash
# Basic scan of a target
AI_MAL 192.168.1.1

# Full scan with vulnerability assessment
AI_MAL 192.168.1.1 --scan-type full --vuln

# Network range scan with service detection
AI_MAL 192.168.0.0/24 --services --version

# Full penetration test with exploitation
AI_MAL 192.168.1.1 --msf --exploit --vuln --ai-analysis
```

## Convenient Aliases

The installation script creates several useful aliases for common scan types:

```bash
# Web server assessment
web-scan 192.168.1.10

# Network discovery and reconnaissance
network-scan 10.0.0.0/24

# Full penetration test with all features
full-pentest 192.168.1.100

# Continuous monitoring of a network
monitor 192.168.0.0/16
```

## Advanced Usage

See [use_cases.md](use_cases.md) for detailed examples and usage scenarios.

## Components

- **Scanner**: Network scanning module using nmap
- **Vulnerability Scanner**: Integration with OpenVAS and nmap NSE scripts
- **Metasploit Framework**: Exploitation of discovered vulnerabilities
- **Script Generator**: AI-powered custom exploitation script generation
- **AI Analysis**: Intelligent analysis of results
- **Report Generator**: Comprehensive reporting in multiple formats

## Requirements

- Kali Linux (recommended) or other Linux distribution
- Python 3.6+
- Nmap
- Metasploit Framework
- OpenVAS (optional but recommended for vulnerability scanning)
- Ollama (for AI functionality)

## AI Models

AI_MAL uses the following AI models by default:
- Primary model: artifish/llama3.2-uncensored
- Fallback model: gemma3:1b

You can specify any Ollama-compatible model with the `--model` parameter.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for legal penetration testing and security research only. Users are responsible for complying with all applicable laws. The authors assume no liability for misuse of this software. 