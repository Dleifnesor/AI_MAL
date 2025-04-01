See [use_cases.md](use_cases.md) for full details on each arg

## Features

- **AI-Powered Adaptive Scanning**: Uses Ollama to analyze scan results and adapt scanning strategies in real-time
- **Network Discovery**: Automatically discovers hosts and networks without manual target specification
- **Stealth Mode**: Various techniques to evade detection while scanning
- **Metasploit Integration**: Automatic exploitation of vulnerabilities through Metasploit
- **Resource Script Generation**: Generates custom Metasploit resource scripts based on scan results
- **Custom Script Generation**: Uses Ollama to generate and optionally execute custom scripts based on reconnaissance data
- **Continuous Monitoring**: Option to continuously scan and monitor for changes in network topology

## Requirements

- Kali Linux (recommended) or other Linux distribution
- Python 3.6+
- Nmap
- Metasploit Framework
- Ollama (with recommended model: qwen2.5-coder:7b)

(The install.sh script will autoinstall MSF and ollama)

## System Requirements and Memory Considerations

AI_MAL relies on Ollama to run AI models, which have different memory requirements:

- **Recommended**: 16GB+ RAM for optimal performance with all models
- **Minimum**: 8GB RAM (with some performance limitations)
- **Low Memory Systems**: 4-8GB RAM (use lightweight model options)

For systems with limited resources:

1. Use the `--model llama3` option instead of the default qwen2.5-coder:7b model:
   ```bash
   AI_MAL --auto-discover --model llama3
   ```

2. Close other memory-intensive applications while running AI_MAL

3. If you experience timeouts or performance issues:
   - The tool automatically increases timeouts on low-memory systems
   - Consider adding a swap file to your system:
     ```bash
     sudo fallocate -l 4G /swapfile
     sudo chmod 600 /swapfile
     sudo mkswap /swapfile
     sudo swapon /swapfile
     ```

4. For virtual machines, consider allocating more RAM if possible

## Installation

See [INSTALL.md](INSTALL.md) for detailed installation instructions.

For quick installation on Kali Linux:

```bash
# Clone the repository
git clone https://github.com/Dleifnesor/AI_MAL.git
cd AI_MAL

# Switch to root user (recommended)
sudo su

# Run the installation script
chmod +x install.sh
./install.sh
```

### Common Installation Issues

If you encounter the error `bad interpreter: /bin/bash^M: no such file or directory` when running the AI_MAL script, it's due to Windows-style line endings (CRLF). Fix it with:

```bash
# Install dos2unix if not already installed
apt install -y dos2unix

# Convert line endings
dos2unix AI_MAL
dos2unix adaptive_nmap_scan.py

# Make scripts executable
chmod +x AI_MAL
chmod +x adaptive_nmap_scan.py
```

## Usage

Basic usage:

```bash
AI_MAL --target 192.168.1.0/24
```

Auto-discovery mode:

```bash
AI_MAL --auto-discover
```

Full autonomous mode:

```bash
AI_MAL --full-auto
```

Run continuously in stealth mode:

```bash
AI_MAL --auto-discover --stealth --continuous
```

Using the Qwen2.5-coder:7b model:

```bash
AI_MAL --auto-discover --model qwen2.5-coder:7b --msf
```

For all available options:

```bash
AI_MAL --help
```

## Running in Docker

Build the Docker image:

```bash
docker build -t ai_mal .
```

Run with auto-discovery:

```bash
docker run --net=host --privileged -v $(pwd)/scripts:/opt/ai_mal/generated_scripts -it ai_mal --auto-discover
```

Target a specific host:

```bash
docker run --net=host --privileged -it ai_mal --target 192.168.1.100 --msf --exploit
```

Full autonomous mode:

```bash
docker run --net=host --privileged -it ai_mal --full-auto
```

## Security Notice

This tool is intended for legitimate security testing and educational purposes only. Unauthorized scanning and exploitation of systems is illegal and unethical. Always obtain proper authorization before testing any systems.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Key Features

- **AI-Guided Scanning**: Uses Ollama AI models to analyze scan results and suggest optimal next steps
- **Adaptive Scanning**: Continuously adjusts scan parameters based on discovered information
- **Full Metasploit Integration**: Imports scan results directly into Metasploit for exploitation
- **Automated Exploitation**: Automatically matches discovered services with appropriate exploits
- **Continuous Scanning Mode**: Runs indefinitely, adapting to network changes over time
- **Stealth Mode**: Employs evasive scanning techniques to minimize detection
- **Automatic Network Discovery**: Identifies local networks and connected hosts for scanning
- **Multi-Subnet Scanning**: Discovers and explores connected network segments automatically
- **Shell Command Wrapper**: Simple command-line wrapper for easy use as a system utility

## Why AI_MAL?

Unlike basic scanning tools or simple automation scripts, AI_MAL brings intelligence to the penetration testing process. Instead of running pre-defined scans, it:

1. Uses AI to analyze scan results and determine the most effective next steps
2. Learns from previous scans to refine its approach
3. Operates autonomously with minimal human intervention
4. Employs stealth techniques to avoid detection
5. Continuously adapts to changes in the network environment

## Installation on Kali Linux

For detailed installation instructions, see [INSTALL.md](INSTALL.md).

### Quick Install

```bash
git clone https://github.com/yourusername/AI_MAL.git
cd AI_MAL
chmod +x install.sh
sudo ./install.sh
```

### Manual Installation

1. Install required Python packages:
```bash
pip install python-nmap requests pymetasploit3 netifaces ipaddress
```
