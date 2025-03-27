# AI_MAL: Advanced Intelligent Machine-Aided Learning for Network Penetration

AI_MAL is a cutting-edge autonomous network reconnaissance and exploitation system that combines adaptive Nmap scanning with Ollama AI and Metasploit to automatically discover networks, identify vulnerabilities, and exploit them without human intervention.

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.6%2B-blue" alt="Python 3.6+">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License: MIT">
  <img src="https://img.shields.io/badge/Platform-Linux-orange" alt="Platform: Linux">
</p>

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

2. Ensure Nmap is installed (should be pre-installed on Kali):
```bash
sudo apt update
sudo apt install nmap
```

3. Install and configure Ollama:
```bash
# Download and install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the llama3 model (or another compatible model)
ollama pull llama3
```

4. Set up Metasploit (should be pre-installed on Kali):
```bash
# Start PostgreSQL service for Metasploit
sudo systemctl start postgresql

# Initialize the Metasploit database
sudo msfdb init

# Start msfrpcd service for API access
sudo msfrpcd -P 'msf_password' -S -a 127.0.0.1 -p 55553
```

5. Install AI_MAL as a system command:
```bash
sudo ln -s $(pwd)/AI_MAL /usr/local/bin/AI_MAL
chmod +x AI_MAL
```

## Usage

### Basic Usage

```bash
AI_MAL [options] [target]
```

### Command-line Options

```
Options:
  -h, --help            Show this help message and exit
  -t TARGET, --target TARGET
                        Target IP address or hostname (optional if --auto-discover is used)
  -m MODEL, --model MODEL
                        Ollama model to use (default: llama3)
  -i ITERATIONS, --iterations ITERATIONS
                        Maximum number of scan iterations (default: 3)
  -c, --continuous      Run in continuous mode until manually stopped
  -d DELAY, --delay DELAY
                        Delay in seconds between scans (default: 2)
  --msf                 Enable Metasploit integration
  --exploit             Automatically attempt exploitation using Metasploit
  --workspace WORKSPACE Name of Metasploit workspace (default: adaptive_scan)
  --stealth             Enable stealth mode for scans to avoid detection
  --auto-script         Auto-generate and run Metasploit resource scripts
  --full-auto           Full autonomous mode (implies --continuous --msf --exploit --auto-script)
  --quiet               Reduce verbosity of output
  --debug               Enable debug logging
  --auto-discover       Automatically discover network and hosts
  --interface INTERFACE Network interface to use for discovery
  --scan-all            Scan all discovered hosts (implies --auto-discover)
  --network NETWORK     Specific network to scan in CIDR notation (e.g., 192.168.1.0/24)
  --host-timeout TIMEOUT
                        Timeout in seconds for host discovery (default: 1)
```

### Usage Examples

#### Network Discovery and Scanning

Discover and scan the local network:
```bash
AI_MAL --auto-discover
```

Scan all hosts on the local network:
```bash
AI_MAL --scan-all
```

Specify a network interface:
```bash
AI_MAL --auto-discover --interface eth0
```

Scan a specific network:
```bash
AI_MAL --auto-discover --network 192.168.1.0/24
```

#### Exploitation and Continuous Scanning

Run with Metasploit integration:
```bash
AI_MAL --auto-discover --msf
```

Enable automatic exploitation:
```bash
AI_MAL --auto-discover --msf --exploit
```

Run continuously in stealth mode:
```bash
AI_MAL --auto-discover --stealth --continuous
```

Full autonomous mode:
```bash
AI_MAL --full-auto --scan-all
```

## Advanced Usage Scenarios

### Penetration Testing

For professional penetration testers, AI_MAL can serve as an automated reconnaissance and initial exploitation tool, freeing up time to focus on more complex aspects of the engagement:

```bash
AI_MAL --target 10.10.10.0/24 --stealth --msf --exploit --workspace client_pentest
```

### Network Security Monitoring

Security teams can use AI_MAL to continuously monitor their network for potentially vulnerable services:

```bash
AI_MAL --auto-discover --continuous --quiet --scan-all --stealth
```

### CTF Competitions

Quickly identify and exploit vulnerable machines in Capture The Flag competitions:

```bash
AI_MAL --auto-discover --full-auto --scan-all --delay 1
```

### Running in Docker

For isolated and portable execution:

```bash
# Build the Docker image
docker build -t ai_mal .

# Run with auto-discovery
docker run --net=host --privileged -v $(pwd)/scripts:/opt/ai_mal/generated_scripts -it ai_mal --auto-discover

# Target a specific host
docker run --net=host --privileged -it ai_mal --target 192.168.1.100 --msf --exploit

# Use full autonomous mode
docker run --net=host --privileged -it ai_mal --full-auto
```

## Comparison to Other Tools

| Feature | AI_MAL | AutoSploit | TheSurg30n | Standard Nmap+MSF |
|---------|--------|------------|------------|-------------------|
| AI-guided scans | ✅ | ❌ | ❌ | ❌ |
| Network auto-discovery | ✅ | ❌ | ❌ | ❌ |
| Stealth techniques | ✅ | ❌ | ❌ | Manual |
| Continuous adaptation | ✅ | ❌ | ❌ | ❌ |
| Exploit matching | ✅ | Basic | ✅ | Manual |
| Ease of use | ✅ | ✅ | ❌ | ❌ |

## Troubleshooting

### Common Issues

1. **Metasploit RPC Connection Errors**: 
   - Ensure msfrpcd is running with `sudo msfrpcd -P 'msf_password' -S -a 127.0.0.1 -p 55553`
   - Check firewall settings aren't blocking the connection

2. **Ollama Model Issues**:
   - Try pulling a different model: `ollama pull llama2`
   - Use it with the command: `AI_MAL --model llama2 --auto-discover`

3. **Network Discovery Problems**:
   - Run the tool with sudo: `sudo AI_MAL --auto-discover`
   - Manually specify your network: `AI_MAL --network 192.168.1.0/24`

4. **Permission Errors**:
   - Most scanning operations require root privileges: `sudo AI_MAL [options]`

### Getting Help

For more assistance, run:
```bash
AI_MAL --help
```

## Security Notice

This tool is designed for legitimate security testing and network administration purposes only. Always ensure you have proper authorization before scanning or exploiting any network or system. Unauthorized scanning or exploitation may violate computer fraud and abuse laws.

## References

- [Metasploit Vulnerability Scanning Guide](https://www.offsec.com/metasploit-unleashed/vulnerability-scanning/)
- [Using Metasploit and Nmap to Scan for Vulnerabilities in Kali Linux](https://www.geeksforgeeks.org/using-metasploit-and-nmap-to-scan-for-vulnerabilities-in-kali-linux/)
- [TheSurg30n Tool for Automated Exploitation](https://medium.com/@wabafet/pwning-metasploitable2-via-th3surg30n-using-nothing-but-a-single-python-script-to-bring-the-power-6e4fdc96cecf)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 