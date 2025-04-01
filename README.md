# AI_MAL - AI-Powered Penetration Testing Tool

AI_MAL is an advanced penetration testing tool that combines the power of Nmap, Metasploit, and AI to automate and enhance security assessments. It uses Ollama's AI models to analyze scan results and generate custom exploitation scripts.

## Features

- **Intelligent Scanning**: Uses Nmap with AI-powered analysis to identify vulnerabilities
- **Metasploit Integration**: Automated exploitation and post-exploitation
- **AI Analysis**: Leverages Ollama models for intelligent vulnerability assessment
- **Custom Script Generation**: AI-powered generation of custom exploitation scripts
- **Full Automation**: Supports fully automated penetration testing workflows
- **Kali Linux Integration**: Optimized for Kali Linux environment

## Prerequisites

- Kali Linux (recommended) or similar penetration testing distribution
- Python 3.8 or higher
- Nmap
- Metasploit Framework
- Ollama (for AI model support)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ai_mal.git
cd ai_mal
```

2. Run the installation script:
```bash
sudo ./install.sh
```

The script will:
- Install system dependencies
- Set up Python virtual environment
- Install AI_MAL package
- Configure environment variables
- Set up command-line access
- Install command completion

## Usage

Basic usage:
```bash
AI_MAL 192.168.1.1 --msf --exploit --model qwen2.5-coder:7b --full-auto
```

### Common Options

- `--msf`: Enable Metasploit integration
- `--exploit`: Attempt exploitation of vulnerabilities
- `--model`: Specify Ollama model to use (default: qwen2.5-coder:7b)
- `--full-auto`: Enable full automation mode
- `--custom-scripts`: Enable AI-powered script generation
- `--script-type`: Type of script to generate (python, bash, ruby)
- `--execute-scripts`: Automatically execute generated scripts

### Advanced Options

- `--stealth`: Enable stealth mode
- `--continuous`: Run continuous scanning
- `--delay`: Delay between scans in seconds
- `--services`: Enable service detection
- `--version`: Enable version detection
- `--os`: Enable OS detection
- `--vuln`: Enable vulnerability scanning
- `--dos`: Attempt Denial of Service attacks

## Examples

1. Basic scan with AI analysis:
```bash
AI_MAL 192.168.1.1 --ai-analysis
```

2. Full automated penetration test:
```bash
AI_MAL 192.168.1.1 --msf --exploit --model qwen2.5-coder:7b --full-auto
```

3. Generate and execute custom scripts:
```bash
AI_MAL 192.168.1.1 --custom-scripts --script-type python --execute-scripts
```

4. Stealth scan with service detection:
```bash
AI_MAL 192.168.1.1 --stealth --services --version
```

## Project Structure

```
ai_mal/
├── ai_mal/              # Main package directory
│   ├── core/           # Core functionality
│   ├── tests/          # Test files
│   └── examples/       # Example scripts
├── main.py             # Entry point
├── setup.py           # Package setup
├── requirements.txt   # Python dependencies
├── install.sh         # Installation script
└── README.md         # This file
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and authorized testing purposes only. Always obtain proper authorization before performing security assessments.

## Acknowledgments

- Nmap Project
- Metasploit Framework
- Ollama Team
- All contributors and users of this tool 