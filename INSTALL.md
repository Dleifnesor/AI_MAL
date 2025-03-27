# AI_MAL Installation Guide for Kali Linux

This guide will walk you through the process of installing and configuring AI_MAL on Kali Linux.

## Prerequisites

AI_MAL requires the following:
- Kali Linux (tested on 2023.1 and newer)
- Python 3.6 or higher
- Nmap
- Metasploit Framework
- Ollama
- Internet connection for downloading dependencies

Kali Linux comes with most of the required tools pre-installed, but we'll need to set up a few additional components.

## Installation Methods

### Method 1: Automated Installation (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/yourusername/AI_MAL.git
cd AI_MAL
```

2. Run the installation script:
```bash
chmod +x install.sh
sudo ./install.sh
```

The script will install all required dependencies, configure Metasploit, and set up AI_MAL as a system command.

### Method 2: Manual Installation

If you prefer to install the components manually or if the automated script fails, follow these steps:

#### 1. Install Python Dependencies

```bash
pip install python-nmap requests pymetasploit3 netifaces ipaddress
```

#### 2. Configure Metasploit

Metasploit needs to be configured with a database and RPC service:

```bash
# Start PostgreSQL service
sudo systemctl start postgresql

# Initialize the Metasploit database
sudo msfdb init

# Start the Metasploit RPC service
sudo msfrpcd -P 'msf_password' -S -a 127.0.0.1 -p 55553
```

#### 3. Install Ollama

Ollama is required for the AI components of AI_MAL:

```bash
# Download and install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the llama3 model (or another compatible model)
ollama pull llama3
```

#### 4. Make AI_MAL Executable and Available System-wide

```bash
# Make the scripts executable
chmod +x adaptive_nmap_scan.py
chmod +x AI_MAL

# Create a symbolic link to make AI_MAL available system-wide
sudo ln -sf $(pwd)/AI_MAL /usr/local/bin/AI_MAL
```

## Post-Installation Setup

### Verify Installation

To verify that AI_MAL is properly installed, run:

```bash
AI_MAL --version
```

You should see the version information displayed.

### First Run

For a basic test of AI_MAL's functionality:

```bash
# Auto-discover mode
sudo AI_MAL --auto-discover

# Or specify a target directly
AI_MAL --target 192.168.1.1
```

### Troubleshooting

#### Ollama Connection Issues

If AI_MAL cannot connect to Ollama, ensure it's running:

```bash
# Check if Ollama is running
ps aux | grep ollama

# Start Ollama if not running
ollama serve
```

#### Metasploit Database Issues

If you encounter Metasploit database errors:

```bash
# Reinitialize the Metasploit database
sudo msfdb reinit

# Verify the database is connected
msfconsole -q -x "db_status; exit"
```

#### Permission Issues

Many scanning operations require root privileges:

```bash
sudo AI_MAL [options]
```

#### Network Interface Issues

If AI_MAL cannot find the correct network interface:

```bash
# List available interfaces
ip addr

# Specify the interface explicitly
AI_MAL --auto-discover --interface eth0
```

## Running AI_MAL in a Docker Container (Advanced)

For isolated environments, you can run AI_MAL in a Docker container:

```bash
# Build the Docker image
docker build -t ai_mal .

# Run AI_MAL in Docker with network access
docker run --net=host --privileged -it ai_mal --auto-discover
```

## Security Considerations

- Always ensure you have proper authorization before scanning or exploiting any network or system
- Be cautious when using the `--execute-scripts` option as it will run AI-generated code
- For production environments, consider running in a dedicated VM or container

## Next Steps

For detailed usage instructions and examples, refer to the README.md file or run:

```bash
AI_MAL --help
```

Happy ethical hacking! 