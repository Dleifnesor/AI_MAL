# AI_MAL Installation Guide for Kali Linux

This guide provides detailed installation instructions for setting up AI_MAL on Kali Linux, including all dependencies and configurations.

## Prerequisites

- Kali Linux (2023.1 or newer)
- Python 3.6 or higher
- Nmap
- Metasploit Framework
- Ollama

## Automated Installation

For a quick setup, follow these steps:

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

3. Pull the Qwen2.5-coder:7b model for Ollama:
   ```bash
   ollama pull qwen2.5-coder:7b
   ```

4. Install required Python modules:
   ```bash
   pip install pymetasploit3 netifaces
   ```

Note: If you encounter a "module 'pymetasploit3' has no attribute 'msfrpc'" error when using MSF integration, try reinstalling the module with:
```bash
pip uninstall -y pymetasploit3
pip install --force-reinstall pymetasploit3
```

The installation script will set up the necessary dependencies and configure the system for AI_MAL.

## Manual Installation

If you prefer to install components manually, follow these steps:

### 1. Install Python Dependencies

```bash
pip install nmap netifaces requests psutil pymetasploit3
```

### 2. Configure Metasploit

Set up the Metasploit RPC service:

```bash
# Create a systemd service for msfrpcd
cat > /etc/systemd/system/msfrpcd.service << EOL
[Unit]
Description=Metasploit rpc daemon
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
ExecStart=/usr/bin/msfrpcd -P msf_password -S -a 127.0.0.1 -p 55553

[Install]
WantedBy=multi-user.target
EOL

# Enable and start the service
systemctl enable msfrpcd.service
systemctl start msfrpcd.service
```

### 3. Install and Configure Ollama

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Start the Ollama service and keep it running
systemctl enable ollama.service    # If it's installed as a systemd service
systemctl start ollama.service     # If it's installed as a systemd service

# Alternative: Start Ollama manually if not using systemd
nohup ollama serve > /var/log/ollama.log 2>&1 &
```

Then pull the Qwen2.5-coder:7b model:

```bash
# Verify Ollama is running before pulling models
curl -s http://localhost:11434/

# Pull models once Ollama is confirmed running
ollama pull qwen2.5-coder:7b
ollama pull llama3  # Backup model for systems with limited resources
```

## Verifying Installation

Verify that all components are working correctly:

1. Check Python dependencies:
   ```bash
   python3 -c "import nmap, netifaces, requests, pymetasploit3; print('Dependencies OK')"
   ```

2. Verify Ollama installation:
   ```bash
   # Check if the Ollama service is running
   systemctl status ollama.service   # If installed as a systemd service
   # OR
   ps aux | grep ollama
   
   # Check if the API endpoint is accessible
   curl -s http://localhost:11434/
   
   # List available models
   ollama list
   ```

3. Check Metasploit RPC service:
   ```bash
   systemctl status msfrpcd.service
   ```

## Running AI_MAL

After installation, run AI_MAL with your preferred options:

```bash
# Example using Qwen2.5-coder:7b model with automatic discovery
sudo AI_MAL --auto-discover --model qwen2.5-coder:7b

# Example targeting a specific host with Metasploit integration
sudo AI_MAL 192.168.1.100 --msf --exploit
```

## Docker Usage

To run AI_MAL in a Docker container:

```bash
# Build the Docker image
docker build -t ai_mal .

# Run with auto-discovery
docker run --net=host --privileged -v $(pwd)/scripts:/opt/ai_mal/generated_scripts -it ai_mal --auto-discover

# Target a specific host with Metasploit
docker run --net=host --privileged -it ai_mal --target 192.168.1.100 --msf --exploit

# Full autonomous mode
docker run --net=host --privileged -it ai_mal --full-auto
```

## Autostart Configuration

The installation script configures Ollama and Metasploit to start automatically when your system boots up. This ensures that AI_MAL can always connect to these essential services without manual intervention.

### Autostart Status

To check if the autostart service is active:
```bash
sudo systemctl status ai_mal_deps.service
```

### Managing Autostart

```bash
# Disable autostart
sudo systemctl disable ai_mal_deps.service

# Enable autostart
sudo systemctl enable ai_mal_deps.service

# Manually start dependencies
sudo systemctl start ai_mal_deps.service

# Manually stop dependencies
sudo systemctl stop ai_mal_deps.service
```

### Automatic Service Startup

When you run AI_MAL, it automatically checks if Ollama and Metasploit services are running. If not, it will attempt to start them, provided you have the necessary permissions (typically root/sudo).

You can always run AI_MAL without waiting for a system restart - it will detect and start any required services that aren't running.

## Troubleshooting

### Ollama Model Problems
- If Ollama fails to load models, ensure you have enough RAM (8GB+ recommended).
- For systems with limited RAM, use the smaller `llama3` model instead of `qwen2.5-coder:7b`.

### Ollama Connection Issues
- If you see "Cannot connect to Ollama API" or similar errors:
  ```bash
  # Check if Ollama is actually running
  ps aux | grep ollama

  # Start Ollama manually if needed
  ollama serve
  
  # Verify the API is accessible (should return 200 OK)
  curl -s -I http://localhost:11434/
  ```

- If API connects but returns errors in AI_MAL:
  ```bash
  # Check available models
  ollama list
  
  # Pull the model you want to use
  ollama pull qwen2.5-coder:7b
  ```

- For "API ERROR: 500" messages:
  1. Check Ollama logs: `journalctl -u ollama.service` (if using systemd)
  2. Verify you have enough disk space and RAM
  3. Try using a smaller model with `--model llama3`
  4. Increase the scan timeout with `--delay 10` (or higher)

### Metasploit Connection Issues
- If you see connection errors with Metasploit, start the service manually:
  ```bash
  sudo msfrpcd -P msf_password -S -a 127.0.0.1 -p 55553
  ```
- If you encounter a "module 'pymetasploit3' has no attribute 'msfrpc'" error, reinstall the module:
  ```bash
  pip uninstall -y pymetasploit3
  pip install --force-reinstall pymetasploit3
  ```

### Permission Issues
- Most features require root/sudo privileges. Run with `sudo AI_MAL [options]`.
- If you encounter permission errors with network interfaces, ensure you're running as root. 