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

The installation script will:
- Set up a Python virtual environment with all required packages
- Configure the Metasploit RPC service
- Install and configure Ollama
- Install the AI_MAL tool system-wide

## Manual Installation

If you prefer to install components manually, follow these steps:

### 1. Install Python Dependencies in a Virtual Environment

```bash
# Create installation directory
sudo mkdir -p /opt/ai_mal

# Create and activate virtual environment
sudo python3 -m venv /opt/ai_mal/venv
source /opt/ai_mal/venv/bin/activate

# Install Python packages
pip install nmap requests pymetasploit3 psutil netifaces

# Deactivate when done
deactivate
```

### 2. Configure Metasploit

Set up the Metasploit RPC service:

```bash
# Create a systemd service for msfrpcd
sudo bash -c 'cat > /etc/systemd/system/msfrpcd.service << EOL
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
EOL'

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable msfrpcd.service
sudo systemctl start msfrpcd.service
```

### 3. Install and Configure Ollama

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Start the Ollama service
sudo systemctl enable ollama.service    # If it's installed as a systemd service
sudo systemctl start ollama.service     # If it's installed as a systemd service

# OR start Ollama manually if not using systemd
nohup ollama serve > /var/log/ollama.log 2>&1 &
```

Then pull the required models:

```bash
# Verify Ollama is running before pulling models
curl -s http://localhost:11434/

# Pull models
ollama pull qwen2.5-coder:7b
ollama pull llama3  # Backup model for systems with limited resources
```

### 4. Install AI_MAL Files

```bash
# Copy files to installation directory
sudo cp adaptive_nmap_scan.py /opt/ai_mal/
sudo cp AI_MAL /opt/ai_mal/

# Fix line endings if needed
sudo dos2unix /opt/ai_mal/adaptive_nmap_scan.py
sudo dos2unix /opt/ai_mal/AI_MAL

# Make executable
sudo chmod +x /opt/ai_mal/adaptive_nmap_scan.py
sudo chmod +x /opt/ai_mal/AI_MAL

# Create symlink
sudo ln -sf /opt/ai_mal/AI_MAL /usr/local/bin/AI_MAL
```

## Verifying Installation

Verify that all components are working correctly:

1. Check Python dependencies (using the virtual environment):
   ```bash
   source /opt/ai_mal/venv/bin/activate
   python -c "import nmap, netifaces, requests, pymetasploit3; print('Dependencies OK')"
   deactivate
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

### Virtual Environment Issues

- If you see errors related to missing Python modules:
  ```bash
  # Recreate the virtual environment
  sudo rm -rf /opt/ai_mal/venv
  sudo python3 -m venv /opt/ai_mal/venv
  sudo /opt/ai_mal/venv/bin/pip install nmap requests pymetasploit3 psutil netifaces
  ```

- If you get permission errors with the virtual environment:
  ```bash
  # Fix ownership
  sudo chown -R root:root /opt/ai_mal/venv
  sudo chmod -R 755 /opt/ai_mal/venv
  ```

### Ollama Model Problems
- If Ollama fails to load models, ensure you have enough RAM (8GB+ recommended).
- For systems with limited RAM, use the smaller `llama3` model instead of `qwen2.5-coder:7b`.

### Python Installation Errors

- If you encounter "externally-managed-environment" errors:
  ```bash
  # This happens in newer Python versions that are managed by the system package manager
  # Add the --break-system-packages flag to pip commands:
  sudo pip3 install --break-system-packages <package-name>
  ```

- If packages fail to install:
  ```bash
  # Try installing dev packages that might be needed for compilation
  sudo apt install -y python3-dev build-essential
  sudo pip3 install --break-system-packages --upgrade pip setuptools wheel
  sudo pip3 install --break-system-packages <package-name>
  ```

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
  sudo pip3 uninstall -y pymetasploit3
  sudo pip3 install --break-system-packages --force-reinstall pymetasploit3
  ```

### Permission Issues
- Most features require root/sudo privileges. Run with `sudo AI_MAL [options]`.
- If you encounter permission errors with network interfaces, ensure you're running as root. 