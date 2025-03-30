# AI_MAL Installation Guide for Kali Linux

This guide provides step-by-step instructions for installing and configuring AI_MAL on Kali Linux.

## Prerequisites

- Kali Linux (2023.1 or newer)
- Python 3.6+
- Nmap
- Metasploit Framework
- Ollama
- Root/sudo privileges

# Automated Installation (Recommended)

### 1. Switch to Root User

```bash
sudo su
```

### 2. Clone the Repository

```bash
git clone https://github.com/Dleifnesor/AI_MAL.git
cd AI_MAL
```

### 3. Run the Installation Script

```bash
chmod +x install.sh
./install.sh
```

This script will:
- Install all required dependencies system-wide
- Configure Metasploit and its database
- Install Ollama and download the Qwen2.5-coder:7b model (default)
- Fix line ending issues (converts Windows CRLF to Unix LF)
- Create the necessary directories
- Set up AI_MAL system-wide

The installation script automatically pulls and tests the Qwen2.5-coder:7b model, which is now the default model for AI_MAL.

## Manual Installation

If you prefer to install components manually or if the automated script fails, follow these steps:

### 1. Switch to Root User

```bash
sudo su
```

### 2. Install Python Dependencies

```bash
# Install system packages
apt install -y python3-nmap python3-requests python3-netifaces dos2unix

# Install additional packages via pip with --break-system-packages flag
pip install pymetasploit3 --break-system-packages
```

### 3. Fix Line Ending Issues

Windows-style line endings can cause issues on Linux. Fix them with:

```bash
# Install dos2unix if not already done
apt install -y dos2unix

# Convert line endings
dos2unix adaptive_nmap_scan.py
dos2unix AI_MAL

# Make scripts executable
chmod +x adaptive_nmap_scan.py
chmod +x AI_MAL
```

### 4. Configure Metasploit

```bash
# Start PostgreSQL service
systemctl start postgresql
systemctl enable postgresql

# Initialize the Metasploit database
msfdb init

# Set up Metasploit RPC service
msfrpcd -P 'msf_password' -S -a 127.0.0.1 -p 55553
```

### 5. Create a Systemd Service for Metasploit RPC (Optional but Recommended)

Create a service file for Metasploit RPC:

```bash
nano /etc/systemd/system/msfrpcd.service
```

Add the following content:

```
[Unit]
Description=Metasploit rpc daemon
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
ExecStart=/usr/bin/msfrpcd -P msf_password -S -a 127.0.0.1 -p 55553
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
systemctl daemon-reload
systemctl enable msfrpcd.service
systemctl start msfrpcd.service
```

### 6. Install and Configure Ollama

```bash
# Download and install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama service
ollama serve &

# Pull the Qwen2.5-coder:7b model
ollama pull qwen2.5-coder:7b
```

### 7. Configure AI_MAL

```bash
# Make scripts executable
chmod +x adaptive_nmap_scan.py
chmod +x AI_MAL

# Create directory for generated scripts
mkdir -p generated_scripts

# Create a system-wide link (optional)
ln -sf $(pwd)/AI_MAL /usr/local/bin/AI_MAL
```

## Verifying the Installation

Verify that AI_MAL is properly installed by running:

```bash
AI_MAL --version
```

## First Run with Qwen2.5-coder:7b

To start using AI_MAL with the Qwen2.5-coder:7b model:

```bash
# For autodiscovery (requires root)
AI_MAL --auto-discover --model qwen2.5-coder:7b

# Or for a specific target
AI_MAL --target 192.168.1.1 --model qwen2.5-coder:7b
```

## Running in Docker

For a containerized setup:

```bash
# Build the Docker image
docker build -t ai_mal .

# Run AI_MAL with the Qwen2.5-coder:7b model
docker run --net=host --privileged -v $(pwd)/scripts:/opt/ai_mal/generated_scripts -it ai_mal --model qwen2.5-coder:7b --auto-discover
```

## Troubleshooting

### Line Ending Issues

If you see the error `bad interpreter: /bin/bash^M: no such file or directory`:

```bash
# Fix line endings
apt install -y dos2unix
dos2unix AI_MAL
dos2unix adaptive_nmap_scan.py
chmod +x AI_MAL
chmod +x adaptive_nmap_scan.py
```

### Python Package Issues

If you encounter issues with Python packages:

```bash
# Reinstall system packages
apt install --reinstall python3-nmap python3-requests python3-netifaces

# Reinstall additional packages
pip install pymetasploit3 --break-system-packages
```

### Ollama Model Issues

If you encounter issues with the Qwen2.5-coder:7b model:

```bash
# Verify Ollama is running
ps aux | grep ollama

# Restart Ollama if needed
killall ollama
ollama serve &

# Re-pull the model
ollama pull qwen2.5-coder:7b
```

### Metasploit Connection Issues

If AI_MAL cannot connect to Metasploit:

```bash
# Check if msfrpcd is running
ps aux | grep msfrpcd

# Restart the service if needed
systemctl restart msfrpcd.service

# Or start manually
msfrpcd -P 'msf_password' -S -a 127.0.0.1 -p 55553
```

### Permission Issues

Many operations require root privileges:

```bash
AI_MAL --auto-discover --model qwen2.5-coder:7b
```

## Performance Optimization

The Qwen2.5-coder:7b model may require significant system resources. For optimal performance:

- Ensure your system has at least 16GB of RAM
- Free up system resources before running AI_MAL
- Consider using a GPU if available

## Security Notice

Always use this tool responsibly and ethically. Only scan and exploit systems you have proper authorization to test. 