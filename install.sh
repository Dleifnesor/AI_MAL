#!/bin/bash

# AI_MAL Installation Script
# This script installs the AI_MAL tool and makes it available as a system command

# Logging functions with color
log_info() {
    echo -e "\033[0;34m[INFO]\033[0m $1"
}

log_status() {
    echo -e "\033[0;36m[STATUS]\033[0m $1"
}

log_warning() {
    echo -e "\033[0;33m[WARNING]\033[0m $1"
}

log_error() {
    echo -e "\033[0;31m[ERROR]\033[0m $1"
}

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display messages with proper formatting
log_info() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[!]${NC} $1"
}

log_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root."
    exit 1
fi

# Check if running on Kali Linux
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ "$ID" == "kali" ]]; then
        IS_KALI=true
        echo "[+] Detected Kali Linux OS"
    else
        IS_KALI=false
        echo "[!] Not running on Kali Linux - some features may not work as expected"
    fi
else
    IS_KALI=false
    echo "[!] Could not determine OS - assuming non-Kali Linux"
fi

# Set correct paths for Kali Linux
if [ "$IS_KALI" = true ]; then
    OPENVAS_SOCKET_PATH="/var/run/ospd/ospd.sock"
    OPENVAS_USER="_gvm"
    OPENVAS_GROUP="_gvm"
else
    OPENVAS_SOCKET_PATH="/run/ospd/ospd.sock"
    OPENVAS_USER="gvm"
    OPENVAS_GROUP="gvm"
fi

# Function to check if Ollama is running
check_ollama_running() {
  max_attempts=10
  attempt=1
  echo "[+] Verifying Ollama service is running..."
  
  while [ $attempt -le $max_attempts ]; do
    if curl -s http://localhost:11434/api/version > /dev/null 2>&1; then
      echo "[+] Ollama service is running!"
      return 0
    else
      echo "[*] Waiting for Ollama service to start (attempt $attempt/$max_attempts)..."
      sleep 3
      attempt=$((attempt+1))
    fi
  done
  
  echo "[!] Ollama service did not start properly after multiple attempts."
  return 1
}

# Install Python dependencies
echo "[+] Installing Python dependencies..."
pip3 install -r requirements.txt 2>/dev/null || {
  echo "[!] No requirements.txt found. Creating one with basic dependencies."
  cat > requirements.txt << EOF
requests>=2.28.0
python-nmap>=0.7.1
pymetasploit3>=1.0.3
ollama>=0.1.4
rich>=12.0.0
pyfiglet>=0.8.0
prettytable>=2.5.0
xmltodict>=0.13.0
cryptography>=39.0.0
python-dateutil>=2.8.2
numpy>=1.22.0
pyyaml>=6.0
colorama>=0.4.4
jinja2>=3.0.0
EOF
  pip3 install -r requirements.txt
}

# Set up virtual environment
echo "[+] Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "[+] Virtual environment created successfully"
else
    echo "[*] Virtual environment already exists"
fi

# Activate virtual environment and install dependencies
echo "[+] Activating virtual environment and installing dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Create activation script
echo "[+] Creating environment activation script..."
cat > activate_venv.sh << EOF
#!/bin/bash
source venv/bin/activate
export PYTHONPATH=\$PYTHONPATH:\$(pwd)
EOF
chmod +x activate_venv.sh

# Install system dependencies and dos2unix for line ending conversion
echo "[+] Installing system dependencies..."
apt-get update
apt-get install -y nmap metasploit-framework hping3 apache2-utils dos2unix 2>/dev/null

# Convert Windows line endings to Unix format
echo "[+] Converting line endings for script files if needed..."
if command -v dos2unix >/dev/null 2>&1; then
    # Only convert .py and .sh files in project directory, excluding venv and site-packages
    find . -type f -name "*.py" -not -path "./venv/*" -not -path "*/site-packages/*" -print0 | xargs -0 dos2unix -q 2>/dev/null || true
    find . -type f -name "*.sh" -not -path "./venv/*" -not -path "*/site-packages/*" -print0 | xargs -0 dos2unix -q 2>/dev/null || true
else
    echo "[!] Warning: dos2unix not found, skipping line ending conversion"
fi

# Install OpenVAS/Greenbone Vulnerability Manager if needed
log_status "Checking for OpenVAS/Greenbone Vulnerability Manager..."
if ! check_openvas_installed; then
    log_status "Installing OpenVAS/Greenbone Vulnerability Manager..."
    
    echo "[+] Installing OpenVAS vulnerability scanner..."
    apt-get install -y openvas gvm 2>/dev/null || apt-get install -y openvas-scanner gvmd 2>/dev/null

    # Set up OpenVAS and get the password
    echo "[+] Setting up OpenVAS (this may take a while)..."
    if ! command -v gvm-check-setup >/dev/null 2>&1; then
        echo "[!] Error: OpenVAS/GVM not properly installed"
    else
        # Check if setup has been run before
        if [ ! -f /var/lib/gvm/GVM_VERSION ]; then
            echo "[+] Running OpenVAS setup (this may take 10-15 minutes)..."
            gvm-setup > /tmp/gvm-setup.log 2>&1 || echo "[!] Warning: gvm-setup returned non-zero exit code"
        else
            echo "[+] OpenVAS already set up, checking status..."
            gvm-check-setup > /tmp/gvm-check.log 2>&1
        fi
        
        # Extract password from logs
        if [ -f /var/log/gvm/gvm-setup.log ]; then
            GVM_PASSWORD=$(grep "User created with password" /var/log/gvm/gvm-setup.log | awk -F"'" '{print $2}')
        elif [ -f /tmp/gvm-setup.log ]; then
            GVM_PASSWORD=$(grep "User created with password" /tmp/gvm-setup.log | awk -F"'" '{print $2}')
        fi
        
        # Use default if not found
        if [ -z "$GVM_PASSWORD" ]; then
            echo "[!] Could not find OpenVAS password in logs, using default"
            GVM_PASSWORD="admin"
        else
            echo "[+] Found OpenVAS password in logs"
        fi
        
        # Export password for the scanner to use
        export GVM_PASSWORD
        echo "export GVM_PASSWORD=\"$GVM_PASSWORD\"" >> ~/.bashrc
        
        # Set socket permissions based on OS (Kali uses _gvm, Ubuntu uses gvm)
        if getent passwd _gvm > /dev/null; then
            echo "[+] Setting socket permissions for Kali Linux (_gvm user)..."
            chmod 666 /run/ospd/ospd.sock 2>/dev/null || true
            chown _gvm:_gvm /run/ospd/ospd.sock 2>/dev/null || true
        else
            echo "[+] Setting socket permissions for Ubuntu/Debian (gvm user)..."
            chmod 666 /run/ospd/ospd.sock 2>/dev/null || true
            chown gvm:gvm /run/ospd/ospd.sock 2>/dev/null || true
        fi
        
        # Add sudoers entry for ospd-openvas
        if getent passwd _gvm > /dev/null; then
            echo "_gvm ALL=(ALL) NOPASSWD: /usr/sbin/ospd-openvas" > /etc/sudoers.d/ospd-openvas
        else
            echo "gvm ALL=(ALL) NOPASSWD: /usr/sbin/ospd-openvas" > /etc/sudoers.d/ospd-openvas
        fi
        
        # Start services
        echo "[+] Starting OpenVAS services..."
        systemctl restart ospd-openvas
        systemctl restart gvmd
        
        echo "[+] OpenVAS setup completed successfully."
        echo "[+] Username: admin"
        echo "[+] Password: $GVM_PASSWORD"
    fi
else
    log_status "OpenVAS/Greenbone Vulnerability Manager is already installed"
fi

# Check and set OpenVAS socket permissions
check_openvas_socket

# Get OpenVAS password
GVM_PASSWORD=$(get_openvas_password)
log_info "OpenVAS admin password: $GVM_PASSWORD"

# Add OpenVAS credentials to environment
log_status "Setting up OpenVAS credentials in environment..."
echo "export GVM_USERNAME=admin" >> ~/.bashrc
echo "export GVM_PASSWORD='$GVM_PASSWORD'" >> ~/.bashrc
source ~/.bashrc

# Verify OpenVAS connection
log_status "Verifying OpenVAS service..."
if test_openvas_connection; then
    log_info "OpenVAS connection verified successfully!"
else
    log_warning "Could not verify OpenVAS connection. Retrying after service restart..."
    systemctl restart ospd-openvas
    systemctl restart gvmd
    sleep 5
    
    if test_openvas_connection; then
        log_info "OpenVAS connection verified successfully after retry!"
    else
        log_error "Could not connect to OpenVAS. Please check the service status manually."
        log_info "Try running: sudo gvm-check-setup"
    fi
fi

# Sync feed data if needed
if [ ! -d "/var/lib/gvm/scap-data" ] || [ -z "$(ls -A /var/lib/gvm/scap-data 2>/dev/null)" ]; then
    log_status "Synchronizing OpenVAS vulnerability data. This may take a while..."
    sudo -u _gvm greenbone-feed-sync --type SCAP || log_warning "Failed to sync SCAP data"
fi

# Install and setup Metasploit Framework
check_msf_installed

# Install and setup Ollama for AI features
if ! check_ollama_installed; then
    install_ollama
fi

# Make sure Ollama is running
if start_ollama; then
    echo "[+] Downloading artifish/llama3.2-uncensored model (this may take a while)..."
    ollama pull artifish/llama3.2-uncensored > /dev/null 2>&1
    
    # Ask if user wants to download additional models
    echo "[?] Do you want to download the backup AI model qwen2.5-coder:7b (will use ~3GB) (y/n)"
    read -r response
    if [[ "$response" == "y" ]]; then
        echo "[+] Downloading additional AI model..."
        ollama pull qwen2.5-coder:7b > /dev/null 2>&1
    fi
else
    echo "[!] Warning: Could not start Ollama service. AI features may not work."
    echo "[!] To use AI features, you'll need to manually start Ollama:"
    echo "    sudo ollama serve"
    echo "    ollama pull artifish/llama3.2-uncensored"
fi

# Make AI_MAL.py executable
echo "[+] Making AI_MAL.py executable..."
chmod +x AI_MAL.py

# Create directories if they don't exist
mkdir -p results logs scripts

# Create an example implant file for testing
echo "[+] Creating example implant for testing..."
mkdir -p scripts/implants
cat > scripts/implants/example_implant.py << EOF
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example Implant for AI_MAL Testing
=================================

This is a simple example implant that can be used for testing
the implant deployment functionality of AI_MAL.

WARNING: This is for educational purposes only.
"""

import os
import sys
import time
import socket
import platform
import subprocess

def get_system_info():
    """Get basic system information."""
    info = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "architecture": platform.machine()
    }
    return info

def establish_persistence():
    """Establish persistence on the system (simulation only)."""
    print("[*] Simulating persistence establishment...")
    print("[+] Persistence established successfully")
    return True

def main():
    """Main implant function."""
    print("[*] Example implant started")
    print("[*] System info:", get_system_info())
    
    # Simulate establishing persistence
    establish_persistence()
    
    # Simulate beacon functionality
    print("[*] Starting beacon loop (CTRL+C to exit)")
    try:
        count = 0
        while True:
            print(f"[*] Beacon {count}: Checking in...")
            time.sleep(5)
            count += 1
    except KeyboardInterrupt:
        print("[*] Implant terminated by user")

if __name__ == "__main__":
    main()
EOF
dos2unix scripts/implants/example_implant.py
chmod +x scripts/implants/example_implant.py

# Create symbolic link to make AI_MAL a command
echo "[+] Creating AI_MAL command..."
INSTALL_DIR=$(pwd)
ln -sf "$INSTALL_DIR/AI_MAL.py" /usr/local/bin/AI_MAL

# Add bash completion for AI_MAL
echo "[+] Setting up command completion..."
cat > /etc/bash_completion.d/ai_mal << EOF
_ai_mal()
{
    local cur prev opts
    COMPREPLY=()
    cur="\${COMP_WORDS[COMP_CWORD]}"
    prev="\${COMP_WORDS[COMP_CWORD-1]}"
    opts="--scan-type --stealth --continuous --delay --services --version --os --vuln --openvas --scan-config --use-nmap --dos --msf --exploit --custom-scripts --script-type --execute-scripts --script-output --script-format --ai-analysis --model --fallback-model --exfil --implant --output-dir --output-format --quiet --no-gui --debug --log-level --log-file --full-auto --custom-vuln"

    if [[ \${cur} == -* ]] ; then
        COMPREPLY=( \$(compgen -W "\${opts}" -- \${cur}) )
        return 0
    fi
}
complete -F _ai_mal AI_MAL
EOF
dos2unix /etc/bash_completion.d/ai_mal

# Create a desktop shortcut
echo "[+] Creating desktop shortcut..."
cat > /usr/share/applications/ai-mal.desktop << EOF
[Desktop Entry]
Name=AI_MAL
GenericName=AI-Powered Penetration Testing Tool
Comment=Advanced penetration testing tool with AI capabilities
Exec=gnome-terminal -- /usr/local/bin/AI_MAL
Icon=kali-menu
Terminal=true
Type=Application
Categories=03-webapp-analysis;03-vulnerability-analysis;04-exploitation-tools;
EOF

# Create common aliases in .bashrc with useful examples from use_cases.md
echo "[+] Creating helpful aliases..."
if ! grep -q "AI_MAL aliases" /root/.bashrc; then
  cat >> /root/.bashrc << EOF

# AI_MAL aliases
alias web-scan='AI_MAL --services --version --vuln --custom-scripts --script-type python --ai-analysis --output-dir ./webserver-assessment'
alias network-scan='AI_MAL --stealth --services --os --output-format json --output-dir ./internal-network-scan'
alias full-pentest='AI_MAL --scan-type full --msf --exploit --vuln --ai-analysis --custom-scripts --execute-scripts --log-level debug'
alias monitor='AI_MAL --continuous --delay 3600 --services --version --vuln --ai-analysis --quiet --output-dir ./continuous-monitoring'
alias critical-server-scan='AI_MAL --scan-type full --os --services --version --vuln --openvas --scan-config full_and_very_deep --ai-analysis --output-dir ./critical-server'
alias advanced-threat='AI_MAL --msf --exploit --exfil --custom-scripts --execute-scripts --ai-analysis --implant ./scripts/implants/example_implant.py'
alias full-auto='AI_MAL --full-auto --output-dir ./full-auto-assessment'
EOF
fi
dos2unix /root/.bashrc

# Set up environment variables for AI models
if ! grep -q "AI_MAL environment" /etc/profile.d/ai_mal.sh 2>/dev/null; then
  cat > /etc/profile.d/ai_mal.sh << EOF
# AI_MAL environment variables
export OLLAMA_HOST=http://localhost:11434
export OLLAMA_MODEL=artifish/llama3.2-uncensored
export OLLAMA_FALLBACK_MODEL=gemma3:1b

# Default to OpenVAS for vulnerability scanning
export AI_MAL_DEFAULT_VULN_SCANNER=openvas
export AI_MAL_OPENVAS_CONFIG=full_and_fast
export AI_MAL_OPENVAS_USERNAME=admin
EOF
  chmod +x /etc/profile.d/ai_mal.sh
  dos2unix /etc/profile.d/ai_mal.sh
fi

# Verify all scripts have correct line endings
echo "[+] Verifying line endings of important files..."
find . -type f -name "*.py" | xargs file | grep -v "CRLF" || echo "[+] All Python files have correct line endings"
find . -type f -name "*.sh" | xargs file | grep -v "CRLF" || echo "[+] All shell scripts have correct line endings"

# Final check that the main script is executable with correct line endings
file AI_MAL.py
head -n 1 AI_MAL.py

# Test that AI_MAL runs without errors
echo ""
echo "[+] Verifying AI_MAL functionality..."
if AI_MAL --help > /dev/null 2>&1; then
  echo "[+] AI_MAL is functioning correctly!"
else
  echo "[!] WARNING: There may be issues with AI_MAL. Please check the error messages and consult the troubleshooting section in the README."
  echo "[!] You might need to fix any import or dependency issues before using the tool."
  echo ""
  echo "[?] Press Enter to continue with installation anyway..."
  read -r
fi

echo "[+] Installation complete!"
echo "[+] Usage: AI_MAL [target] [options]"
echo "[+] For help: AI_MAL --help"
echo "[+] Examples can be found in use_cases.md"
echo ""
echo "[+] OpenVAS has been configured as the DEFAULT vulnerability scanner"
echo "[+] OpenVAS credentials - username: admin, password: (the password you saved during setup)"
echo ""
echo "[+] Special aliases created:"
echo "    web-scan [target] - Quick web server assessment"
echo "    network-scan [target] - Network reconnaissance"
echo "    full-pentest [target] - Complete penetration test"
echo "    monitor [target] - Continuous monitoring"
echo "    critical-server-scan [target] - Thorough assessment with deep OpenVAS scan"
echo "    advanced-threat [target] - Exploitation with data exfiltration and implant deployment"
echo "    full-auto [target] - Complete automated assessment"
echo ""
echo "[+] Example implant available at: ./scripts/implants/example_implant.py"
echo ""
echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                  IMPORTANT: OLLAMA SERVICE STATUS                             ║"
echo "║                                                                               ║"
if check_ollama_running; then
  echo "║         Ollama service is running properly!                                   ║"
  echo "║                                                                               ║"
  echo "║      AI features will work automatically.                                     ║"
else
  echo "║     Ollama service is NOT running properly!                                   ║"
  echo "║                                                                               ║"
  echo "║  To enable AI features, you must manually start Ollama:                       ║"
  echo "║  1. Open a terminal and run: ollama serve                                     ║"
  echo "║  2. Open another terminal and run: ollama pull artifish/llama3.2-uncensored   ║"
fi
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"

# Function to check if OpenVAS/GVM is installed
check_openvas_installed() {
    if command -v gvm-cli &> /dev/null && command -v gvmd &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to convert Python files to Unix format, excluding venv and site-packages
convert_python_files() {
    log_status "Converting Python files to Unix format..."
    find . -type f -name "*.py" -not -path "./venv/*" -not -path "*/site-packages/*" -print0 | xargs -0 dos2unix -q 2>/dev/null || true
}

# Function to convert shell script files to Unix format, excluding venv and site-packages
convert_shell_scripts() {
    log_status "Converting shell scripts to Unix format..."
    find . -type f -name "*.sh" -not -path "./venv/*" -not -path "*/site-packages/*" -print0 | xargs -0 dos2unix -q 2>/dev/null || true
}

# Function to extract OpenVAS admin password from logs or output
get_openvas_password() {
    local password=""
    
    # Check GVM setup log
    if [ -f "/var/log/gvm/gvm-setup.log" ]; then
        password=$(grep -a "User created with password" /var/log/gvm/gvm-setup.log | tail -1 | grep -o "'.*'" | tr -d "'")
        if [ -n "$password" ]; then
            log_info "Found admin password in gvm-setup.log"
            return 0
        fi
    fi
    
    # Check gvmd log
    if [ -f "/var/log/gvm/gvmd.log" ]; then
        password=$(grep -a "Created admin user with password" /var/log/gvm/gvmd.log | tail -1 | grep -o "'.*'" | tr -d "'")
        if [ -n "$password" ]; then
            log_info "Found admin password in gvmd.log"
            echo "$password"
            return 0
        fi
    fi
    
    # Check output of gvm-setup command
    if command -v gvm-setup >/dev/null 2>&1; then
        local setup_output=$(sudo gvm-setup 2>&1 || true)
        password=$(echo "$setup_output" | grep -a "password:" | tail -1 | awk '{print $NF}')
        if [ -n "$password" ]; then
            log_info "Found admin password from gvm-setup output"
            echo "$password"
            return 0
        fi
    fi
    
    log_warning "Could not find OpenVAS admin password"
    echo ""
    return 1
}

# Function to check and set OpenVAS socket permissions
check_openvas_socket() {
    local socket_found=false
    
    # Check both possible socket locations
    if [ -S "/var/run/ospd/ospd.sock" ]; then
        log_info "Found OpenVAS socket at /var/run/ospd/ospd.sock"
        sudo chmod 666 /var/run/ospd/ospd.sock
        socket_found=true
    fi
    
    if [ -S "/run/ospd/ospd.sock" ]; then
        log_info "Found OpenVAS socket at /run/ospd/ospd.sock"
        sudo chmod 666 /run/ospd/ospd.sock
        socket_found=true
    fi
    
    if [ "$socket_found" = false ]; then
        log_warning "OpenVAS socket not found. Services may need to be started."
    fi
}

# Function to test OpenVAS connection
test_openvas_connection() {
    log_info "Testing OpenVAS connection..."
    
    # Check if gvm-cli is available
    if ! command -v gvm-cli >/dev/null 2>&1; then
        log_error "gvm-cli command not found. OpenVAS may not be installed correctly."
        return 1
    fi
    
    # Try with password from environment
    local password="$GVM_PASSWORD"
    if [ -n "$password" ]; then
        if gvm-cli socket --gmp-username admin --gmp-password "$password" --xml "<get_version/>" >/dev/null 2>&1; then
            log_success "Successfully connected to OpenVAS with saved password."
            return 0
        fi
    fi
    
    # Try with default password
    if gvm-cli socket --gmp-username admin --gmp-password "admin" --xml "<get_version/>" >/dev/null 2>&1; then
        log_success "Successfully connected to OpenVAS with default password 'admin'."
        GVM_PASSWORD="admin"
        return 0
    fi
    
    # Try with no credentials
    if gvm-cli socket --xml "<get_version/>" >/dev/null 2>&1; then
        log_success "Successfully connected to OpenVAS without credentials."
        return 0
    fi
    
    log_error "Failed to connect to OpenVAS with any credentials."
    log_warning "You may need to run 'sudo gvm-check-setup' and 'sudo gvm-setup' to initialize OpenVAS."
    return 1
}

# Function to check if Metasploit is installed
check_msf_installed() {
    if command -v msfconsole &> /dev/null; then
        echo "[+] Metasploit Framework is installed"
        return 0
    else
        echo "[!] Metasploit Framework not found"
        if [ "$IS_KALI" = true ]; then
            echo "[+] Installing Metasploit Framework..."
            apt-get update && apt-get install -y metasploit-framework
            return $?
        else
            echo "[!] Please install Metasploit Framework manually"
            return 1
        fi
    fi
}

# Function to check if Ollama is installed
check_ollama_installed() {
    if command -v ollama &> /dev/null; then
        echo "[+] Ollama is installed"
        return 0
    else
        echo "[!] Ollama not found, will attempt to install"
        return 1
    fi
}

# Function to install Ollama
install_ollama() {
    echo "[+] Installing Ollama..."
    if curl -fsSL https://ollama.com/install.sh | sh; then
        echo "[+] Ollama installation successful"
        return 0
    else
        echo "[!] Ollama installation failed"
        return 1
    fi
}

# Function to check if Ollama service is running
check_ollama_running() {
    if pgrep -x "ollama" > /dev/null; then
        return 0
    elif curl -s localhost:11434/api/tags >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Start ollama in a more reliable way
start_ollama() {
    if ! check_ollama_running; then
        echo "[+] Starting Ollama service..."
        nohup ollama serve > /tmp/ollama.log 2>&1 &
        
        # Wait for service to start
        echo "[+] Waiting for Ollama service to initialize..."
        for i in {1..30}; do
            if curl -s localhost:11434/api/tags >/dev/null 2>&1; then
                echo "[+] Ollama service started successfully"
                return 0
            fi
            sleep 1
        done
        echo "[!] Timed out waiting for Ollama service"
        return 1
    else
        echo "[+] Ollama service is already running"
        return 0
    fi
}

# OpenVAS / Greenbone Vulnerability Management setup
if [ "$INSTALL_OPENVAS" = true ] || [ -z "$INSTALL_OPENVAS" ]; then
    echo "╔═════════════════════════════════════════════════════════════════════╗"
    echo "║                 Installing OpenVAS Scanner                          ║"
    echo "╚═════════════════════════════════════════════════════════════════════╝"
    
    # Install all prerequisites from INSTALL.md
    echo "[+] Installing OpenVAS prerequisites..."
    apt-get update
    apt-get install -y gcc pkg-config libssh-gcrypt-dev libgnutls28-dev \
        libglib2.0-dev libjson-glib-dev libpcap-dev libgpgme-dev bison libksba-dev \
        libsnmp-dev libgcrypt20-dev redis-server libbsd-dev libcurl4-gnutls-dev \
        krb5-multidev cmake doxygen
    
    echo "[+] Setting up Redis for OpenVAS..."
    # Copy Redis config from template
    if [ -f "/etc/redis/redis-openvas.conf" ]; then
        echo "[*] Redis OpenVAS config already exists"
    else
        echo "[+] Creating Redis OpenVAS config..."
        cp ./openvas-scanner-23.16.1/config/redis-openvas.conf /etc/redis/
        chown redis:redis /etc/redis/redis-openvas.conf
    fi
    
    # Ensure Redis socket directory exists
    mkdir -p /run/redis-openvas
    chown redis:redis /run/redis-openvas
    
    # Configure OpenVAS to use the Redis socket
    mkdir -p /etc/openvas
    echo "db_address = /run/redis-openvas/redis.sock" > /etc/openvas/openvas.conf
    
    # Start the Redis service for OpenVAS
    echo "[+] Starting Redis for OpenVAS..."
    systemctl start redis-server@openvas.service
    systemctl enable redis-server@openvas.service
    
    if ! systemctl is-active --quiet redis-server@openvas.service; then
        echo "[!] Warning: Redis service for OpenVAS failed to start"
        echo "    Starting in standard mode instead..."
        systemctl start redis-server
        systemctl enable redis-server
    fi

    # Building and installing OpenVAS from source if not already installed
    if command -v openvas >/dev/null 2>&1; then
        echo "[+] OpenVAS is already installed"
    else
        echo "[+] Building OpenVAS from source..."
        cd openvas-scanner-23.16.1
        mkdir -p build
        cd build
        cmake ..
        make
        make install
        cd ../..
    fi
    
    # Configure logging for OpenVAS
    mkdir -p /var/log/gvm
    echo "[+] Configuring OpenVAS logging..."
    cat > /etc/openvas/openvas_log.conf << EOF
[sd   main]
prepend=%t %p
prepend_time_format=%Y-%m-%d %Hh%M.%S %Z
file=/var/log/gvm/openvas.log
level=128
EOF

    # Sync NVT Feed using greenbone-feed-sync
    echo "[+] Syncing NVT feed with greenbone-feed-sync..."
    if command -v greenbone-feed-sync >/dev/null 2>&1; then
        greenbone-feed-sync --type nvt
    else
        echo "[!] Warning: greenbone-feed-sync not found"
        echo "    Please run 'pip install greenbone-feed-sync' to install it"
        echo "    Then run 'greenbone-feed-sync --type nvt' to sync the NVT feed"
    fi

    # Upload NVTs to Redis for OpenVAS to use
    echo "[+] Uploading NVTs to Redis..."
    if command -v openvas >/dev/null 2>&1; then
        openvas -u
    else
        echo "[!] Warning: openvas command not found"
    fi
    
    # Start and enable OpenVAS services
    echo "[+] Starting OpenVAS services..."
    if command -v ospd-openvas >/dev/null 2>&1; then
        systemctl start ospd-openvas
        systemctl enable ospd-openvas
    else
        echo "[!] Warning: ospd-openvas service not found"
    fi
    
    if command -v gvmd >/dev/null 2>&1; then
        systemctl start gvmd
        systemctl enable gvmd
    else
        echo "[!] Warning: gvmd service not found"
    fi
    
    # Get OpenVAS password
    echo "[+] Retrieving OpenVAS admin password..."
    if [ -z "$GVM_PASSWORD" ]; then
        # Try to get password from logs one more time
        if [ -f "/var/log/gvm/gvm-setup.log" ]; then
            PASSWORD_FROM_LOG=$(grep "User created with password" /var/log/gvm/gvm-setup.log | awk -F"'" '{print $2}')
            if [ ! -z "$PASSWORD_FROM_LOG" ]; then
                GVM_PASSWORD="$PASSWORD_FROM_LOG"
                echo "[+] Found OpenVAS password in logs: $GVM_PASSWORD"
            else
                GVM_PASSWORD="admin"
                echo "[!] Warning: Unable to find OpenVAS password in logs, using default: admin"
            fi
        else
            GVM_PASSWORD="admin"
            echo "[!] Warning: Unable to find OpenVAS password in logs, using default: admin"
        fi
    else
        echo "[+] Found OpenVAS password: $GVM_PASSWORD"
    fi
    
    # Export password to environment and bash config
    echo "export GVM_USERNAME=admin" >> ~/.bashrc
    echo "export GVM_PASSWORD='$GVM_PASSWORD'" >> ~/.bashrc
    export GVM_USERNAME=admin
    export GVM_PASSWORD="$GVM_PASSWORD"
    
    # Configure socket permissions - check for Kali Linux vs Ubuntu/Debian user names
    if [ -e "/run/ospd/ospd.sock" ]; then
        echo "[+] Setting permissions for /run/ospd/ospd.sock"
        chmod 660 /run/ospd/ospd.sock
        
        # Check if _gvm user exists (Kali) or gvm (Ubuntu/Debian)
        if id -u _gvm >/dev/null 2>&1; then
            chown _gvm:_gvm /run/ospd/ospd.sock
            echo "[+] Using _gvm:_gvm user/group (Kali Linux)"
        else
            chown gvm:gvm /run/ospd/ospd.sock
            echo "[+] Using gvm:gvm user/group (Ubuntu/Debian)"
        fi
    fi
    
    # Add user to sudoers for ospd-openvas - determine correct username
    echo "[+] Adding sudoers entry for ospd-openvas..."
    if id -u _gvm >/dev/null 2>&1; then
        # Kali Linux uses _gvm
        cat > /etc/sudoers.d/openvas << EOF
# Allow ospd-openvas to run openvas with root permissions
_gvm ALL = NOPASSWD: /usr/local/sbin/openvas
EOF
    else
        # Ubuntu/Debian uses gvm
        cat > /etc/sudoers.d/openvas << EOF
# Allow ospd-openvas to run openvas with root permissions
gvm ALL = NOPASSWD: /usr/local/sbin/openvas
EOF
    fi
    chmod 440 /etc/sudoers.d/openvas
    
    echo "[+] OpenVAS setup completed successfully!"
    echo "    Username: admin"
    echo "    Password: $GVM_PASSWORD"
fi 