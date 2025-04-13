#!/bin/bash

# AI_MAL Installation Script
# This script installs the AI_MAL tool and makes it available as a system command

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'
UNDERLINE='\033[4m'

# Get terminal width
TERM_WIDTH=$(stty size 2>/dev/null | awk '{print $2}' || echo 80)
[ -z "$TERM_WIDTH" ] && TERM_WIDTH=80

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_status() {
    echo -e "${CYAN}[STATUS]${NC} $1"
}

# Section display function
section() {
    local section_title="$1"
    local title_length=${#section_title}
    local padding=$(( (TERM_WIDTH - title_length - 4) / 2 ))
    local padding_left=$padding
    local padding_right=$padding
    
    # Adjust if odd length
    if (( (title_length + 4 + padding * 2) != TERM_WIDTH )); then
        padding_right=$((padding + 1))
    fi
    
    echo
    echo -e "${MAGENTA}$(printf '═%.0s' $(seq 1 $TERM_WIDTH))${NC}"
    echo -e "${MAGENTA}$(printf '═%.0s' $(seq 1 $padding_left))${WHITE} ${BOLD}${section_title}${NC} ${MAGENTA}$(printf '═%.0s' $(seq 1 $padding_right))${NC}"
    echo -e "${MAGENTA}$(printf '═%.0s' $(seq 1 $TERM_WIDTH))${NC}"
    echo
}

# Function to draw a box around text
draw_box() {
    local title="$1"
    local content="$2"
    local width=$((TERM_WIDTH - 4))
    local title_length=${#title}
    
    # Calculate padding for title
    local title_padding=$(( (width - title_length) / 2 ))
    local title_padding_left=$title_padding
    local title_padding_right=$title_padding
    
    # Adjust if odd length
    if (( (title_length + title_padding * 2) != width )); then
        title_padding_right=$((title_padding + 1))
    fi
    
    echo
    echo -e "${CYAN}╔$(printf '═%.0s' $(seq 1 $width))╗${NC}"
    echo -e "${CYAN}║${YELLOW}$(printf ' %.0s' $(seq 1 $title_padding_left))${BOLD}${title}${NC}${YELLOW}$(printf ' %.0s' $(seq 1 $title_padding_right))${CYAN}║${NC}"
    echo -e "${CYAN}╠$(printf '═%.0s' $(seq 1 $width))╣${NC}"
    
    # Process each line of content
    IFS=$'\n'
    for line in $content; do
        local line_length=${#line}
        local line_padding=$(( width - line_length ))
        echo -e "${CYAN}║${WHITE} ${line}${NC}$(printf ' %.0s' $(seq 1 $line_padding))${CYAN}║${NC}"
    done
    
    echo -e "${CYAN}╚$(printf '═%.0s' $(seq 1 $width))╝${NC}"
    echo
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
            # Capture the full output to search for password
            gvm-setup > /tmp/gvm-setup.log 2>&1 || echo "[!] Warning: gvm-setup returned non-zero exit code"
            
            # Immediately check for password in the setup output
            if grep -q "Password:" /tmp/gvm-setup.log; then
                GVM_PASSWORD=$(grep "Password:" /tmp/gvm-setup.log | tail -1 | awk '{print $NF}' | tr -d '\r\n')
                if [ -n "$GVM_PASSWORD" ]; then
                    echo "[+] Found OpenVAS password in setup log: $GVM_PASSWORD"
                fi
            fi
        else
            echo "[+] OpenVAS already set up, checking status..."
            gvm-check-setup > /tmp/gvm-check.log 2>&1
        fi
        
        # If password not set yet, try our comprehensive extraction function
        if [ -z "$GVM_PASSWORD" ]; then
            # Use the extraction function to find the password in various logs
            GVM_PASSWORD=$(get_openvas_password)
        fi
        
        # At this point, GVM_PASSWORD should contain the password or "admin" as fallback
        if [ "$GVM_PASSWORD" = "admin" ]; then
            echo "[!] Warning: Could not find the generated password, using default 'admin'"
            echo "[!] This may not work if OpenVAS generated a random password"
        else
            echo "[+] Using OpenVAS admin password: $GVM_PASSWORD"
        fi
        
        # Save the password to environment and bashrc for persistence
        export GVM_PASSWORD
        if ! grep -q "GVM_PASSWORD=" ~/.bashrc || ! grep -q "$GVM_PASSWORD" ~/.bashrc; then
            # Remove any existing GVM_PASSWORD lines to avoid duplication
            sed -i '/GVM_PASSWORD=/d' ~/.bashrc
            # Add the new password to bashrc
            echo "export GVM_PASSWORD=\"$GVM_PASSWORD\"" >> ~/.bashrc
            # Also add to /etc/environment for system-wide persistence
            if ! grep -q "GVM_PASSWORD=" /etc/environment; then
                echo "GVM_PASSWORD=\"$GVM_PASSWORD\"" >> /etc/environment
            else
                sed -i "s/GVM_PASSWORD=.*/GVM_PASSWORD=\"$GVM_PASSWORD\"/" /etc/environment
            fi
            echo "[+] Password saved to environment variables and ~/.bashrc"
        fi
        
        # Set socket permissions
        check_openvas_socket
        
        # Start services
        echo "[+] Starting OpenVAS services..."
        systemctl restart ospd-openvas
        systemctl restart gvmd
        
        echo "[+] OpenVAS setup completed successfully."
        echo "[+] Username: admin"
        echo "[+] Password: $GVM_PASSWORD"
        
        # Confirm the password is correct
        confirm_gvm_password
    fi
else
    log_status "OpenVAS/Greenbone Vulnerability Manager is already installed"
fi

# Verify the OpenVAS setup is complete
log_status "Verifying OpenVAS configuration..."
# Only run if we don't have a password yet (first install)
if [ -z "$GVM_PASSWORD" ]; then
    # Extract password using our comprehensive function
    GVM_PASSWORD=$(get_openvas_password)
    log_info "Extracted OpenVAS admin password: $GVM_PASSWORD"
    
    # Save to environment for this session and future ones
    export GVM_PASSWORD
    if ! grep -q "GVM_PASSWORD=" ~/.bashrc || ! grep -q "$GVM_PASSWORD" ~/.bashrc; then
        # Clean up existing entries to avoid duplicates
        sed -i '/GVM_PASSWORD=/d' ~/.bashrc
        echo "export GVM_USERNAME=admin" >> ~/.bashrc
        echo "export GVM_PASSWORD=\"$GVM_PASSWORD\"" >> ~/.bashrc
        log_info "Saved OpenVAS credentials to .bashrc"
    fi
else
    log_info "Using existing OpenVAS password: $GVM_PASSWORD"
fi

# Confirm the password with user
confirm_gvm_password

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
echo "[+] Setting up Ollama for AI features..."
if command -v ollama >/dev/null 2>&1; then
    echo "[+] Ollama is already installed"
else
    echo "[+] Installing Ollama..."
    # Use the official install script
    if curl -fsSL https://ollama.com/install.sh | sh; then
        echo "[+] Ollama installation successful"
    else
        echo "[!] Error: Ollama installation failed"
        echo "[!] You'll need to manually install Ollama to use AI features:"
        echo "    curl -fsSL https://ollama.com/install.sh | sh"
        OLLAMA_INSTALLED=false
    fi
fi

# Only try to start and pull models if Ollama was successfully installed
if command -v ollama >/dev/null 2>&1; then
    echo "[+] Starting Ollama service..."
    # Try to start Ollama service
    nohup ollama serve > /tmp/ollama.log 2>&1 &
    
    # Wait for service to start (max 30 seconds)
    echo "[+] Waiting for Ollama service to initialize..."
    for i in {1..30}; do
        if curl -s localhost:11434/api/tags >/dev/null 2>&1; then
            OLLAMA_RUNNING=true
            echo "[+] Ollama service started successfully"
            break
        fi
        sleep 1
        echo "[*] Waiting for Ollama service to start (attempt $i/30)..."
    done
    
    # Only try to pull models if service is running
    if [ "$OLLAMA_RUNNING" = true ]; then
        echo "[+] Downloading artifish/llama3.2-uncensored model (this may take a while)..."
        ollama pull artifish/llama3.2-uncensored > /dev/null 2>&1 &
        echo "[+] Model download started in background"
        
        # Ask if user wants to download additional models
        echo "[?] Do you want to download the backup AI model qwen2.5-coder:7b (will use ~3GB) (y/n)"
        read -r response
        if [[ "$response" == "y" ]]; then
            echo "[+] Downloading additional AI model in background..."
            ollama pull qwen2.5-coder:7b > /dev/null 2>&1 &
        fi
    else
        echo "[!] Warning: Could not start Ollama service. AI features may not work."
        echo "[!] To use AI features, you'll need to manually start Ollama:"
        echo "    sudo ollama serve"
        echo "    ollama pull artifish/llama3.2-uncensored"
    fi
else
    echo "[!] Ollama is not installed. AI features will not be available."
    echo "[!] To install Ollama, run: curl -fsSL https://ollama.com/install.sh | sh"
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
section "IMPORTANT: OLLAMA SERVICE STATUS"

if [ "$OLLAMA_RUNNING" = true ]; then
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
    if command -v gvm-cli &> /dev/null; then
        echo "[+] OpenVAS/GVM is installed"
        return 0
    else
        echo "[!] OpenVAS/GVM is not installed"
        return 1
    fi
}

# Function to confirm OpenVAS password with user
confirm_gvm_password() {
    section "CONFIRM OPENVAS PASSWORD"
    
    if [ -z "$GVM_PASSWORD" ]; then
        log_warning "No OpenVAS password found. Using default 'admin'."
        GVM_PASSWORD="admin"
    fi
    
    # Show current password to user for confirmation
    draw_box "OpenVAS Password" "Current OpenVAS admin password: $GVM_PASSWORD\n\nIs this the correct password? (y/n)"
    read -r is_correct
    
    if [[ "$is_correct" != "y" && "$is_correct" != "Y" ]]; then
        log_info "Please enter the correct OpenVAS admin password:"
        read -r -s new_password
        echo
        
        # Confirm password
        log_info "Please confirm the password by entering it again:"
        read -r -s confirm_password
        echo
        
        if [[ "$new_password" == "$confirm_password" ]]; then
            GVM_PASSWORD="$new_password"
            export GVM_PASSWORD
            save_credentials
            log_success "Password successfully updated and saved."
        else
            log_error "Passwords do not match. Please try again."
            # Recursive call to try again
            confirm_gvm_password
            return
        fi
    else
        log_success "Using confirmed password: $GVM_PASSWORD"
    fi
    
    # Test connection with confirmed password
    log_info "Testing connection with confirmed password..."
    # First find a suitable socket
    SOCKET_PATH=""
    for path in "/var/run/gvmd/gvmd.sock" "/run/gvmd/gvmd.sock" "/var/run/gvmd.sock" "/run/gvmd.sock"; do
        if [ -S "$path" ]; then
            SOCKET_PATH="$path"
            break
        fi
    done
    
    if [ -n "$SOCKET_PATH" ]; then
        if gvm-cli socket --socketpath="$SOCKET_PATH" --gmp-username=admin --gmp-password="$GVM_PASSWORD" --xml "<get_version/>" &> /dev/null; then
            log_success "Successfully connected with confirmed password!"
        else
            log_warning "Could not connect with confirmed password. You may need to verify it again later."
        fi
    else
        log_warning "Could not find GVM socket to test password. Connection test skipped."
    fi
    
    return 0
}

# Function to extract and save OpenVAS admin password
get_openvas_password() {
    section "RETRIEVING OPENVAS PASSWORD"
    
    # Check if we already have the password in environment
    if [ -n "$GVM_PASSWORD" ]; then
        log_success "Using OpenVAS password from environment: $GVM_PASSWORD"
        validate_openvas_password "$GVM_PASSWORD"
        return 0
    fi
    
    # Ensure directory exists with proper permissions
    mkdir -p ~/.config/ai_mal
    chmod 700 ~/.config/ai_mal
    
    # Define encryption key file
    KEY_FILE=~/.config/ai_mal/.key
    
    # Check if credentials file exists and source it
    if [ -f ~/.config/ai_mal/credentials.enc ] && [ -f "$KEY_FILE" ]; then
        # Decrypt credentials
        PASSWORD=$(openssl enc -aes-256-cbc -d -in ~/.config/ai_mal/credentials.enc -pass file:"$KEY_FILE" 2>/dev/null | grep GVM_PASSWORD | cut -d= -f2 | tr -d '"')
        
        if [ -n "$PASSWORD" ]; then
            GVM_PASSWORD="$PASSWORD"
            log_success "Retrieved OpenVAS password from encrypted credentials file"
            validate_openvas_password "$GVM_PASSWORD"
            return 0
        fi
    elif [ -f ~/.config/ai_mal/credentials ]; then
        # Legacy support for unencrypted credentials
        source ~/.config/ai_mal/credentials
        if [ -n "$GVM_PASSWORD" ]; then
            log_success "Retrieved OpenVAS password from credentials file"
            validate_openvas_password "$GVM_PASSWORD"
            # Upgrade to encrypted storage
            encrypt_credentials
            return 0
        fi
    fi
    
    log_info "Searching for OpenVAS password in log files..."
    
    # Method 1: Check log file for password
    if [ -f /var/log/gvm/gvm-setup.log ]; then
        PASSWORD=$(grep -a "User created with password" /var/log/gvm/gvm-setup.log | tail -1 | sed -e 's/.*password *//' -e 's/ *\.//')
        
        if [ -z "$PASSWORD" ]; then
            PASSWORD=$(grep -a "Password:" /var/log/gvm/gvm-setup.log | tail -1 | awk '{print $2}')
        fi
        
        if [ -n "$PASSWORD" ]; then
            log_success "Found OpenVAS password in logs: $PASSWORD"
            GVM_PASSWORD="$PASSWORD"
            export GVM_PASSWORD
            save_credentials
            validate_openvas_password "$GVM_PASSWORD"
            return 0
        fi
    else
        log_warning "Log file /var/log/gvm/gvm-setup.log not found"
    fi
    
    # Method 2: Try to use gvmd --get-users to find admin user and password
    if command -v gvmd &> /dev/null; then
        log_info "Attempting to retrieve password using gvmd command..."
        
        # This might work in some configurations, but not all
        ADMIN_INFO=$(sudo gvmd --get-users 2>/dev/null | grep admin)
        if [ -n "$ADMIN_INFO" ]; then
            # Extract password if present in the output
            PASSWORD=$(echo "$ADMIN_INFO" | grep -oP 'password=\K[^ ]+')
            if [ -n "$PASSWORD" ]; then
                log_success "Found OpenVAS admin password using gvmd: $PASSWORD"
                GVM_PASSWORD="$PASSWORD"
                export GVM_PASSWORD
                save_credentials
                validate_openvas_password "$GVM_PASSWORD"
                return 0
            fi
        fi
    fi
    
    # Method 3: Try to read from a potential password file
    for PASSWORD_FILE in /var/lib/gvm/admin-password /usr/local/var/lib/gvm/admin-password; do
        if [ -f "$PASSWORD_FILE" ]; then
            PASSWORD=$(cat "$PASSWORD_FILE")
            if [ -n "$PASSWORD" ]; then
                log_success "Found OpenVAS password in $PASSWORD_FILE: $PASSWORD"
                GVM_PASSWORD="$PASSWORD"
                export GVM_PASSWORD
                save_credentials
                validate_openvas_password "$GVM_PASSWORD"
                return 0
            fi
        fi
    done
    
    # Method 4: Try to retrieve from gvmd.log
    if [ -f /var/log/gvm/gvmd.log ]; then
        PASSWORD=$(grep -a "password" /var/log/gvm/gvmd.log | grep -v "hash" | grep -oP '(?<=password ")[^"]+' | tail -1)
        if [ -n "$PASSWORD" ]; then
            log_success "Found OpenVAS password in gvmd.log: $PASSWORD"
            GVM_PASSWORD="$PASSWORD"
            export GVM_PASSWORD
            save_credentials
            validate_openvas_password "$GVM_PASSWORD"
            return 0
        fi
    fi
    
    # Default to "admin" if no password found
    log_warning "Could not find OpenVAS password, defaulting to 'admin'"
    GVM_PASSWORD="admin"
    export GVM_PASSWORD
    save_credentials
    
    draw_box "OpenVAS Password" "Using default password: 'admin'\nIf this doesn't work, please set the correct password manually:\n\nexport GVM_PASSWORD='your_password'"
    
    return 0
}

# Function to encrypt credentials
encrypt_credentials() {
    if [ ! -f ~/.config/ai_mal/credentials.enc ]; then
        log_info "Upgrading to encrypted credential storage..."
        
        # Generate a strong random encryption key if it doesn't exist
        if [ ! -f "$KEY_FILE" ]; then
            openssl rand -base64 32 > "$KEY_FILE"
            chmod 600 "$KEY_FILE"
        fi
        
        # Encrypt credentials
        if [ -f ~/.config/ai_mal/credentials ]; then
            openssl enc -aes-256-cbc -salt -in ~/.config/ai_mal/credentials -out ~/.config/ai_mal/credentials.enc -pass file:"$KEY_FILE" 2>/dev/null
            if [ $? -eq 0 ]; then
                chmod 600 ~/.config/ai_mal/credentials.enc
                log_success "Credentials encrypted successfully"
                # Keep original as backup but restrict access
                chmod 600 ~/.config/ai_mal/credentials
                mv ~/.config/ai_mal/credentials ~/.config/ai_mal/credentials.bak
            else
                log_error "Failed to encrypt credentials"
            fi
        fi
    fi
}

# Function to validate OpenVAS password
validate_openvas_password() {
    local password=$1
    
    # Password should not be empty or just whitespace
    if [ -z "$password" ] || [ "$password" = "$(echo "$password" | tr -d '[:space:]')" ]; then
        log_warning "OpenVAS password validation: Password seems unusually short or empty"
        return 1
    fi
    
    # Check if password meets minimum complexity requirements (optional check)
    if [ ${#password} -lt 8 ]; then
        log_warning "OpenVAS password validation: Password is less than 8 characters"
    fi
    
    return 0
}

# Helper function to save credentials
save_credentials() {
    # Save to credentials file
    mkdir -p ~/.config/ai_mal
    chmod 700 ~/.config/ai_mal
    
    # Create credentials file with proper permissions
    echo "GVM_USERNAME=admin" > ~/.config/ai_mal/credentials
    echo "GVM_PASSWORD=\"$GVM_PASSWORD\"" >> ~/.config/ai_mal/credentials
    chmod 600 ~/.config/ai_mal/credentials
    log_success "Saved credentials to ~/.config/ai_mal/credentials"
    
    # Encrypt the credentials
    encrypt_credentials
    
    # Add to current session
    export GVM_USERNAME=admin
    export GVM_PASSWORD
    
    # Add to .bashrc if it doesn't contain GVM_PASSWORD already
    if ! grep -q "export GVM_PASSWORD" ~/.bashrc 2>/dev/null; then
        echo "# AI_MAL: OpenVAS credentials" >> ~/.bashrc
        echo "export GVM_USERNAME=admin" >> ~/.bashrc
        echo "export GVM_PASSWORD=\"$GVM_PASSWORD\"" >> ~/.bashrc
        log_success "Added credentials to ~/.bashrc for future sessions"
    fi
    
    # Try to add to system-wide environment if we have sudo access
    if command -v sudo &> /dev/null && sudo -n true 2>/dev/null; then
        if ! sudo grep -q "GVM_PASSWORD" /etc/environment 2>/dev/null; then
            sudo sh -c "echo 'GVM_USERNAME=admin' >> /etc/environment"
            sudo sh -c "echo 'GVM_PASSWORD=\"$GVM_PASSWORD\"' >> /etc/environment"
            log_success "Added credentials to system-wide environment"
        fi
    fi
    
    draw_box "OpenVAS Credentials" "Username: admin\nPassword: $GVM_PASSWORD\n\nCredentials have been securely saved for future use."
}

# Function to check OpenVAS socket
check_openvas_socket() {
    # Check for common socket locations
    if [ -S "/var/run/ospd/ospd.sock" ]; then
        echo "/var/run/ospd/ospd.sock"
        return 0
    elif [ -S "/var/run/ospd.sock" ]; then
        echo "/var/run/ospd.sock"
        return 0
    else
        # Try to extract from service configuration
        socket_path=$(systemctl show ospd-openvas --property=ExecStart | grep -o -- "--socket-path=.*" | cut -d' ' -f1 | cut -d'=' -f2)
        if [ -n "$socket_path" ] && [ -S "$socket_path" ]; then
            echo "$socket_path"
            return 0
        fi
    fi

    # If nothing found, return default path
    echo "/var/run/ospd/ospd.sock"
    return 1
}

# Test OpenVAS connection
test_openvas_connection() {
    section "TESTING OPENVAS CONNECTION"
    
    # Check if gvm-cli is available
    if ! command -v gvm-cli &> /dev/null; then
        log_error "gvm-cli not found. OpenVAS may not be properly installed."
        draw_box "Missing Component" "You need to install the GVM command line interface.\nTry: sudo apt install gvm-tools"
        return 1
    fi
    
    log_info "Attempting to connect to OpenVAS/GVM..."
    
    # Source credentials from our encrypted storage if available
    if [ -f ~/.config/ai_mal/credentials.enc ] && [ -f ~/.config/ai_mal/.key ]; then
        log_info "Using encrypted credentials from ~/.config/ai_mal/credentials.enc"
        PASSWORD=$(openssl enc -aes-256-cbc -d -in ~/.config/ai_mal/credentials.enc -pass file:~/.config/ai_mal/.key 2>/dev/null | grep GVM_PASSWORD | cut -d= -f2 | tr -d '"')
        if [ -n "$PASSWORD" ]; then
            GVM_PASSWORD="$PASSWORD"
            export GVM_PASSWORD
        fi
    # Legacy support for unencrypted credentials
    elif [ -f ~/.config/ai_mal/credentials ]; then
        source ~/.config/ai_mal/credentials
        log_info "Using credentials from ~/.config/ai_mal/credentials"
    fi
    
    # Comprehensive test for socket path with priority order
    log_info "Searching for GVM socket..."
    SOCKET_PATH=""
    
    # Priority 1: Check the most common locations by distribution
    for path in "/var/run/gvmd/gvmd.sock" "/run/gvmd/gvmd.sock" "/var/run/gvmd.sock" "/run/gvmd.sock"; do
        if [ -S "$path" ]; then
            SOCKET_PATH="$path"
            log_success "Found GVM socket at: $SOCKET_PATH"
            break
        fi
    done
    
    # Priority 2: Check system service files if not found yet
    if [ -z "$SOCKET_PATH" ]; then
        log_info "Checking service configuration for socket path..."
        # Check gvmd service file
        GVMD_SOCK=$(systemctl show gvmd --property=ExecStart 2>/dev/null | grep -o -- "--listen=.*/.*\.sock" | cut -d'=' -f2)
        if [ -n "$GVMD_SOCK" ] && [ -S "$GVMD_SOCK" ]; then
            SOCKET_PATH="$GVMD_SOCK"
            log_success "Found GVM socket from service configuration: $SOCKET_PATH"
        fi
    fi
    
    # Priority 3: Last resort - search the filesystem
    if [ -z "$SOCKET_PATH" ]; then
        log_info "Searching filesystem for GVM socket..."
        FOUND_SOCK=$(find /var/run /run -name "gvmd*.sock" -type s 2>/dev/null | head -1)
        if [ -n "$FOUND_SOCK" ]; then
            SOCKET_PATH="$FOUND_SOCK"
            log_success "Found GVM socket by filesystem search: $SOCKET_PATH"
        fi
    fi
    
    if [ -z "$SOCKET_PATH" ]; then
        log_error "GVM socket not found. OpenVAS services may not be running."
        log_info "Attempting to start OpenVAS services..."
        
        # Try to start the services
        for service in ospd-openvas gvmd; do
            if systemctl is-active $service >/dev/null 2>&1; then
                log_info "$service is already running"
            else
                log_info "Starting $service..."
                systemctl start $service
                sleep 2
                if systemctl is-active $service >/dev/null 2>&1; then
                    log_success "Successfully started $service"
                else
                    log_error "Failed to start $service"
                fi
            fi
        done
        
        # Check again after trying to start services
        sleep 5
        for path in "/var/run/gvmd/gvmd.sock" "/run/gvmd/gvmd.sock" "/var/run/gvmd.sock" "/run/gvmd.sock"; do
            if [ -S "$path" ]; then
                SOCKET_PATH="$path"
                log_success "Found GVM socket after service restart: $SOCKET_PATH"
                break
            fi
        done
        
        if [ -z "$SOCKET_PATH" ]; then
            log_error "Still could not find GVM socket. Check OpenVAS installation."
            draw_box "OpenVAS Connection Failed" "GVM socket not found after service restart.\n\nService Status:\nospd-openvas: $OSPD_STATUS\ngvmd: $GVMD_STATUS\n\nDetected socket: $SOCKET_PATH\n\nNext steps:\n1. Run 'sudo gvm-check-setup' for diagnostics\n2. Run 'sudo gvm-setup' if first-time setup\n3. Check logs with 'journalctl -u gvmd -u ospd-openvas'"
            return 1
        fi
    fi
    
    # Test connection using stored password
    if [ -n "$GVM_PASSWORD" ]; then
        log_status "Attempting connection with stored credentials..."
        CONNECTION_OUTPUT=$(gvm-cli socket --socketpath="$SOCKET_PATH" --gmp-username=admin --gmp-password="$GVM_PASSWORD" --xml "<get_version/>" 2>&1)
        if [ $? -eq 0 ]; then
            log_success "Successfully connected to OpenVAS/GVM using stored credentials"
            VERSION=$(echo "$CONNECTION_OUTPUT" | grep -oP '(?<=<version>)[^<]+' | head -1)
            if [ -n "$VERSION" ]; then
                log_info "OpenVAS/GVM version: $VERSION"
            fi
            return 0
        else
            log_warning "Could not connect using stored credentials. Trying alternative methods..."
            CONNECTION_ERROR=$(echo "$CONNECTION_OUTPUT" | grep -i "error" | head -1)
            if [ -n "$CONNECTION_ERROR" ]; then
                log_warning "Connection error: $CONNECTION_ERROR"
            fi
        fi
    fi
    
    # Try with default admin password
    log_status "Attempting connection with default 'admin' password..."
    CONNECTION_OUTPUT=$(gvm-cli socket --socketpath="$SOCKET_PATH" --gmp-username=admin --gmp-password="admin" --xml "<get_version/>" 2>&1)
    if [ $? -eq 0 ]; then
        log_success "Successfully connected to OpenVAS/GVM using default 'admin' password"
        VERSION=$(echo "$CONNECTION_OUTPUT" | grep -oP '(?<=<version>)[^<]+' | head -1)
        if [ -n "$VERSION" ]; then
            log_info "OpenVAS/GVM version: $VERSION"
        fi
        
        # Update stored credentials
        GVM_PASSWORD="admin"
        export GVM_PASSWORD
        save_credentials
        return 0
    fi
    
    # Try without password (some installations)
    log_status "Attempting connection without password..."
    CONNECTION_OUTPUT=$(gvm-cli socket --socketpath="$SOCKET_PATH" --gmp-username=admin --xml "<get_version/>" 2>&1)
    if [ $? -eq 0 ]; then
        log_success "Successfully connected to OpenVAS/GVM without password"
        VERSION=$(echo "$CONNECTION_OUTPUT" | grep -oP '(?<=<version>)[^<]+' | head -1)
        if [ -n "$VERSION" ]; then
            log_info "OpenVAS/GVM version: $VERSION"
        fi
        return 0
    fi
    
    # Final attempt: run the get_openvas_password function to extract and try again
    log_info "Attempting to retrieve password from system..."
    get_openvas_password
    
    if [ -n "$GVM_PASSWORD" ]; then
        log_status "Attempting connection with newly retrieved password..."
        CONNECTION_OUTPUT=$(gvm-cli socket --socketpath="$SOCKET_PATH" --gmp-username=admin --gmp-password="$GVM_PASSWORD" --xml "<get_version/>" 2>&1)
        if [ $? -eq 0 ]; then
            log_success "Successfully connected to OpenVAS/GVM with newly retrieved password"
            VERSION=$(echo "$CONNECTION_OUTPUT" | grep -oP '(?<=<version>)[^<]+' | head -1)
            if [ -n "$VERSION" ]; then
                log_info "OpenVAS/GVM version: $VERSION"
            fi
            return 0
        else
            CONNECTION_ERROR=$(echo "$CONNECTION_OUTPUT" | grep -i "error" | head -1)
            if [ -n "$CONNECTION_ERROR" ]; then
                log_warning "Connection error with new password: $CONNECTION_ERROR"
            fi
        fi
    fi
    
    # If we get here, all attempts failed
    log_error "Failed to connect to OpenVAS/GVM after multiple attempts."
    log_error "Try running 'sudo gvm-check-setup' to diagnose issues."
    log_error "You may need to initialize OpenVAS with 'sudo gvm-setup'."
    
    # Determine and report active services
    OSPD_STATUS=$(systemctl is-active ospd-openvas)
    GVMD_STATUS=$(systemctl is-active gvmd)
    
    draw_box "OpenVAS Connection Failed" "Please ensure OpenVAS is properly installed and running.\n\nService Status:\nospd-openvas: $OSPD_STATUS\ngvmd: $GVMD_STATUS\n\nDetected socket: $SOCKET_PATH\n\nNext steps:\n1. Run 'sudo gvm-check-setup' for diagnostics\n2. Run 'sudo gvm-setup' if first-time setup\n3. Check logs with 'journalctl -u gvmd -u ospd-openvas'"
    return 1
}

# Function to check if Metasploit is installed
check_msf_installed() {
    if command -v msfconsole &> /dev/null; then
        echo "[+] Metasploit Framework is installed"
        return 0
    else
        echo "[!] Metasploit Framework is not installed"
        return 1
    fi
}

# OpenVAS / Greenbone Vulnerability Management setup
if [ "$INSTALL_OPENVAS" = true ] || [ -z "$INSTALL_OPENVAS" ]; then
    section "Installing OpenVAS Scanner"
    
    # Install all prerequisites from INSTALL.md
    echo "[+] Installing OpenVAS prerequisites..."
    apt-get update
    apt-get install -y gcc pkg-config libssh-gcrypt-dev libgnutls28-dev \
        libglib2.0-dev libjson-glib-dev libpcap-dev libgpgme-dev bison libksba-dev \
        libsnmp-dev libgcrypt20-dev redis-server libbsd-dev libcurl4-gnutls-dev \
        krb5-multidev cmake doxygen
    
    # Enhance Redis setup for OpenVAS
    echo "[+] Setting up Redis for OpenVAS..."
    # Create Redis configuration for OpenVAS if it doesn't exist
    if [ -f "/etc/redis/redis-openvas.conf" ]; then
        echo "[*] Redis OpenVAS config already exists"
    else
        echo "[+] Creating Redis OpenVAS config..."
        cat > /etc/redis/redis-openvas.conf << EOF
unixsocket /run/redis-openvas/redis.sock
unixsocketperm 770
port 0
timeout 0
databases 128
EOF
        chown redis:redis /etc/redis/redis-openvas.conf
    fi

    # Ensure Redis socket directory exists with proper permissions
    mkdir -p /run/redis-openvas
    chown redis:redis /run/redis-openvas

    # Set the correct group based on OS detection
    if id -u _gvm >/dev/null 2>&1; then
        # Kali Linux uses _gvm
        usermod -a -G redis _gvm
    else
        # Ubuntu/Debian uses gvm
        usermod -a -G redis gvm
    fi

    # Configure OpenVAS to use the Redis socket
    mkdir -p /etc/openvas
    echo "db_address = /run/redis-openvas/redis.sock" > /etc/openvas/openvas.conf

    # Stop any running Redis instances
    systemctl stop redis-server 2>/dev/null || true
    systemctl stop redis-server@openvas 2>/dev/null || true

    # Start Redis with the OpenVAS configuration
    echo "[+] Starting Redis for OpenVAS..."
    systemctl start redis-server@openvas.service
    systemctl enable redis-server@openvas.service

    # Verify Redis is running with the correct socket
    if [ -S "/run/redis-openvas/redis.sock" ]; then
        echo "[+] Redis socket created successfully"
    else
        echo "[!] Redis socket not created, trying alternative configuration..."
        # Start Redis in standard mode as fallback
        systemctl start redis-server
        systemctl enable redis-server
        
        # Check if we need to modify the main Redis config
        if ! grep -q "unixsocket /run/redis-openvas/redis.sock" /etc/redis/redis.conf; then
            echo "[+] Updating main Redis config to support OpenVAS..."
            cp /etc/redis/redis.conf /etc/redis/redis.conf.bak
            cat >> /etc/redis/redis.conf << EOF

# OpenVAS configuration
unixsocket /run/redis-openvas/redis.sock
unixsocketperm 770
EOF
            systemctl restart redis-server
        fi
    fi

    # Wait a moment for socket creation
    sleep 5

    # Final check for Redis socket
    if [ -S "/run/redis-openvas/redis.sock" ]; then
        echo "[+] Redis configured successfully for OpenVAS"
    else
        echo "[!] Warning: Redis socket for OpenVAS not found. Scanning may not work properly."
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
    
    # Also add to /etc/environment for system-wide persistence
    if ! grep -q "GVM_USERNAME=" /etc/environment; then
        echo "GVM_USERNAME=admin" >> /etc/environment
    else
        sed -i "s/GVM_USERNAME=.*/GVM_USERNAME=admin/" /etc/environment
    fi

    if ! grep -q "GVM_PASSWORD=" /etc/environment; then
        echo "GVM_PASSWORD=\"$GVM_PASSWORD\"" >> /etc/environment
    else
        sed -i "s/GVM_PASSWORD=.*/GVM_PASSWORD=\"$GVM_PASSWORD\"/" /etc/environment
    fi

    echo "[+] OpenVAS credentials saved system-wide"
    
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