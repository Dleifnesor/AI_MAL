#!/bin/bash

# AI_MAL Installation Script
# This script installs the AI_MAL tool and makes it available as a system command

echo "[+] AI_MAL - AI-Powered Penetration Testing Tool Installation"
echo "[+] This script will install AI_MAL and its dependencies"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root"
  exit 1
fi

# Check if running on Kali Linux
if ! grep -q 'Kali' /etc/os-release; then
  echo "[!] Warning: This tool is designed for Kali Linux"
  echo "[?] Do you want to continue anyway? (y/n)"
  read -r response
  if [[ "$response" != "y" ]]; then
    exit 1
  fi
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

# Convert all scripts to Unix format (fix line endings)
echo "[+] Converting scripts to Unix format (fixing line endings)..."
find . -type f -name "*.py" -exec dos2unix {} \;
find . -type f -name "*.sh" -exec dos2unix {} \;
find ./src -type f -exec dos2unix {} \; 2>/dev/null
dos2unix AI_MAL.py

# Install OpenVAS/Greenbone Vulnerability Manager - HIGH PRIORITY
echo "[+] Installing OpenVAS/Greenbone Vulnerability Manager (PRIMARY VULNERABILITY SCANNER)..."
apt-get install -y openvas gvm

# Run OpenVAS setup
echo "[+] Setting up OpenVAS (this may take a while)..."

# Run the GVM setup and start services
gvm-setup

# Wait for user confirmation after password generation
echo ""
echo "╔═════════════════════════════════════════════════════════════════════════╗"
echo "║                       !!! PASSWORD CONFIRMATION !!!                     ║"
echo "║                                                                         ║"
echo "║ Did you save the OpenVAS admin password displayed above?                ║"
echo "║ If not, please scroll up and find the line that says:                   ║"
echo "║ [*] User created with password 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'.  ║"
echo "║                           Username:admin                                ║"
echo "║                                                                         ║"
echo "║ Type 'y' to confirm you have saved the password, or 'n' to exit:        ║"
echo "╚═════════════════════════════════════════════════════════════════════════╝"
echo ""

while true; do
    read -r -p "[?] Have you saved the OpenVAS admin password? (y/n): " response
    case "$response" in
        [yY])
            break
            ;;
        [nN])
            echo "[!] Please save the OpenVAS admin password and run the installation again."
            exit 1
            ;;
        *)
            echo "[!] Please enter 'y' or 'n'."
            ;;
    esac
done

# Start OpenVAS services
gvm-start

echo "[+] OpenVAS installed and configured as the default vulnerability scanner"
echo "[+] Default OpenVAS credentials - username: admin, password: (the password you saved above)"

# Configure OpenVAS integration
echo "[+] Configuring OpenVAS integration with AI_MAL..."
mkdir -p scripts/openvas
cat > scripts/openvas/config.yml << EOF
# OpenVAS Configuration for AI_MAL
default: true
hostname: localhost
port: 9390
username: admin
scan_configs:
  full_and_fast: "daba56c8-73ec-11df-a475-002264764cea"
  full_and_fast_ultimate: "698f691e-7489-11df-9d8c-002264764cea"
  full_and_very_deep: "708f25c4-7489-11df-8094-002264764cea"
  empty: "085569ce-73ed-11df-83c3-002264764cea"
  discovery: "8715c877-47a0-438d-98a3-27c7a6ab2196"
  host_discovery: "2d3f051c-55ba-11e3-bf43-406186ea4fc5"
EOF

# Install Ollama for AI features if not present
if ! command -v ollama &> /dev/null; then
  echo "[+] Installing Ollama for AI features..."
  curl -fsSL https://ollama.com/install.sh | sh > /dev/null 2>&1
  
  # Make sure Ollama is running before continuing
  echo "[+] Starting Ollama service..."
  ollama serve &>/dev/null &
  
  # Wait for Ollama service to start
  echo "[+] Waiting for Ollama service to initialize..."
  sleep 10  # Initial wait
  
  # Check if Ollama is running
  if ! check_ollama_running; then
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                  IMPORTANT: OLLAMA SERVICE STATUS                             ║"
    echo "║                                                                               ║"
    echo "║ [!] Ollama service is not running!                                            ║"
    echo "║                                                                               ║"
    echo "║ To enable AI features, please run:                                            ║"
    echo "║     ollama serve                                                              ║"
    echo "║                                                                               ║"
    echo "║ Then in another terminal:                                                     ║"
    echo "║     ollama pull artifish/llama3.2-uncensored gemma3:1b                        ║"
    echo "║                                                                               ║"
    echo "║ Press Enter to continue with installation anyway...                            ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    read -r
  else
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                  IMPORTANT: OLLAMA SERVICE STATUS                             ║"
    echo "║                                                                               ║"
    echo "║ [+] Ollama service is running properly!                                       ║"
    echo "║                                                                               ║"
    echo "║ AI features will work automatically.                                          ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Pull default models
    echo "[+] Downloading artifish/llama3.2-uncensored (this may take a while)..."
    ollama pull artifish/llama3.2-uncensored > /dev/null 2>&1
    
    # Ask if user wants to download additional models
    echo "[?] Do you want to download the backup model qwen2.5-coder:7b (will take approx 3GB) (y/n)"
    read -r response
    if [[ "$response" == "y" ]]; then
      echo "[+] Downloading additional AI models..."
      ollama pull qwen2.5-coder:7b > /dev/null 2>&1
    fi
  fi
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