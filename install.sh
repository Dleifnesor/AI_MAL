#!/bin/bash
# Installation script for AI_MAL on Kali Linux
# This script installs dependencies and sets up the environment

# Exit on any error
set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Version
VERSION="1.0.0"

# Function to check if running with sudo
check_sudo() {
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${RED}This script needs to be run with sudo privileges${NC}"
        echo -e "    Please run: ${GREEN}sudo ./install.sh${NC}"
        exit 1
    fi
}

# Function to check if running on Kali Linux
check_kali() {
    if ! grep -qi "kali" /etc/os-release; then
        echo -e "${RED}This script is designed for Kali Linux only${NC}"
        exit 1
    fi
}

# Check for sudo privileges and Kali Linux
check_sudo
check_kali

# Determine the installation directory
INSTALL_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$INSTALL_DIR" || { echo "Could not change to install directory"; exit 1; }

# Print welcome message
echo "====================================================="
echo "       Installing AI_MAL - AI-Powered Penetration Testing Tool"
echo "====================================================="
echo

# Update system packages
echo -e "${YELLOW}[+] Updating system packages...${NC}"
apt-get update
apt-get upgrade -y

# Install core system dependencies
echo -e "${YELLOW}[+] Installing core system dependencies...${NC}"
apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    nmap \
    nmap-common \
    ndiff \
    ncat \
    libpcap-dev \
    postgresql \
    postgresql-contrib \
    libpq-dev \
    python3-psycopg2 \
    python3-samba \
    python3-ldap \
    python3-kerberos \
    python3-gssapi \
    python3-cryptography \
    python3-paramiko \
    python3-netifaces \
    python3-requests \
    python3-dateutil \
    python3-pymetasploit3 \
    python3-ollama \
    metasploit-framework \
    ca-certificates \
    gnupg \
    software-properties-common

# Create and activate virtual environment
echo -e "${YELLOW}[+] Setting up Python virtual environment...${NC}"
rm -rf venv  # Remove existing venv if any
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo -e "${YELLOW}[+] Installing Python dependencies...${NC}"
pip install --upgrade pip
pip install --no-cache-dir \
    python-nmap==0.7.1 \
    requests==2.31.0 \
    netifaces==0.11.0 \
    pymetasploit3==1.0.3 \
    smbclient==0.18.0 \
    paramiko==3.4.0 \
    wmi==1.5.1 \
    cryptography==42.0.2 \
    python-dateutil==2.8.2 \
    ipaddress==1.0.23 \
    ollama==0.1.6 \
    rich==13.7.0 \
    click==8.1.7 \
    ntlm-auth==1.5.0 \
    pywinrm==0.4.3

# Install Ollama
echo -e "${YELLOW}[+] Installing Ollama...${NC}"
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama service
echo -e "${YELLOW}[+] Starting Ollama service...${NC}"
systemctl enable ollama
systemctl start ollama

# Wait for Ollama to be ready
echo -e "${GREEN}[+] Waiting for Ollama to start...${NC}"
for i in {1..30}; do
    if curl -s http://localhost:11434/api/version > /dev/null; then
        echo -e "${GREEN}[+] Ollama is ready${NC}"
        break
    fi
    echo -n "."
    sleep 1
done

# Pull required Ollama models
echo -e "${YELLOW}[+] Pulling required Ollama models...${NC}"
ollama pull qwen2.5-coder:7b
ollama pull gemma3:1b

# Set up PostgreSQL
echo -e "${YELLOW}[+] Setting up PostgreSQL...${NC}"
systemctl start postgresql
systemctl enable postgresql

# Wait for PostgreSQL to start
echo -e "${GREEN}[+] Waiting for PostgreSQL to start...${NC}"
for i in {1..30}; do
    if pg_isready -q; then
        echo -e "${GREEN}[+] PostgreSQL is ready${NC}"
        break
    fi
    echo -n "."
    sleep 1
done

# Create database and user
echo -e "${YELLOW}[+] Creating database and user...${NC}"
sudo -u postgres psql -c "CREATE DATABASE ai_mal;" 2>/dev/null || true
sudo -u postgres psql -c "CREATE USER ai_mal WITH PASSWORD 'ai_mal';" 2>/dev/null || true
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ai_mal TO ai_mal;" 2>/dev/null || true

# Set up Metasploit
echo -e "${YELLOW}[+] Setting up Metasploit...${NC}"
msfdb init

# Set permissions
echo -e "${GREEN}[+] Setting permissions...${NC}"
chmod +x adaptive_nmap_scan.py

# Create wrapper script
echo -e "${YELLOW}[+] Creating wrapper script...${NC}"
cat > AI_MAL << 'EOL'
#!/bin/bash
source "$(dirname "$0")/venv/bin/activate"
python "$(dirname "$0")/adaptive_nmap_scan.py" "$@"
EOL
chmod +x AI_MAL

# Create symlink in /usr/local/bin
echo -e "${YELLOW}[+] Creating symlink in /usr/local/bin...${NC}"
ln -sf "$INSTALL_DIR/AI_MAL" /usr/local/bin/AI_MAL

# Verify Nmap installation
echo -e "${YELLOW}[+] Verifying Nmap installation...${NC}"
if ! command -v nmap &> /dev/null; then
    echo -e "${RED}Nmap installation failed${NC}"
    exit 1
fi

# Test Nmap with a basic scan
echo -e "${YELLOW}[+] Testing Nmap with a basic scan...${NC}"
nmap -sn localhost || {
    echo -e "${RED}Nmap test failed${NC}"
    exit 1
}

# Final success message
echo
echo "====================================================="
echo "       AI_MAL Installation Complete"
echo "====================================================="
echo
echo "Examples:"
echo "  # Basic scan of a target"
echo "  AI_MAL 192.168.1.1"
echo
echo "  # Auto-discover hosts and scan with stealth mode"
echo "  AI_MAL --auto-discover --stealth"
echo
echo "  # Use gemma3:1b model for systems with less than 4GB RAM"
echo "  AI_MAL --model gemma3:1b --stealth"
echo
echo "  # Full integration with Metasploit"
echo "  AI_MAL 192.168.1.1 --msf --exploit"
echo
echo "Read the documentation for more information."
echo "For help, run: AI_MAL --help"
echo