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

# Check for sudo privileges
check_sudo

# Determine the installation directory
INSTALL_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$INSTALL_DIR" || { echo "Could not change to install directory"; exit 1; }

# Print welcome message
echo "====================================================="
echo "       Installing AI_MAL - AI-Powered Penetration Testing Tool"
echo "====================================================="
echo

# Update system and install essential packages
echo -e "${YELLOW}[+] Updating system and installing essential packages...${NC}"
apt-get update
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
    metasploit-framework \
    postgresql \
    postgresql-contrib \
    libpcap-dev \
    libsmbclient0 \
    libsmbclient-dev \
    samba \
    samba-dev \
    python3-samba \
    ca-certificates \
    dos2unix \
    || { echo -e "${RED}Failed to install system dependencies${NC}"; exit 1; }

# Start and enable PostgreSQL
echo -e "${YELLOW}[+] Setting up PostgreSQL...${NC}"
systemctl enable postgresql
systemctl start postgresql

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

# Initialize Metasploit database
echo -e "${YELLOW}[+] Initializing Metasploit database...${NC}"
msfdb init || {
    echo -e "${RED}Failed to initialize Metasploit database${NC}"
    echo -e "${YELLOW}Trying alternative setup...${NC}"
    
    # Create msf user and database
    sudo -u postgres psql -c "CREATE USER msf WITH PASSWORD 'msf';" 2>/dev/null || true
    sudo -u postgres psql -c "CREATE DATABASE msf OWNER msf;" 2>/dev/null || true
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE msf TO msf;" 2>/dev/null || true
}

# Clean up previous virtual environment if it exists
echo -e "${YELLOW}[+] Cleaning up previous virtual environment (if any)...${NC}"
rm -rf venv

# Create virtual environment
echo -e "${YELLOW}[+] Creating virtual environment...${NC}"
python3 -m venv --system-site-packages venv || { echo -e "${RED}Failed to create virtual environment${NC}"; exit 1; }

# Activate virtual environment
echo -e "${YELLOW}[+] Activating virtual environment...${NC}"
source venv/bin/activate || { echo -e "${RED}Failed to activate virtual environment${NC}"; exit 1; }

# Install Python packages
echo -e "${YELLOW}[+] Installing Python dependencies...${NC}"
python3 -m pip install --upgrade pip

# Install core dependencies
echo -e "${YELLOW}[+] Installing core dependencies...${NC}"
python3 -m pip install --upgrade --ignore-installed \
    requests \
    pymetasploit3 \
    psutil \
    netifaces \
    paramiko \
    scapy \
    rich \
    click \
    || { echo -e "${RED}Failed to install core dependencies${NC}"; exit 1; }

# Install optional dependencies
echo -e "${YELLOW}[+] Installing optional dependencies...${NC}"
python3 -m pip install --upgrade --ignore-installed \
    impacket \
    pyasn1 \
    pycryptodomex \
    prompt-toolkit \
    || { echo -e "${RED}Failed to install optional dependencies${NC}"; exit 1; }

# Install Ollama
echo -e "${YELLOW}[+] Installing Ollama...${NC}"
curl -fsSL https://ollama.com/install.sh | sh || {
    echo -e "${RED}Failed to install Ollama${NC}"
    echo -e "${YELLOW}Continuing without Ollama support...${NC}"
}

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

# Pull required models
echo -e "${YELLOW}[+] Pulling required models...${NC}"
ollama pull codellama || echo -e "${RED}Failed to pull codellama model${NC}"
ollama pull gemma3:1b || echo -e "${RED}Failed to pull gemma3:1b model${NC}"
ollama pull qwen2.5-coder:7b || echo -e "${RED}Failed to pull qwen2.5-coder:7b model${NC}"

# Fix line endings in the wrapper script
echo -e "${GREEN}[+] Ensuring correct line endings for AI_MAL script...${NC}"
dos2unix "$INSTALL_DIR/AI_MAL"

# Make the main files executable
echo -e "${GREEN}[+] Setting executable permissions...${NC}"
chmod +x "$INSTALL_DIR/AI_MAL"

# Create symlink in /usr/local/bin
echo -e "${GREEN}[+] Creating symlink in /usr/local/bin...${NC}"
ln -sf "$INSTALL_DIR/AI_MAL" /usr/local/bin/AI_MAL

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