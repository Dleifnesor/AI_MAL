#!/bin/bash

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Get the current directory
CURRENT_DIR=$(pwd)

echo -e "${YELLOW}>>> Installing AI_MAL...${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Check if running on Kali Linux
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "$ID" = "kali" ]; then
        echo -e "${YELLOW}>>> Detected Kali Linux${NC}"
        
        # Update system
        echo -e "${YELLOW}>>> Updating system packages...${NC}"
        apt-get update
        apt-get upgrade -y
        
        # Install required system packages
        echo -e "${YELLOW}>>> Installing system dependencies...${NC}"
        apt-get install -y \
            python3 \
            python3-pip \
            python3-venv \
            git \
            nmap \
            metasploit-framework \
            curl \
            wget \
            build-essential \
            libssl-dev \
            libffi-dev \
            python3-nmap \
            smbclient \
            libpcap-dev \
            libnetfilter-queue-dev \
            libnetfilter-queue1 \
            libnetfilter-conntrack-dev \
            libnetfilter-conntrack3 \
            python3-dev \
            python3-setuptools \
            python3-wheel

        # Install Ollama
        echo -e "${YELLOW}>>> Installing Ollama...${NC}"
        curl -fsSL https://ollama.com/install.sh | sh -s -- -q

        # Start Ollama service
        echo -e "${YELLOW}>>> Starting Ollama service...${NC}"
        systemctl start ollama
        systemctl enable ollama

        # Pull the specified model
        echo -e "${YELLOW}>>> Pulling artifish/llama3.2-uncensored model...${NC}"
        ollama pull artifish/llama3.2-uncensored

        # Set as default model in .env file
        echo -e "${YELLOW}>>> Setting artifish/llama3.2-uncensored as default model...${NC}"
        if [ -f .env ]; then
            sed -i 's/^OLLAMA_MODEL=.*/OLLAMA_MODEL=artifish\/llama3.2-uncensored/' .env
        else
            echo "OLLAMA_MODEL=artifish/llama3.2-uncensored" > .env
            echo "OLLAMA_FALLBACK_MODEL=mistral:7b" >> .env
            echo "LOG_DIR=logs" >> .env
            echo "WORKSPACE_DIR=workspaces" >> .env
        fi
        
        # Also set it in the current shell session
        export OLLAMA_MODEL=artifish/llama3.2-uncensored
    else
        echo -e "${RED}>>> Error: This script is designed for Kali Linux${NC}"
        echo -e "${RED}>>> Please install Kali Linux or modify this script for your distribution${NC}"
        exit 1
    fi
else
    echo -e "${RED}>>> Error: Could not detect Linux distribution${NC}"
    echo -e "${RED}>>> Please ensure you are running Kali Linux${NC}"
    exit 1
fi

# Clean up any existing installation
echo -e "${YELLOW}>>> Cleaning up any existing installation...${NC}"
pip3 uninstall -y AI_MAL || true
rm -f /usr/local/bin/AI_MAL
rm -rf "$CURRENT_DIR/venv" || true
rm -rf "$CURRENT_DIR/build" || true
rm -rf "$CURRENT_DIR/dist" || true
rm -rf "$CURRENT_DIR/AI_MAL.egg-info" || true

# Create virtual environment
echo -e "${YELLOW}>>> Creating virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo -e "${YELLOW}>>> Installing dependencies...${NC}"
pip3 install --upgrade pip
pip3 install -r requirements.txt

# Install AI_MAL package
echo -e "${YELLOW}>>> Installing AI_MAL package...${NC}"
pip3 install -e .

# Create necessary directories
echo -e "${YELLOW}>>> Creating necessary directories...${NC}"
mkdir -p logs
mkdir -p results
mkdir -p scripts
mkdir -p workspaces

# Set permissions
echo -e "${YELLOW}>>> Setting permissions...${NC}"
chmod -R 755 "$CURRENT_DIR"
chmod +x "$CURRENT_DIR/venv/bin/AI_MAL"

# Create symbolic link
echo -e "${YELLOW}>>> Creating symbolic link...${NC}"
ln -sf "$CURRENT_DIR/venv/bin/AI_MAL" /usr/local/bin/AI_MAL

# Add alias to .bashrc
echo -e "${YELLOW}>>> Adding alias to .bashrc...${NC}"
if ! grep -q "alias activate_ai_mal" ~/.bashrc; then
    echo "alias activate_ai_mal='source $CURRENT_DIR/venv/bin/activate'" >> ~/.bashrc
fi

echo -e "${GREEN}>>> Installation complete!${NC}"
echo -e "${GREEN}>>> To activate the virtual environment, run: source venv/bin/activate${NC}"
echo -e "${GREEN}>>> Or simply run: activate_ai_mal${NC}"
echo -e "${GREEN}>>> To run AI_MAL, simply type: AI_MAL${NC}"
echo -e "${GREEN}>>> Ollama is installed and configured with artifish/llama3.2-uncensored model${NC}" 