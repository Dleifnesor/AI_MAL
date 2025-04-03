#!/bin/bash

# Exit on error
set -e

echo ">>> Installing system dependencies..."

# Check if running on Kali Linux
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "$ID" = "kali" ]; then
        echo ">>> Detected Kali Linux"
        
        # Update system
        echo ">>> Updating system packages..."
        sudo apt-get update
        sudo apt-get upgrade -y
        
        # Install required system packages
        echo ">>> Installing system dependencies..."
        sudo apt-get install -y \
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
        echo ">>> Installing Ollama..."
        curl -fsSL https://ollama.com/install.sh | sh

        # Start Ollama service
        echo ">>> Starting Ollama service..."
        sudo systemctl start ollama
        sudo systemctl enable ollama

        # Pull the specified model
        echo ">>> Pulling artifish/llama3.2-uncensored model..."
        ollama pull artifish/llama3.2-uncensored

        # Set as default model in .env file
        echo ">>> Setting artifish/llama3.2-uncensored as default model..."
        # Create or update .env file
        if [ -f .env ]; then
            # Update existing .env file
            sed -i 's/^OLLAMA_MODEL=.*/OLLAMA_MODEL=artifish\/llama3.2-uncensored/' .env
        else
            # Create new .env file
            echo "OLLAMA_MODEL=artifish/llama3.2-uncensored" > .env
            echo "OLLAMA_FALLBACK_MODEL=mistral:7b" >> .env
            echo "LOG_DIR=logs" >> .env
            echo "WORKSPACE_DIR=workspaces" >> .env
        fi
        
        # Also set it in the current shell session
        export OLLAMA_MODEL=artifish/llama3.2-uncensored
    else
        echo ">>> Error: This script is designed for Kali Linux"
        echo ">>> Please install Kali Linux or modify this script for your distribution"
        exit 1
    fi
else
    echo ">>> Error: Could not detect Linux distribution"
    echo ">>> Please ensure you are running Kali Linux"
    exit 1
fi

# Create Python virtual environment
echo ">>> Creating Python virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo ">>> Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo ">>> Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
echo ">>> Installing Python dependencies..."
pip install -r requirements.txt

# Install the package in development mode
echo ">>> Installing AI_MAL package..."
pip install -e .

echo ">>> Installation complete!"
echo ">>> To activate the virtual environment, run: source venv/bin/activate"
echo ">>> To run AI_MAL, simply type: AI_MAL"
echo ">>> Ollama is installed and configured with artifish/llama3.2-uncensored model" 