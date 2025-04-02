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
            python3-wheel \
            python3-cffi \
            python3-cryptography \
            python3-scapy \
            python3-paramiko \
            python3-requests \
            python3-urllib3 \
            python3-numpy \
            python3-pandas \
            python3-scikit-learn \
            python3-torch \
            python3-transformers \
            python3-colorama \
            python3-tqdm \
            python3-yaml \
            python3-jinja2 \
            python3-click \
            python3-rich \
            python3-pytest \
            python3-pytest-asyncio \
            python3-pytest-cov \
            python3-pytest-mock \
            python3-black \
            python3-flake8 \
            python3-mypy \
            python3-isort
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
pip install -e .

echo ">>> Installation complete!"
echo ">>> To activate the virtual environment, run: source venv/bin/activate"
echo ">>> To run AI_MAL, simply type: AI_MAL" 