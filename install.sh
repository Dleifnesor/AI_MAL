#!/bin/bash

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to handle errors
handle_error() {
    echo -e "${RED}Error: $1${NC}"
    exit 1
}

# Suppress verbose output
suppress_output() {
    "$@" > /dev/null 2>&1
}

echo -e "${YELLOW}>>> Installing AI_MAL...${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    handle_error "Please run as root (sudo ./install.sh)"
fi

# Check if running on Kali Linux
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "$ID" = "kali" ]; then
        echo -e "${YELLOW}>>> Detected Kali Linux${NC}"
        
        # Update system packages
        echo -e "${YELLOW}>>> Updating system packages...${NC}"
        suppress_output apt-get update
        suppress_output apt-get upgrade -y
        
        # Install required system packages
        echo -e "${YELLOW}>>> Installing system dependencies...${NC}"
        suppress_output apt-get install -y \
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

        # Install Ollama if not already installed
        if ! command_exists ollama; then
            echo -e "${YELLOW}>>> Installing Ollama...${NC}"
            curl -fsSL https://ollama.com/install.sh | sh -s -- -q > /dev/null 2>&1
            
            # Start Ollama service
            echo -e "${YELLOW}>>> Starting Ollama service...${NC}"
            systemctl start ollama
            systemctl enable ollama
            
            # Wait for Ollama to start
            echo -e "${YELLOW}>>> Waiting for Ollama service to start...${NC}"
            sleep 5
            
            # Pull the specified models
            echo -e "${YELLOW}>>> Pulling required AI models...${NC}"
            ollama pull artifish/llama3.2-uncensored > /dev/null 2>&1
            ollama pull gemma:1b > /dev/null 2>&1
        else
            echo -e "${YELLOW}>>> Ollama already installed, checking for required models...${NC}"
            # Check if models are available
            if ! ollama list | grep -q "artifish/llama3.2-uncensored"; then
                echo -e "${YELLOW}>>> Pulling primary AI model: artifish/llama3.2-uncensored${NC}"
                ollama pull artifish/llama3.2-uncensored > /dev/null 2>&1
            fi
            
            if ! ollama list | grep -q "gemma:1b"; then
                echo -e "${YELLOW}>>> Pulling fallback AI model: gemma:1b${NC}"
                ollama pull gemma:1b > /dev/null 2>&1
            fi
        fi

        # Set as default model in .env file
        echo -e "${YELLOW}>>> Setting artifish/llama3.2-uncensored as default model...${NC}"
        if [ -f .env ]; then
            sed -i 's/^OLLAMA_MODEL=.*/OLLAMA_MODEL=artifish\/llama3.2-uncensored/' .env
        else
            echo "OLLAMA_MODEL=artifish/llama3.2-uncensored" > .env
            echo "OLLAMA_FALLBACK_MODEL=gemma:1b" >> .env
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

# Get the current directory
INSTALL_DIR=$(pwd)

# Clean up any existing installation
echo -e "${YELLOW}>>> Cleaning up any existing installation...${NC}"
suppress_output pip3 uninstall -y AI_MAL || true
rm -f /usr/local/bin/AI_MAL
rm -rf "$INSTALL_DIR/venv" || true
rm -rf "$INSTALL_DIR/build" || true
rm -rf "$INSTALL_DIR/dist" || true
rm -rf "$INSTALL_DIR/AI_MAL.egg-info" || true

# Create necessary directories
echo -e "${YELLOW}>>> Creating necessary directories...${NC}"
mkdir -p logs
mkdir -p scan_results
mkdir -p msf_resources
mkdir -p generated_scripts
mkdir -p workspaces
mkdir -p exfiltrated_data
mkdir -p implant_logs

# Create virtual environment
echo -e "${YELLOW}>>> Creating virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo -e "${YELLOW}>>> Installing dependencies...${NC}"
suppress_output pip3 install --upgrade pip
suppress_output pip3 install -r requirements.txt

# Install AI_MAL package
echo -e "${YELLOW}>>> Installing AI_MAL package...${NC}"
suppress_output pip3 install -e .

# Set permissions
echo -e "${YELLOW}>>> Setting permissions...${NC}"
chmod -R 755 "$INSTALL_DIR"

# Check if Metasploit is running, if not start it
echo -e "${YELLOW}>>> Checking Metasploit service...${NC}"
if ! pgrep -x "postgres" > /dev/null; then
    echo -e "${YELLOW}>>> Starting PostgreSQL for Metasploit...${NC}"
    systemctl start postgresql
    systemctl enable postgresql
fi

if ! pgrep -f "msfrpcd" > /dev/null; then
    echo -e "${YELLOW}>>> Initializing Metasploit database...${NC}"
    suppress_output msfdb init
fi

# Create system-wide executable wrapper script
echo -e "${YELLOW}>>> Creating system-wide executable wrapper...${NC}"
cat > /usr/local/bin/AI_MAL << EOF
#!/bin/bash
# AI_MAL wrapper script
# This script automatically activates the virtual environment and starts all dependencies before running AI_MAL

# Path to the virtual environment and installation
INSTALL_DIR="$INSTALL_DIR"
VENV_PATH="\$INSTALL_DIR/venv"
PYTHON_PATH="\$VENV_PATH/bin/python"

# Function to check if a service is running
is_service_running() {
    systemctl is-active --quiet \$1
    return \$?
}

# Ensure needed directories exist
mkdir -p "\$INSTALL_DIR/logs" 2>/dev/null || true
mkdir -p "\$INSTALL_DIR/scan_results" 2>/dev/null || true
mkdir -p "\$INSTALL_DIR/msf_resources" 2>/dev/null || true
mkdir -p "\$INSTALL_DIR/generated_scripts" 2>/dev/null || true
mkdir -p "\$INSTALL_DIR/workspaces" 2>/dev/null || true
mkdir -p "\$INSTALL_DIR/exfiltrated_data" 2>/dev/null || true
mkdir -p "\$INSTALL_DIR/implant_logs" 2>/dev/null || true

# Check and start required services
# 1. Check PostgreSQL (required for Metasploit)
if ! is_service_running postgresql; then
    echo "Starting PostgreSQL service..."
    sudo systemctl start postgresql
fi

# 2. Check and start Ollama
if ! is_service_running ollama; then
    echo "Starting Ollama service..."
    sudo systemctl start ollama
    # Give Ollama time to initialize
    sleep 3
fi

# 3. Initialize Metasploit database if needed
if ! pgrep -f msfrpcd > /dev/null; then
    echo "Initializing Metasploit database..."
    sudo msfdb init > /dev/null 2>&1
fi

# 4. Set environment variables
export OLLAMA_MODEL="artifish/llama3.2-uncensored"
export OLLAMA_FALLBACK_MODEL="gemma:1b"
export LOG_DIR="\$INSTALL_DIR/logs"
export WORKSPACE_DIR="\$INSTALL_DIR/workspaces"
export MSF_RESOURCES_DIR="\$INSTALL_DIR/msf_resources"
export SCAN_RESULTS_DIR="\$INSTALL_DIR/scan_results"
export GENERATED_SCRIPTS_DIR="\$INSTALL_DIR/generated_scripts"
export EXFIL_DIR="\$INSTALL_DIR/exfiltrated_data"

# Activate the virtual environment and run AI_MAL with all arguments passed to this script
cd "\$INSTALL_DIR" && "\$PYTHON_PATH" -m AI_MAL.main "\$@"
EOF

# Make the wrapper executable
chmod +x /usr/local/bin/AI_MAL

# Add to system PATH and make it persist across reboots
echo -e "${YELLOW}>>> Creating systemd service for persistence...${NC}"

# Create Metasploit autostart service if it doesn't exist
if [ ! -f /etc/systemd/system/metasploit.service ]; then
    cat > /etc/systemd/system/metasploit.service << EOF
[Unit]
Description=Metasploit Framework Service
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
ExecStartPre=/usr/bin/msfdb init
ExecStart=/usr/bin/msfconsole -q
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    # Enable the service but don't start it immediately
    systemctl enable metasploit.service
fi

# Reload systemd
systemctl daemon-reload

# Create a sudoers file for AI_MAL
echo -e "${YELLOW}>>> Configuring sudoers permissions for AI_MAL...${NC}"
cat > /etc/sudoers.d/ai_mal << EOF
# Allow AI_MAL to run specific privileged commands without password

# Commands needed for Metasploit
ALL ALL=(ALL) NOPASSWD: /usr/bin/msfdb
ALL ALL=(ALL) NOPASSWD: /usr/bin/msfconsole

# Commands needed for network operations
ALL ALL=(ALL) NOPASSWD: /usr/bin/nmap
ALL ALL=(ALL) NOPASSWD: /sbin/ip
ALL ALL=(ALL) NOPASSWD: /bin/systemctl start postgresql
ALL ALL=(ALL) NOPASSWD: /bin/systemctl start ollama
ALL ALL=(ALL) NOPASSWD: /usr/sbin/arp
ALL ALL=(ALL) NOPASSWD: /usr/sbin/arping
ALL ALL=(ALL) NOPASSWD: /bin/ip
ALL ALL=(ALL) NOPASSWD: /sbin/ifconfig
EOF

# Secure the sudoers file
chmod 0440 /etc/sudoers.d/ai_mal

# Make a link in /usr/bin as well for maximum compatibility
ln -sf /usr/local/bin/AI_MAL /usr/bin/AI_MAL 2>/dev/null || true

# Make sure AI_MAL is in the PATH
if ! grep -q "PATH=" ~/.bashrc; then
    echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bashrc
fi

echo -e "${GREEN}>>> Installation complete!${NC}"
echo -e "${GREEN}>>> You can now run AI_MAL from anywhere with: AI_MAL <target> [options]${NC}"
echo -e "${GREEN}>>> For example: AI_MAL 192.168.1.1 --msf --exploit --full-auto --vuln${NC}"
echo -e "${GREEN}>>> Ollama is installed and configured with artifish/llama3.2-uncensored model${NC}" 