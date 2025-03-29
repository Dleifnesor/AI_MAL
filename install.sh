#!/bin/bash

# AI_MAL Installation Script
# This script installs AI_MAL and its dependencies on a Kali Linux system

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ASCII Art Banner
echo -e "\n                                                     
                              @@@@@@@@@@                        
                              @@@     @@@                       
                             @@@@     @@@                       
                             @@@@     @@@                       
                             @@@@     @@@                       
                             @@@@     @@@                       
                       @@@@@@@@@@     @@@                       
                      @@@@@@@@@@@     @@@@@@@@@                 
                     @@@     @@@@     @@@@@@@@@@@               
                     @@@      @@@     @@@@    @@@               
                     @@@      @@@     @@@      @@@@@@@@@        
        @@@@@@@@@    @@@      @@@     @@@      @@@@@@@@@@       
       @@@@@@@@@@@@  @@@      @@@     @@@      @@@     @@@      
      @@@@@       @@@@@@      @@@     @@@      @@@     @@@      
        @@@@        @@@@      @@@     @@@      @@@     @@@      
         @@@@@       @@@@     @@@     @@@      @@@     @@@      
           @@@@       @@@                              @@@      
            @@@@                                       @@@      
              @@@@                                     @@@      
                @@@@                                   @@@      
                  @@@@                                 @@@      
                    @@@@@@                             @@@      
                      @@@@                           @@@@@      
                      @@@                          @@@@@@       
                      @@@@                       @@@@@@         
                       @@@                         @@@          
                        @@@@                     @@@@           
                         @@@@@@@@@@@@@@@@@@@@@@@@@@@            
                           @@@@@@@@@@@@@@@@@@@@@@               
 Advanced Intelligent Machine-Aided Learning
 for Network Penetration

"

echo -e "\nStarting AI_MAL installation...\n"

# Get installation directory
INSTALL_DIR=$(pwd)
echo "Installation directory: $INSTALL_DIR\n"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check system
check_system() {
    echo "Checking system..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [ "$ID" = "kali" ]; then
            echo "Kali Linux detected. Continuing installation..."
            return 0
        fi
    fi
    echo "Error: This script is designed for Kali Linux only."
    exit 1
}

# Function to check Python version
check_python() {
    echo "Checking Python version..."
    if command_exists python3; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        echo "Python version: $PYTHON_VERSION"
        return 0
    else
        echo "Error: Python 3 is not installed."
        exit 1
    fi
}

# Function to install Python dependencies
install_python_deps() {
    echo "Installing Python dependencies..."
    
    # Install system packages via apt
    apt update
    apt install -y python3-nmap python3-requests python3-netifaces
    
    # Install additional packages via pip with --break-system-packages flag
    pip install pymetasploit3 --break-system-packages
    
    if [ $? -eq 0 ]; then
        echo "Python dependencies installed successfully."
    else
        echo "Error: Failed to install Python dependencies."
        exit 1
    fi
}

# Function to configure Metasploit
configure_metasploit() {
    echo "Configuring Metasploit..."
    
    # Start and enable PostgreSQL
    systemctl start postgresql
    systemctl enable postgresql
    
    # Initialize Metasploit database
    msfdb init
    
    # Create systemd service for msfrpcd
    cat > /etc/systemd/system/msfrpcd.service << 'EOL'
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
EOL
    
    # Enable and start msfrpcd service
    systemctl daemon-reload
    systemctl enable msfrpcd.service
    systemctl start msfrpcd.service
    
    echo "Metasploit configured successfully."
}

# Function to install Ollama
install_ollama() {
    echo "Installing Ollama..."
    
    # Download and install Ollama
    curl -fsSL https://ollama.com/install.sh | sh
    
    # Start Ollama service
    ollama serve &
    
    # Pull required models
    echo "Pulling required Ollama models..."
    ollama pull llama3
    ollama pull qwen2.5-coder:7b
    
    echo "Ollama installed successfully."
}

# Function to configure AI_MAL
configure_ai_mal() {
    echo "Configuring AI_MAL..."
    
    # Make scripts executable
    chmod +x adaptive_nmap_scan.py
    chmod +x AI_MAL
    
    # Create directory for generated scripts
    mkdir -p generated_scripts
    
    # Create system-wide link
    ln -sf "$INSTALL_DIR/AI_MAL" /usr/local/bin/AI_MAL
    
    echo "AI_MAL configured successfully."
}

# Main installation process
check_system
check_python
install_python_deps
configure_metasploit
install_ollama
configure_ai_mal

echo -e "\nInstallation completed successfully!"
echo -e "You can now use AI_MAL by running: AI_MAL --help\n"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}WARNING: Some installation steps require root privileges.${NC}"
    echo -e "Consider running with: ${GREEN}sudo ./install.sh${NC}"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation aborted."
        exit 1
    fi
fi

echo -e "${BLUE}Starting AI_MAL installation...${NC}"
echo ""

# Check if Nmap is installed
echo -e "${BLUE}Checking for Nmap...${NC}"
if command -v nmap &>/dev/null; then
    NMAP_VERSION=$(nmap --version | head -n1)
    echo -e "Nmap version: ${GREEN}${NMAP_VERSION}${NC}"
else
    echo -e "${YELLOW}Nmap not found. Installing Nmap...${NC}"
    if [ "$EUID" -eq 0 ]; then
        apt-get update && apt-get install -y nmap
    else
        echo -e "${RED}Error: Root privileges required to install Nmap.${NC}"
        echo "Please install Nmap manually with: sudo apt-get install nmap"
        exit 1
    fi
fi

# Installation complete
echo ""
echo -e "${GREEN}AI_MAL installation complete!${NC}"
echo ""
echo -e "To run AI_MAL, use the command: ${BLUE}AI_MAL${NC}"
echo -e "For help and options, run: ${BLUE}AI_MAL --help${NC}"
echo ""
echo -e "Please note that you may need to start the Metasploit RPC service manually:"
echo -e "${YELLOW}sudo msfrpcd -P 'msf_password' -S -a 127.0.0.1 -p 55553${NC}"
echo ""
echo -e "${RED}IMPORTANT SECURITY NOTICE:${NC}"
echo -e "This tool is designed for legitimate security testing only."
echo -e "Always ensure you have proper authorization before scanning or exploiting any network or system."
echo "" 
