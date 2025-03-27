#!/bin/bash

# AI_MAL Installation Script
# This script installs AI_MAL and its dependencies on a Kali Linux system

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${RED}"
echo "                               @@@@@@@@                         "
echo "                              @@@@@@@@@@                        "
echo "                              @@@     @@@                       "
echo "                             @@@@     @@@                       "
echo "                             @@@@     @@@                       "
echo "                             @@@@     @@@                       "
echo "                             @@@@     @@@                       "
echo "                       @@@@@@@@@@     @@@                       "
echo "                      @@@@@@@@@@@     @@@@@@@@@                 "
echo "                     @@@     @@@@     @@@@@@@@@@@               "
echo "                     @@@      @@@     @@@@    @@@               "
echo "                     @@@      @@@     @@@      @@@@@@@@@        "
echo "        @@@@@@@@@    @@@      @@@     @@@      @@@@@@@@@@       "
echo "       @@@@@@@@@@@@  @@@      @@@     @@@      @@@     @@@      "
echo "      @@@@@       @@@@@@      @@@     @@@      @@@     @@@      "
echo "        @@@@        @@@@      @@@     @@@      @@@     @@@      "
echo "         @@@@@       @@@@     @@@     @@@      @@@     @@@      "
echo "           @@@@       @@@                              @@@      "
echo "            @@@@                                       @@@      "
echo "              @@@@                                     @@@      "
echo "                @@@@                                   @@@      "
echo "                  @@@@                                 @@@      "
echo "                    @@@@@@                             @@@      "
echo "                      @@@@                           @@@@@      "
echo "                      @@@                          @@@@@@       "
echo "                      @@@@                       @@@@@@         "
echo "                       @@@                         @@@          "
echo "                        @@@@                     @@@@           "
echo "                         @@@@@@@@@@@@@@@@@@@@@@@@@@@            "
echo "                           @@@@@@@@@@@@@@@@@@@@@@               "
echo " Advanced Intelligent Machine-Aided Learning"
echo " for Network Penetration"
echo -e "${NC}"
echo ""

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

# Set up installation directory
INSTALL_DIR="$(pwd)"
echo -e "${BLUE}Installation directory: ${INSTALL_DIR}${NC}"
echo ""

# Check if we're on Kali Linux
echo -e "${BLUE}Checking system...${NC}"
if grep -q "Kali" /etc/os-release; then
    echo -e "${GREEN}Kali Linux detected. Continuing installation...${NC}"
else
    echo -e "${YELLOW}Warning: This doesn't appear to be a Kali Linux system.${NC}"
    echo "AI_MAL is designed to work best on Kali Linux."
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation aborted."
        exit 1
    fi
fi

# Check Python version
echo -e "${BLUE}Checking Python version...${NC}"
if command -v python3 &>/dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo -e "Python version: ${GREEN}${PYTHON_VERSION}${NC}"
    
    # Compare version
    MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
    MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
    
    if [ "$MAJOR" -lt 3 ] || ([ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 6 ]); then
        echo -e "${RED}Error: Python 3.6+ is required.${NC}"
        exit 1
    fi
else
    echo -e "${RED}Error: Python 3 is not installed.${NC}"
    echo "Please install Python 3.6+ to continue."
    exit 1
fi

# Install Python dependencies
echo -e "${BLUE}Installing Python dependencies...${NC}"
pip3 install python-nmap requests pymetasploit3 netifaces ipaddress

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to install Python dependencies.${NC}"
    echo "Please make sure pip is installed and try again."
    exit 1
fi

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

# Configure Ollama
echo -e "${BLUE}Setting up Ollama...${NC}"
if command -v ollama &>/dev/null; then
    echo -e "${GREEN}Ollama is already installed.${NC}"
else
    echo -e "${YELLOW}Installing Ollama...${NC}"
    curl -fsSL https://ollama.com/install.sh | sh
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to install Ollama. Please install it manually:${NC}"
        echo "curl -fsSL https://ollama.com/install.sh | sh"
        echo "Continuing with installation..."
    fi
fi

# Pull Ollama model
echo -e "${BLUE}Pulling Ollama model (llama3)...${NC}"
if command -v ollama &>/dev/null; then
    ollama pull llama3
    
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}Warning: Failed to pull llama3 model.${NC}"
        echo "You can try again later with: ollama pull llama3"
    fi
else
    echo -e "${YELLOW}Warning: Skipping model pull since Ollama is not installed.${NC}"
fi

# Configure Metasploit
echo -e "${BLUE}Setting up Metasploit...${NC}"
if command -v msfconsole &>/dev/null; then
    echo -e "${GREEN}Metasploit is already installed.${NC}"
    
    # Check if PostgreSQL is running
    if [ "$EUID" -eq 0 ]; then
        if systemctl is-active --quiet postgresql; then
            echo -e "${GREEN}PostgreSQL is running.${NC}"
        else
            echo -e "${YELLOW}Starting PostgreSQL service...${NC}"
            systemctl start postgresql
            systemctl enable postgresql
        fi
        
        # Initialize MSF database
        echo -e "${YELLOW}Initializing Metasploit database...${NC}"
        msfdb init
        
        # Set up Metasploit RPC as a system service
        echo -e "${YELLOW}Setting up Metasploit RPC service...${NC}"
        
        # Create systemd service for msfrpcd
        cat > /etc/systemd/system/msfrpcd.service << EOL
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

        # Reload systemd, enable and start the service
        systemctl daemon-reload
        systemctl enable msfrpcd.service
        systemctl start msfrpcd.service
        
        echo -e "${GREEN}Metasploit RPC service is now configured to start automatically.${NC}"
    else
        echo -e "${YELLOW}Warning: Root privileges required to configure PostgreSQL and Metasploit RPC.${NC}"
        echo "Please run the following commands manually:"
        echo "  sudo systemctl start postgresql"
        echo "  sudo systemctl enable postgresql"
        echo "  sudo msfdb init"
        echo "  sudo msfrpcd -P 'msf_password' -S -a 127.0.0.1 -p 55553"
    fi
else
    echo -e "${RED}Error: Metasploit not found.${NC}"
    echo "Please install Metasploit Framework and try again."
    exit 1
fi

# Make scripts executable
echo -e "${BLUE}Making scripts executable...${NC}"
chmod +x "${INSTALL_DIR}/adaptive_nmap_scan.py"
chmod +x "${INSTALL_DIR}/AI_MAL"

# Create symbolic link
echo -e "${BLUE}Creating symbolic link...${NC}"
if [ "$EUID" -eq 0 ]; then
    ln -sf "${INSTALL_DIR}/AI_MAL" /usr/local/bin/AI_MAL
    echo -e "${GREEN}Symbolic link created: /usr/local/bin/AI_MAL${NC}"
else
    echo -e "${YELLOW}Warning: Root privileges required to create system-wide symbolic link.${NC}"
    echo "You can create it manually with:"
    echo "  sudo ln -sf ${INSTALL_DIR}/AI_MAL /usr/local/bin/AI_MAL"
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