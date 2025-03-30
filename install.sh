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
echo -e "\n                               @@@@@@@@                         
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

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: This script requires root privileges.${NC}"
  echo "Please run with: sudo $0"
  exit 1
fi

# Check system compatibility
if [ ! -f /etc/os-release ]; then
  echo -e "${RED}Error: Cannot determine operating system.${NC}"
  exit 1
fi

source /etc/os-release
if [[ "$ID" != "kali" && "$ID_LIKE" != *"debian"* ]]; then
  echo -e "${YELLOW}Warning: This installer is optimized for Kali Linux.${NC}"
  echo "Your system: $PRETTY_NAME"
  read -p "Continue anyway? (y/n) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
  fi
fi

# Installation directory
INSTALL_DIR="/opt/ai_mal"
mkdir -p $INSTALL_DIR

echo -e "\n${GREEN}Step 1: Installing system dependencies...${NC}"
apt update
apt install -y python3 python3-pip nmap metasploit-framework dos2unix netifaces

echo -e "\n${GREEN}Step 2: Installing Python dependencies...${NC}"
# First try to uninstall existing pymetasploit3 to ensure clean installation
pip3 uninstall -y pymetasploit3
pip3 install nmap requests pymetasploit3 psutil netifaces

# Verify pymetasploit3 installation
echo -e "\n${YELLOW}Verifying pymetasploit3 installation...${NC}"
if ! python3 -c "from pymetasploit3.msfrpc import MsfRpcClient; print('pymetasploit3 correctly installed')" 2>/dev/null; then
  echo -e "${RED}Warning: pymetasploit3 not properly installed. Trying alternative method...${NC}"
  pip3 uninstall -y pymetasploit3
  pip3 install --force-reinstall pymetasploit3
  
  # Verify again
  if ! python3 -c "from pymetasploit3.msfrpc import MsfRpcClient; print('pymetasploit3 correctly installed')" 2>/dev/null; then
    echo -e "${RED}Error: Could not properly install pymetasploit3.${NC}"
    echo "You may need to manually fix this issue before using Metasploit integration."
  else
    echo -e "${GREEN}pymetasploit3 successfully installed!${NC}"
  fi
else
  echo -e "${GREEN}pymetasploit3 successfully installed!${NC}"
fi

echo -e "\n${GREEN}Step 3: Setting up Metasploit...${NC}"
# Start PostgreSQL and initialize Metasploit database
systemctl start postgresql
systemctl enable postgresql

# Initialize Metasploit database if not already done
if [ ! -f ~/.msf4/db ]; then
  echo "Initializing Metasploit database..."
  msfdb init
fi

# Set up Metasploit RPC daemon service
echo "Creating Metasploit RPC service..."
cat > /etc/systemd/system/msfrpcd.service << EOL
[Unit]
Description=Metasploit rpc daemon
After=network.target postgresql.service
Wants=postgresql.service
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/bin/msfrpcd -P msf_password -S -a 127.0.0.1 -p 55553
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
EOL

# Reload, enable and start service
systemctl daemon-reload
systemctl enable msfrpcd.service
systemctl start msfrpcd.service

echo -e "\n${GREEN}Step 4: Installing Ollama...${NC}"
curl -fsSL https://ollama.com/install.sh | sh

echo -e "\n${GREEN}Step 5: Setting up AI_MAL...${NC}"
# Copy files to installation directory
cp adaptive_nmap_scan.py $INSTALL_DIR/
cp AI_MAL $INSTALL_DIR/

# Fix line endings (in case files came from Windows)
dos2unix $INSTALL_DIR/adaptive_nmap_scan.py
dos2unix $INSTALL_DIR/AI_MAL

# Make files executable
chmod +x $INSTALL_DIR/adaptive_nmap_scan.py
chmod +x $INSTALL_DIR/AI_MAL

# Create directory for generated scripts
mkdir -p $INSTALL_DIR/generated_scripts

# Create symlink for system-wide access
ln -sf $INSTALL_DIR/AI_MAL /usr/local/bin/AI_MAL

echo -e "\n${GREEN}Step 6: Pulling Ollama models...${NC}"
echo "This may take some time depending on your internet speed..."
# Pull the recommended model
ollama pull qwen2.5-coder:7b
# Also pull the smaller model for compatibility
ollama pull llama3

echo -e "\n${GREEN}Installation complete!${NC}"
echo -e "You can now run AI_MAL with: ${YELLOW}AI_MAL [options] [target]${NC}"
echo -e "For help and available options, run: ${YELLOW}AI_MAL --help${NC}"
echo
echo -e "${RED}IMPORTANT: AI_MAL requires root privileges for most features.${NC}"
echo -e "Run with sudo: ${YELLOW}sudo AI_MAL [options] [target]${NC}"
echo
echo -e "${YELLOW}Examples:${NC}"
echo "sudo AI_MAL --auto-discover --model qwen2.5-coder:7b"
echo "sudo AI_MAL 192.168.1.1 --msf --exploit"
echo "sudo AI_MAL --model llama3 (for systems with limited RAM)"
echo
echo -e "${GREEN}Thank you for installing AI_MAL!${NC}"

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
echo -e "To check if the service is already running: ${YELLOW}netstat -tuln | grep 55553${NC}"
echo ""

# Check system memory and provide recommendations for low-memory systems
MEM_GB=$(free -g | awk '/^Mem:/{print $2}')
if [ "$MEM_GB" -lt 8 ]; then
    echo -e "${YELLOW}LOW MEMORY WARNING:${NC}"
    echo -e "Your system has ${MEM_GB}GB of RAM, which may cause performance issues with Ollama models."
    echo -e "Recommendations for low-memory systems:"
    echo -e "  - Use a smaller model with --model llama3 instead of qwen2.5-coder"
    echo -e "  - Increase Ollama timeout in the code if you experience timeouts"
    echo -e "  - Consider adding a swap file if you have less than 8GB RAM"
    echo -e "  - Close other memory-intensive applications before running AI_MAL"
    echo -e ""
fi

echo -e "${RED}IMPORTANT SECURITY NOTICE:${NC}"
echo -e "This tool is designed for legitimate security testing only."
echo -e "Always ensure you have proper authorization before scanning or exploiting any network or system."
echo "" 