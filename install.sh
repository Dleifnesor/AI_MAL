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
# Install required system packages
apt install -y python3 python3-pip nmap metasploit-framework dos2unix

echo -e "\n${GREEN}Step 2: Setting up Python virtual environment...${NC}"
# Install python3-venv if not already installed
if ! dpkg -l | grep -q python3-venv; then
  echo "Installing python3-venv package..."
  apt install -y python3-venv
fi

# Create virtual environment
echo "Creating Python virtual environment at $INSTALL_DIR/venv..."
python3 -m venv $INSTALL_DIR/venv

# Activate virtual environment
source $INSTALL_DIR/venv/bin/activate

# Install Python dependencies in the virtual environment
echo -e "Installing Python packages in virtual environment..."
# Upgrade pip first
pip install --upgrade pip

# Install packages one by one to better handle errors
echo "Installing python-nmap..."
pip install python-nmap

echo "Installing requests..."
pip install requests

echo "Installing pymetasploit3..."
pip install pymetasploit3

echo "Installing psutil..."
pip install psutil

echo "Installing netifaces..."
pip install netifaces

# Verify pymetasploit3 installation
echo -e "\n${YELLOW}Verifying pymetasploit3 installation...${NC}"
if ! python -c "from pymetasploit3.msfrpc import MsfRpcClient; print('pymetasploit3 correctly installed')" 2>/dev/null; then
  echo -e "${RED}Warning: pymetasploit3 not properly installed. Trying alternative method...${NC}"
  pip uninstall -y pymetasploit3
  pip install --force-reinstall pymetasploit3
  
  # Verify again
  if ! python -c "from pymetasploit3.msfrpc import MsfRpcClient; print('pymetasploit3 correctly installed')" 2>/dev/null; then
    echo -e "${RED}Error: Could not properly install pymetasploit3.${NC}"
    echo "You may need to manually fix this issue before using Metasploit integration."
  else
    echo -e "${GREEN}pymetasploit3 successfully installed!${NC}"
  fi
else
  echo -e "${GREEN}pymetasploit3 correctly installed!${NC}"
fi

# Create a wrapper script to activate the virtual environment
echo "Creating virtual environment wrapper..."
cat > $INSTALL_DIR/venv_wrapper.sh << EOL
#!/bin/bash
# This script activates the virtual environment and runs the given command
source $INSTALL_DIR/venv/bin/activate
exec "\$@"
EOL
chmod +x $INSTALL_DIR/venv_wrapper.sh

# Deactivate virtual environment
deactivate

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
echo "Installing Ollama (this may take a moment)..."

# Use the official installer but redirect the output to a log file
echo "Downloading and installing Ollama..."
curl -fsSL https://ollama.com/install.sh | sh > /tmp/ollama_install.log 2>&1
INSTALL_STATUS=$?

# Check if installation was successful based on the exit code
if [ $INSTALL_STATUS -ne 0 ] || ! command -v ollama &>/dev/null; then
  echo -e "${RED}Error: Ollama installation failed.${NC}"
  echo "Please check the installation log at /tmp/ollama_install.log"
  echo "You may need to install Ollama manually by following instructions at: https://ollama.com/download"
else
  echo -e "${GREEN}Ollama successfully installed!${NC}"
fi

# Ensure Ollama service is started and running
echo -e "\n${GREEN}Starting Ollama service...${NC}"
# Check if Ollama is already running
if pgrep ollama >/dev/null; then
  echo "Ollama is already running."
else
  # For systems with systemd
  if command -v systemctl >/dev/null && systemctl list-unit-files | grep -q ollama; then
    echo "Starting Ollama using systemd..."
    systemctl enable ollama
    systemctl start ollama
  else
    # For systems without systemd or where Ollama doesn't register as a service
    echo "Starting Ollama manually..."
    nohup ollama serve > /var/log/ollama.log 2>&1 &
    echo "Ollama started with PID: $!"
  fi
fi

# Verify Ollama is accessible
echo "Verifying Ollama API is accessible..."
MAX_RETRIES=10
RETRY_DELAY=2
retry_count=0

while [ $retry_count -lt $MAX_RETRIES ]; do
  if curl -s -o /dev/null -w "%{http_code}" http://localhost:11434/ | grep -q "200"; then
    echo -e "${GREEN}Ollama API is up and running!${NC}"
    break
  else
    echo -e "${YELLOW}Waiting for Ollama API to become available... (${retry_count}/${MAX_RETRIES})${NC}"
    sleep $RETRY_DELAY
    retry_count=$((retry_count + 1))
  fi
done

if [ $retry_count -eq $MAX_RETRIES ]; then
  echo -e "${RED}Warning: Could not verify Ollama API is running. You may need to start it manually with 'ollama serve'.${NC}"
fi

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

# Check if Ollama API is accessible before trying to pull models
if curl -s -o /dev/null -w "%{http_code}" http://localhost:11434/ | grep -q "200"; then
  # Pull the primary model: qwen2.5-coder:7b
  echo "Pulling qwen2.5-coder:7b model (this may take 5-10 minutes)..."
  ollama pull qwen2.5-coder:7b > /tmp/ollama_pull_qwen.log 2>&1 &
  QWEN_PID=$!
  
  # Show a simple progress indicator while pulling qwen model
  echo -n "Downloading qwen2.5-coder:7b model: "
  while kill -0 $QWEN_PID 2>/dev/null; do
    echo -n "."
    sleep 2
  done
  echo " Done!"
  
  # Also pull the smaller model for compatibility with limited resources
  echo "Pulling gemma3:1b model as a backup for systems with limited resources..."
  ollama pull gemma3:1b > /tmp/ollama_pull_gemma.log 2>&1 &
  GEMMA_PID=$!
  
  # Show a simple progress indicator while pulling gemma model
  echo -n "Downloading gemma3:1b model: "
  while kill -0 $GEMMA_PID 2>/dev/null; do
    echo -n "."
    sleep 2
  done
  echo " Done!"
  
  # Verify models are available
  echo "Verifying models are accessible..."
  MODEL_STATUS=0
  
  if ollama list | grep -q "qwen2.5-coder:7b"; then
    echo -e "${GREEN}✓ Successfully installed qwen2.5-coder:7b model!${NC}"
  else
    echo -e "${YELLOW}⚠ Warning: qwen2.5-coder:7b model may not have been installed correctly.${NC}"
    echo "You can try installing it manually with: ollama pull qwen2.5-coder:7b"
    MODEL_STATUS=1
  fi
  
  if ollama list | grep -q "gemma3:1b"; then
    echo -e "${GREEN}✓ Successfully installed gemma3:1b model!${NC}"
  else
    echo -e "${YELLOW}⚠ Warning: gemma3:1b model may not have been installed correctly.${NC}"
    echo "You can try installing it manually with: ollama pull gemma3:1b"
    MODEL_STATUS=1
  fi
  
  if [ $MODEL_STATUS -eq 0 ]; then
    echo -e "${GREEN}All models successfully installed!${NC}"
  fi
else
  echo -e "${RED}Warning: Ollama API is not accessible. Could not pull models.${NC}"
  echo "You will need to manually pull the models after starting Ollama:"
  echo "  ollama pull qwen2.5-coder:7b"
  echo "  ollama pull gemma3:1b"
fi

echo -e "\n${GREEN}Step 7: Setting up autostart services...${NC}"
echo "Creating systemd service to automatically start Ollama and Metasploit on system boot..."

# Create AI_MAL autostart service file
cat > /etc/systemd/system/ai_mal_deps.service << EOL
[Unit]
Description=AI_MAL Dependencies Service
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c "systemctl start msfrpcd.service"
ExecStart=/bin/bash -c "if command -v systemctl &>/dev/null && systemctl list-unit-files | grep -q ollama; then systemctl start ollama.service; else nohup ollama serve > /var/log/ollama.log 2>&1 & fi"
ExecStop=/bin/bash -c "systemctl stop msfrpcd.service"
ExecStop=/bin/bash -c "if command -v systemctl &>/dev/null && systemctl list-unit-files | grep -q ollama; then systemctl stop ollama.service; else pkill -f 'ollama serve'; fi"

[Install]
WantedBy=multi-user.target
EOL

# Enable the service to start on boot
systemctl daemon-reload
systemctl enable ai_mal_deps.service
systemctl start ai_mal_deps.service

# Verify the service is active
if systemctl is-active --quiet ai_mal_deps.service; then
  echo -e "${GREEN}AI_MAL dependencies autostart service successfully installed and activated!${NC}"
  echo "The service will automatically start Ollama and Metasploit RPC on system boot."
else
  echo -e "${YELLOW}Warning: AI_MAL dependencies autostart service installation may have failed.${NC}"
  echo "You may need to manually start Ollama and Metasploit each time the system boots."
fi

# Add autostart info to installation completion message
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
echo "sudo AI_MAL --model gemma3:1b (for systems with limited RAM)"
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

# Check system memory and provide recommendations for low-memory systems
MEM_GB=$(free -g | awk '/^Mem:/{print $2}')
if [ "$MEM_GB" -lt 8 ]; then
    echo -e "${YELLOW}LOW MEMORY WARNING:${NC}"
    echo -e "Your system has ${MEM_GB}GB of RAM, which may cause performance issues with Ollama models."
    echo -e "Recommendations for low-memory systems:"
    echo -e "  - Use a smaller model with --model gemma3:1b instead of qwen2.5-coder:7b"
    echo -e "  - Increase Ollama timeout in the code if you experience timeouts"
    echo -e "  - Consider adding a swap file if you have less than 8GB RAM"
    echo -e "  - Close other memory-intensive applications before running AI_MAL"
    echo -e ""
fi

echo -e "${RED}IMPORTANT SECURITY NOTICE:${NC}"
echo -e "This tool is designed for legitimate security testing only."
echo -e "Always ensure you have proper authorization before scanning or exploiting any network or system."
echo ""

echo -e "${GREEN}Autostart Status:${NC}"
echo -e "  Ollama and Metasploit RPC will start automatically on system boot."
echo -e "  To disable autostart: ${YELLOW}sudo systemctl disable ai_mal_deps.service${NC}"
echo -e "  To manually start dependencies: ${YELLOW}sudo systemctl start ai_mal_deps.service${NC}"
echo -e "" 