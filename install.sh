#!/bin/bash

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Print header
echo -e "${GREEN}AI_MAL Installation Script${NC}"
echo "================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

# Get current directory
INSTALL_DIR=$(pwd)
echo -e "${GREEN}Installing AI_MAL in: ${INSTALL_DIR}${NC}"

# Check if Kali Linux
if grep -q "Kali" /etc/os-release; then
    echo -e "${GREEN}Kali Linux detected${NC}"
else
    echo -e "${YELLOW}Warning: This script is designed for Kali Linux${NC}"
    echo -e "${YELLOW}Some features may not work properly on other distributions${NC}"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Update system
echo -e "${GREEN}Updating system...${NC}"
apt-get update

# Install required system packages
echo -e "${GREEN}Installing system dependencies...${NC}"
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
    smbclient

# Check if Nmap is installed
if ! command -v nmap &> /dev/null; then
    echo -e "${RED}Error: Nmap is not installed. Please install nmap manually.${NC}"
    exit 1
fi

# Check if Metasploit is installed
if ! command -v msfconsole &> /dev/null; then
    echo -e "${RED}Error: Metasploit Framework is not installed. Please install it manually.${NC}"
    exit 1
fi

# Check if Ollama is installed
if ! command -v ollama &> /dev/null; then
    echo -e "${GREEN}Installing Ollama...${NC}"
    curl -fsSL https://ollama.com/install.sh | sh
    
    # Start Ollama service
    systemctl enable ollama || true
    systemctl start ollama || true
    
    # Pull required models
    echo -e "${GREEN}Pulling AI models...${NC}"
    ollama pull qwen2.5-coder:7b || echo -e "${YELLOW}Failed to pull qwen2.5-coder:7b model, will try to use later${NC}"
    ollama pull mistral:7b || echo -e "${YELLOW}Failed to pull mistral:7b model, will try to use later${NC}"
    ollama pull gemma3:1b || echo -e "${YELLOW}Failed to pull gemma3:1b model, will try to use later${NC}"
fi

# Create full directory structure
echo -e "${GREEN}Creating directory structure...${NC}"
mkdir -p "${INSTALL_DIR}/ai_mal/core"
mkdir -p "${INSTALL_DIR}/ai_mal/tests"
mkdir -p "${INSTALL_DIR}/ai_mal/examples"
mkdir -p "${INSTALL_DIR}/msf_resources"
mkdir -p "${INSTALL_DIR}/scan_results"
mkdir -p "${INSTALL_DIR}/generated_scripts"
mkdir -p "${INSTALL_DIR}/logs"

# Create virtual environment
echo -e "${GREEN}Setting up Python virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo -e "${GREEN}Installing Python dependencies...${NC}"
pip install -U pip
if [ -f requirements.txt ]; then
    pip install -r requirements.txt
else
    echo -e "${RED}Error: requirements.txt not found${NC}"
    exit 1
fi

# Install Rich for the pseudo GUI interface
echo -e "${GREEN}Installing Rich library for terminal GUI...${NC}"
pip install rich

# Install package in development mode
echo -e "${GREEN}Installing AI_MAL package...${NC}"
pip install -e .

# Set up environment variables
echo -e "${GREEN}Setting up environment variables...${NC}"
cat > .env << EOL
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=qwen2.5-coder:7b
OLLAMA_FALLBACK_MODEL=mistral:7b
SCAN_RESULTS_DIR=${INSTALL_DIR}/scan_results
MSF_RESOURCES_DIR=${INSTALL_DIR}/msf_resources
GENERATED_SCRIPTS_DIR=${INSTALL_DIR}/generated_scripts
LOG_DIR=${INSTALL_DIR}/logs
EOL

# Create a wrapper script for the command-line access
echo -e "${GREEN}Creating command-line shortcut...${NC}"
cat > /usr/local/bin/AI_MAL << EOL
#!/bin/bash
# AI_MAL wrapper script
cd ${INSTALL_DIR}
source ${INSTALL_DIR}/venv/bin/activate
python ${INSTALL_DIR}/main.py "\$@"
EOL

# Make the wrapper script executable
chmod +x /usr/local/bin/AI_MAL

# Set up completion script
echo -e "${GREEN}Setting up command completion...${NC}"
if [ -d "/etc/bash_completion.d" ]; then
    cat > /etc/bash_completion.d/AI_MAL << EOL
_AI_MAL_completions()
{
    local cur=\${COMP_WORDS[COMP_CWORD]}
    COMPREPLY=( \$(compgen -W "--msf --exploit --model --fallback-model --full-auto --custom-scripts --script-type --execute-scripts --stealth --continuous --delay --services --version --os --vuln --dos --output-dir --output-format --quiet --iterations --custom-vuln --ai-analysis --no-gui" -- \$cur) )
}
complete -F _AI_MAL_completions AI_MAL
EOL
else
    echo -e "${YELLOW}Bash completion directory not found, skipping command completion setup${NC}"
fi

# Set permissions
echo -e "${GREEN}Setting permissions...${NC}"
chmod -R 755 "${INSTALL_DIR}/scan_results" "${INSTALL_DIR}/msf_resources" "${INSTALL_DIR}/generated_scripts" "${INSTALL_DIR}/logs"

# Print success message
echo -e "${GREEN}Installation completed successfully!${NC}"
echo -e "${YELLOW}Please restart your shell to enable command completion${NC}"
echo -e "${YELLOW}You can now use the 'AI_MAL' command from anywhere${NC}"
echo
echo -e "${GREEN}Example usage:${NC}"
echo "AI_MAL 192.168.1.1 --msf --exploit --model gemma3:1b --full-auto"
echo "AI_MAL 192.168.1.1 --custom-scripts --script-type python --execute-scripts"

echo ">>> Installation complete!"
echo ">>> To activate the virtual environment, run: source venv/bin/activate" 