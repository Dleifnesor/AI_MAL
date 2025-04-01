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

# Check if running on Kali Linux
if ! grep -q "Kali GNU/Linux" /etc/os-release; then
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
apt-get upgrade -y

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
    libffi-dev

# Check if Ollama is installed
if ! command -v ollama &> /dev/null; then
    echo -e "${GREEN}Installing Ollama...${NC}"
    curl -fsSL https://ollama.com/install.sh | sh
    
    # Start Ollama service
    systemctl enable ollama
    systemctl start ollama
    
    # Pull required models
    echo -e "${GREEN}Pulling AI models...${NC}"
    ollama pull qwen2.5-coder:7b
    ollama pull mistral:7b
fi

# Create virtual environment
echo -e "${GREEN}Setting up Python virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Install package in development mode
echo -e "${GREEN}Installing AI_MAL package...${NC}"
pip install -e .

# Create necessary directories
echo -e "${GREEN}Creating directories...${NC}"
mkdir -p msf_resources
mkdir -p scan_results
mkdir -p generated_scripts
mkdir -p logs

# Set up environment variables
echo -e "${GREEN}Setting up environment variables...${NC}"
cat > .env << EOL
OLLAMA_MODEL=qwen2.5-coder:7b
OLLAMA_FALLBACK_MODEL=mistral:7b
SCAN_RESULTS_DIR=scan_results
MSF_RESOURCES_DIR=msf_resources
GENERATED_SCRIPTS_DIR=generated_scripts
LOG_DIR=logs
EOL

# Create symbolic link for command-line access
echo -e "${GREEN}Creating command-line shortcut...${NC}"
ln -sf "$(pwd)/venv/bin/AI_MAL" /usr/local/bin/AI_MAL

# Set up completion script
echo -e "${GREEN}Setting up command completion...${NC}"
cat > /etc/bash_completion.d/AI_MAL << EOL
_AI_MAL_completions()
{
    local cur=\${COMP_WORDS[COMP_CWORD]}
    COMPREPLY=( \$(compgen -W "--msf --exploit --model --fallback-model --full-auto --custom-scripts --script-type --execute-scripts --stealth --continuous --delay --services --version --os --vuln --dos --output-dir --output-format --quiet --iterations --custom-vuln --ai-analysis" -- \$cur) )
}
complete -F _AI_MAL_completions AI_MAL
EOL

# Set permissions
echo -e "${GREEN}Setting permissions...${NC}"
chmod +x /usr/local/bin/AI_MAL
chmod -R 755 scan_results msf_resources generated_scripts logs

# Print success message
echo -e "${GREEN}Installation completed successfully!${NC}"
echo -e "${YELLOW}Please restart your shell to enable command completion${NC}"
echo -e "${YELLOW}You can now use the 'AI_MAL' command from anywhere${NC}"
echo
echo -e "${GREEN}Example usage:${NC}"
echo "AI_MAL 192.168.1.1 --msf --exploit --model qwen2.5-coder:7b --full-auto"
echo "AI_MAL 192.168.1.1 --custom-scripts --script-type python --execute-scripts" 