#!/bin/bash

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
    msfvenom \
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
    ollama pull gemma3:1b
fi

# Create virtual environment
echo -e "${GREEN}Setting up Python virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Install package in development mode
echo -e "${GREEN}Installing AI_MAL package...${NC}"
pip install --upgrade pip
pip install -e .

# Create necessary directories
echo -e "${GREEN}Creating directories...${NC}"
mkdir -p msf_resources
mkdir -p scan_results
mkdir -p logs

# Set up environment variables
echo -e "${GREEN}Setting up environment variables...${NC}"
cat > .env << EOL
OLLAMA_HOST=http://localhost:11434
DEFAULT_MODEL=qwen2.5-coder:7b
FALLBACK_MODEL=gemma3:1b
MSF_WORKSPACE=ai_mal_workspace
SCAN_RESULTS_DIR=scan_results
LOG_DIR=logs
EOL

# Create symbolic link for command-line access
echo -e "${GREEN}Creating command-line shortcut...${NC}"
ln -sf "$(pwd)/main.py" /usr/local/bin/AI_MAL
chmod +x /usr/local/bin/AI_MAL

# Set up completion script
echo -e "${GREEN}Setting up command completion...${NC}"
cat > /etc/bash_completion.d/AI_MAL << EOL
_ai_mal_completions()
{
    local cur=\${COMP_WORDS[COMP_CWORD]}
    local opts="--msf --exploit --model --full-auto --dos --custom-scripts --script-type --execute-scripts --timeout --max-threads --memory-limit --debug --verbose --log"
    COMPREPLY=( \$(compgen -W "\${opts}" -- \${cur}) )
}
complete -F _ai_mal_completions AI_MAL
EOL

# Print success message
echo -e "${GREEN}Installation completed successfully!${NC}"
echo -e "${YELLOW}Please restart your shell to enable command completion${NC}"
echo -e "${YELLOW}You can now use the 'AI_MAL' command from anywhere${NC}"
echo
echo -e "${GREEN}Example usage:${NC}"
echo "AI_MAL 192.168.1.1 --msf --exploit --model qwen2.5-coder:7b --full-auto"
echo "AI_MAL 192.168.1.1 --custom-scripts --script-type python --execute-scripts" 