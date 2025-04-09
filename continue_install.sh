#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${YELLOW}>>> Continuing AI_MAL installation...${NC}"

# Function to install a single package with direct output
install_package() {
    echo -e "${CYAN}Installing $1...${NC}"
    apt-get install -y $1
    if [ $? -ne 0 ]; then
        echo -e "${RED}>>> Failed to install $1${NC}"
        return 1
    else
        echo -e "${GREEN}>>> Successfully installed $1${NC}"
        return 0
    fi
}

# Install remaining packages one by one
echo -e "${YELLOW}>>> Installing remaining required packages...${NC}"

# Network packages
network_packages=(
    "nmap" "python3-nmap" "smbclient" "libpcap-dev" "hping3"
    "libnetfilter-queue-dev" "libnetfilter-queue1" 
    "libnetfilter-conntrack-dev" "libnetfilter-conntrack3"
)

for package in "${network_packages[@]}"; do
    install_package "$package"
done

# Python packages
python_packages=(
    "python3-dev" "python3-setuptools" "python3-wheel"
)

for package in "${python_packages[@]}"; do
    install_package "$package"
done

# Additional packages
additional_packages=(
    "apache2-utils" "bc"
)

for package in "${additional_packages[@]}"; do
    install_package "$package"
done

# Install Metasploit separately as it's the largest package
echo -e "${YELLOW}>>> Installing Metasploit Framework...${NC}"
apt-get install -y metasploit-framework

# Skip to Python environment setup
echo -e "${YELLOW}>>> Setting up Python environment...${NC}"

# Create necessary directories
echo -e "${YELLOW}>>> Creating necessary directories...${NC}"
directories=(
    "logs" "scan_results" "msf_resources" "generated_scripts" 
    "workspaces" "exfiltrated_data" "implant_logs"
)

for dir in "${directories[@]}"; do
    mkdir -p $dir 2>/dev/null
    echo -e "${GREEN}>>> Created directory: $dir${NC}"
    
    # Ensure proper permissions for script execution
    if [ "$dir" = "generated_scripts" ]; then
        echo -e "${YELLOW}>>> Setting execution permissions for generated scripts directory...${NC}"
        chmod -R 755 "$dir"
    fi
done

# Create virtual environment
echo -e "${YELLOW}>>> Creating virtual environment...${NC}"
python3 -m venv venv
echo -e "${GREEN}>>> Virtual environment created${NC}"
source venv/bin/activate

# Install dependencies
echo -e "${YELLOW}>>> Installing Python dependencies...${NC}"
pip3 install --upgrade pip

# Install the package
echo -e "${YELLOW}>>> Installing AI_MAL package...${NC}"
pip3 install -e .

echo -e "${GREEN}>>> Installation continued successfully!${NC}"
echo -e "${YELLOW}>>> You can now run the main installer again to complete the process:${NC}"
echo -e "${GREEN}>>> ./install.sh${NC}" 