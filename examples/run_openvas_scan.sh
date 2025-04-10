#!/bin/bash

# Run OpenVAS scan using AI_MAL
# This script demonstrates how to run OpenVAS scans from the command line

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check if target IP is provided
if [ $# -lt 1 ]; then
    echo -e "${RED}Error: No target IP specified${NC}"
    echo "Usage: $0 <target_ip> [options]"
    exit 1
fi

TARGET=$1
shift # Remove the target from the arguments

# Display banner
echo -e "${CYAN}=======================================================${NC}"
echo -e "${CYAN}      AI_MAL OpenVAS Vulnerability Scanner${NC}"
echo -e "${CYAN}=======================================================${NC}"
echo -e "${YELLOW}Target:${NC} $TARGET"
echo -e "${YELLOW}Date:${NC} $(date)"
echo -e "${CYAN}=======================================================${NC}"

# Check if OpenVAS is installed
if ! command -v openvas &> /dev/null; then
    echo -e "${RED}Error: OpenVAS is not installed.${NC}"
    echo -e "${YELLOW}Do you want to install OpenVAS now? (y/n)${NC}"
    read -r install_choice
    
    if [[ "$install_choice" == "y" || "$install_choice" == "Y" ]]; then
        echo -e "${CYAN}Installing OpenVAS. This may take a while...${NC}"
        sudo apt-get update
        sudo apt-get install -y openvas gvm redis
        sudo gvm-setup
        sudo systemctl start redis-server@openvas
        sudo systemctl start gvmd
        sudo systemctl start ospd-openvas
        sudo systemctl start gsad
    else
        echo -e "${RED}OpenVAS installation aborted. Cannot continue.${NC}"
        exit 1
    fi
fi

# Check if OpenVAS services are running
if ! ps aux | grep -q "[g]vmd" || ! ps aux | grep -q "[o]spd-openvas"; then
    echo -e "${YELLOW}OpenVAS services are not running. Starting services...${NC}"
    sudo systemctl start redis-server@openvas
    sudo systemctl start gvmd
    sudo systemctl start ospd-openvas
    sudo systemctl start gsad
    
    # Wait for services to start
    echo -e "${YELLOW}Waiting for services to start...${NC}"
    sleep 10
fi

# Create results directory
RESULTS_DIR="scan_results"
mkdir -p "$RESULTS_DIR"
echo -e "${GREEN}Results will be saved to: $RESULTS_DIR${NC}"

# Run the scan using AI_MAL
echo -e "${CYAN}Starting OpenVAS scan against $TARGET...${NC}"
echo -e "${YELLOW}This may take several minutes depending on the scan configuration.${NC}"

# Command construction
CMD="python -m AI_MAL.openvas_scan $TARGET --output-dir $RESULTS_DIR $@"
echo -e "${CYAN}Running command: $CMD${NC}"
echo -e "${CYAN}=======================================================${NC}"

# Execute the command
eval "$CMD"

# Check exit status
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Scan completed successfully!${NC}"
    echo -e "${GREEN}Results saved to $RESULTS_DIR${NC}"
else
    echo -e "${RED}Scan encountered errors. Check the logs for details.${NC}"
fi

echo -e "${CYAN}=======================================================${NC}" 