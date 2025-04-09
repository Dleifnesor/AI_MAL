#!/bin/bash

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Set installation directory if not specified
if [ -z "$INSTALL_DIR" ]; then
    INSTALL_DIR="/opt/AI_MAL"
    echo -e "${YELLOW}>>> Using default installation directory: $INSTALL_DIR${NC}"
fi

# Create the installation directory if it doesn't exist
if [ ! -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}>>> Creating installation directory: $INSTALL_DIR${NC}"
    mkdir -p "$INSTALL_DIR"
fi

# Progress bar function
progress_bar() {
    local duration=$1
    local prefix=$2
    local size=40
    local count=0
    local progress=0
    local step=$((duration / size))
    
    printf "${prefix} ["
    while [ $count -lt $size ]; do
        printf "${BLUE}▓${NC}"
        count=$((count + 1))
        sleep $step
    done
    printf "] ${GREEN}100%%${NC}\n"
}

# Spinner function for operations without clear progress
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    printf "${2} "
    
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf "${YELLOW}[%c]${NC}" "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b"
    done
    printf "${GREEN}[✓]${NC}\n"
}

# Animated progress for longer tasks
animated_progress() {
    local message="$1"
    local duration="$2"
    local size=40
    local count=0
    local step=$((duration / size))
    
    echo -ne "${message} [${NC}"
    while [ $count -lt $size ]; do
        sleep $step
        count=$((count + 1))
        progress=$((count * 100 / size))
        
        # Different colors for different progress ranges
        if [ $progress -lt 25 ]; then
            color="${BLUE}"
        elif [ $progress -lt 50 ]; then
            color="${CYAN}"
        elif [ $progress -lt 75 ]; then
            color="${YELLOW}"
        else
            color="${GREEN}"
        fi
        
        echo -ne "${color}▓${NC}"
    done
    echo -e "] ${GREEN}Done!${NC}"
}

# Parse command line arguments
SKIP_MODELS=false
for arg in "$@"; do
  case $arg in
    --no-models)
      SKIP_MODELS=true
      shift
      ;;
  esac
done

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
        apt-get update > /dev/null 2>&1 &
        update_pid=$!
        spinner $update_pid "${CYAN}Updating package lists"

        apt-get upgrade -y > /dev/null 2>&1 &
        upgrade_pid=$!
        spinner $upgrade_pid "${CYAN}Upgrading installed packages"
        
        # Install required system packages
        echo -e "${YELLOW}>>> Installing system dependencies...${NC}"
        
        # Group packages by category for better reliability
        base_packages=(
            "python3" "python3-pip" "python3-venv" "git" "curl" "wget" 
            "build-essential" "libssl-dev" "libffi-dev"
        )
        
        network_packages=(
            "nmap" "python3-nmap" "smbclient" "libpcap-dev" "hping3"
            "libnetfilter-queue-dev" "libnetfilter-queue1" 
            "libnetfilter-conntrack-dev" "libnetfilter-conntrack3"
        )
        
        python_packages=(
            "python3-dev" "python3-setuptools" "python3-wheel"
        )
        
        additional_packages=(
            "apache2-utils" "bc"
        )
        
        # Install metasploit separately as it's the largest package
        echo -e "${YELLOW}>>> Installing Metasploit Framework (this may take a while)...${NC}"
        apt-get install -y metasploit-framework
        if [ $? -ne 0 ]; then
            echo -e "${RED}>>> Warning: Metasploit installation may have issues. Will continue with other packages.${NC}"
        else
            echo -e "${GREEN}>>> Metasploit Framework installed successfully.${NC}"
        fi
        
        # Function to install package groups with better error handling
        install_package_group() {
            local group_name=$1
            shift
            local packages=("$@")
            
            echo -e "${YELLOW}>>> Installing ${group_name} packages...${NC}"
            local total=${#packages[@]}
            local current=0
            local failed=()
            
            for package in "${packages[@]}"; do
                current=$((current + 1))
                echo -ne "${CYAN}Installing ${package} (${current}/${total}) ${NC}"
                
                # Install with timeout to prevent hanging
                timeout 300 apt-get install -y $package
                if [ $? -ne 0 ]; then
                    echo -e " ${RED}[FAILED]${NC}"
                    failed+=("$package")
                else
                    echo -e " ${GREEN}[OK]${NC}"
                fi
            done
            
            # Report any failed packages
            if [ ${#failed[@]} -gt 0 ]; then
                echo -e "${YELLOW}>>> Some packages failed to install: ${failed[*]}${NC}"
                echo -e "${YELLOW}>>> Will continue with installation anyway.${NC}"
            else
                echo -e "${GREEN}>>> All ${group_name} packages installed successfully.${NC}"
            fi
        }
        
        # Install package groups
        install_package_group "base" "${base_packages[@]}"
        install_package_group "network" "${network_packages[@]}"
        install_package_group "Python" "${python_packages[@]}"
        install_package_group "additional" "${additional_packages[@]}"

        # Verify nmap installation
        echo -e "${YELLOW}>>> Verifying nmap installation...${NC}"
        nmap_version=$(nmap --version | head -n 1)
        if [ $? -ne 0 ]; then
            echo -e "${RED}>>> Error: Nmap is not installed correctly${NC}"
            echo -e "${YELLOW}>>> Attempting to reinstall nmap...${NC}"
            suppress_output apt-get remove --purge -y nmap
            suppress_output apt-get install -y nmap
            nmap_version=$(nmap --version | head -n 1)
            if [ $? -ne 0 ]; then
                echo -e "${RED}>>> Critical Error: Could not install nmap. Scanning functionality will not work.${NC}"
            else
                echo -e "${GREEN}>>> Successfully reinstalled nmap: ${nmap_version}${NC}"
            fi
        else
            echo -e "${GREEN}>>> Nmap installed correctly: ${nmap_version}${NC}"
        fi

        # Ensure nmap has proper permissions for privileged operations
        echo -e "${YELLOW}>>> Setting proper permissions for nmap...${NC}"
        if [ -f /usr/bin/nmap ]; then
            chmod +s /usr/bin/nmap
            echo -e "${GREEN}>>> Set setuid bit on nmap to allow privileged operations${NC}"
        fi

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
            
            # Check if we should skip model downloads
            if [ "$SKIP_MODELS" = true ]; then
                echo -e "${YELLOW}>>> Skipping model downloads (--no-models flag detected)${NC}"
                echo -e "${YELLOW}>>> You will need to pull models manually later with:${NC}"
                echo -e "${GREEN}>>>   ollama pull artifish/llama3.2-uncensored${NC}"
                echo -e "${GREEN}>>>   ollama pull gemma:1b${NC}"
            else
                # Pull the specified models with progress indication
                echo -e "${YELLOW}>>> Pulling required AI models...${NC}"
                echo -e "${YELLOW}>>> This may take several minutes for large models. Please be patient.${NC}"
                echo -e "${YELLOW}>>> To skip model downloads, run the installer with --no-models${NC}"
                
                # Function to pull a model with timeout
                pull_model_with_timeout() {
                    local model=$1
                    local timeout=$2
                    local start_time=$(date +%s)
                    
                    echo -e "${YELLOW}>>> Pulling $model (timeout: ${timeout}s)...${NC}"
                    echo -ne "${CYAN}Downloading model ${NC}["
                    
                    # Start the pull in background
                    ollama pull $model > /dev/null 2>&1 &
                    local pull_pid=$!
                    
                    # Variables for progress tracking
                    local progress=0
                    local bar_size=40
                    local elapsed=0
                    local last_progress_time=$start_time
                    
                    # Monitor the process with progress updates
                    while kill -0 $pull_pid 2>/dev/null; do
                        local current_time=$(date +%s)
                        elapsed=$((current_time - start_time))
                        
                        # Calculate progress based on elapsed time and timeout
                        # This is an approximation since we don't have actual download progress
                        if [ $elapsed -lt $timeout ]; then
                            progress=$((elapsed * 90 / timeout)) # Cap at 90% during download
                        else
                            progress=90 # Cap at 90% if timeout reached
                        fi
                        
                        # Different colors based on progress
                        if [ $progress -lt 25 ]; then
                            color="${BLUE}"
                        elif [ $progress -lt 50 ]; then
                            color="${CYAN}"
                        elif [ $progress -lt 75 ]; then
                            color="${YELLOW}"
                        else
                            color="${GREEN}"
                        fi
                        
                        # Only update the display every second to reduce flickering
                        if [ $current_time -ne $last_progress_time ]; then
                            last_progress_time=$current_time
                            
                            # Calculate how many blocks to show
                            local blocks=$((progress * bar_size / 100))
                            
                            # Print progress bar
                            printf "\r${CYAN}Downloading model ${NC}["
                            for ((i=0; i<blocks; i++)); do
                                printf "${color}▓${NC}"
                            done
                            for ((i=blocks; i<bar_size; i++)); do
                                printf " "
                            done
                            printf "] ${progress}%% (${elapsed}s)"
                        fi
                        
                        # Exit if timeout reached
                        if [ $elapsed -ge $timeout ]; then
                            echo -e "\n${RED}>>> Timeout reached ($timeout seconds) for $model. Aborting pull.${NC}"
                            kill -9 $pull_pid 2>/dev/null || true
                            wait $pull_pid 2>/dev/null || true
                            return 1
                        fi
                        
                        sleep 0.2
                    done
                    
                    # Complete the progress bar to 100%
                    printf "\r${CYAN}Downloading model ${NC}["
                    for ((i=0; i<bar_size; i++)); do
                        printf "${GREEN}▓${NC}"
                    done
                    printf "] ${GREEN}100%%${NC} (${elapsed}s)\n"
                    
                    # Check if the model is now available
                    if ollama list | grep -q "$model"; then
                        echo -e "${GREEN}>>> Successfully pulled $model${NC}"
                        return 0
                    else
                        echo -e "${RED}>>> Failed to pull $model${NC}"
                        return 1
                    fi
                }

                # Try to pull the primary model with a generous timeout (10 minutes)
                if ! ollama list | grep -q "artifish/llama3.2-uncensored"; then
                    echo -e "${YELLOW}>>> Pulling primary AI model: artifish/llama3.2-uncensored${NC}"
                    echo -e "${YELLOW}>>> This is a large model and may take several minutes...${NC}"
                    if ! pull_model_with_timeout "artifish/llama3.2-uncensored" 600; then
                        echo -e "${RED}>>> Could not pull artifish/llama3.2-uncensored within the timeout period.${NC}"
                        echo -e "${YELLOW}>>> Will try to use a smaller model instead.${NC}"
                    fi
                else
                    echo -e "${GREEN}>>> Primary model artifish/llama3.2-uncensored is already available${NC}"
                fi

                # Pull the fallback model (smaller and faster to download)
                if ! ollama list | grep -q "gemma:1b"; then
                    echo -e "${YELLOW}>>> Pulling fallback AI model: gemma:1b${NC}"
                    if ! pull_model_with_timeout "gemma:1b" 300; then
                        echo -e "${RED}>>> Could not pull gemma:1b within the timeout period.${NC}"
                        echo -e "${YELLOW}>>> The AI analysis features may not work correctly.${NC}"
                    fi
                else
                    echo -e "${GREEN}>>> Fallback model gemma:1b is already available${NC}"
                fi
            fi
        else
            echo -e "${YELLOW}>>> Ollama already installed, checking for required models...${NC}"
            
            # Check if we should skip model downloads
            if [ "$SKIP_MODELS" = true ]; then
                echo -e "${YELLOW}>>> Skipping model downloads (--no-models flag detected)${NC}"
                echo -e "${YELLOW}>>> You will need to pull models manually later with:${NC}"
                echo -e "${GREEN}>>>   ollama pull artifish/llama3.2-uncensored${NC}"
                echo -e "${GREEN}>>>   ollama pull gemma:1b${NC}"
            else
                # Function to pull a model with timeout
                pull_model_with_timeout() {
                    local model=$1
                    local timeout=$2
                    local start_time=$(date +%s)
                    
                    echo -e "${YELLOW}>>> Pulling $model (timeout: ${timeout}s)...${NC}"
                    echo -ne "${CYAN}Downloading model ${NC}["
                    
                    # Start the pull in background
                    ollama pull $model > /dev/null 2>&1 &
                    local pull_pid=$!
                    
                    # Variables for progress tracking
                    local progress=0
                    local bar_size=40
                    local elapsed=0
                    local last_progress_time=$start_time
                    
                    # Monitor the process with progress updates
                    while kill -0 $pull_pid 2>/dev/null; do
                        local current_time=$(date +%s)
                        elapsed=$((current_time - start_time))
                        
                        # Calculate progress based on elapsed time and timeout
                        # This is an approximation since we don't have actual download progress
                        if [ $elapsed -lt $timeout ]; then
                            progress=$((elapsed * 90 / timeout)) # Cap at 90% during download
                        else
                            progress=90 # Cap at 90% if timeout reached
                        fi
                        
                        # Different colors based on progress
                        if [ $progress -lt 25 ]; then
                            color="${BLUE}"
                        elif [ $progress -lt 50 ]; then
                            color="${CYAN}"
                        elif [ $progress -lt 75 ]; then
                            color="${YELLOW}"
                        else
                            color="${GREEN}"
                        fi
                        
                        # Only update the display every second to reduce flickering
                        if [ $current_time -ne $last_progress_time ]; then
                            last_progress_time=$current_time
                            
                            # Calculate how many blocks to show
                            local blocks=$((progress * bar_size / 100))
                            
                            # Print progress bar
                            printf "\r${CYAN}Downloading model ${NC}["
                            for ((i=0; i<blocks; i++)); do
                                printf "${color}▓${NC}"
                            done
                            for ((i=blocks; i<bar_size; i++)); do
                                printf " "
                            done
                            printf "] ${progress}%% (${elapsed}s)"
                        fi
                        
                        # Exit if timeout reached
                        if [ $elapsed -ge $timeout ]; then
                            echo -e "\n${RED}>>> Timeout reached ($timeout seconds) for $model. Aborting pull.${NC}"
                            kill -9 $pull_pid 2>/dev/null || true
                            wait $pull_pid 2>/dev/null || true
                            return 1
                        fi
                        
                        sleep 0.2
                    done
                    
                    # Complete the progress bar to 100%
                    printf "\r${CYAN}Downloading model ${NC}["
                    for ((i=0; i<bar_size; i++)); do
                        printf "${GREEN}▓${NC}"
                    done
                    printf "] ${GREEN}100%%${NC} (${elapsed}s)\n"
                    
                    # Check if the model is now available
                    if ollama list | grep -q "$model"; then
                        echo -e "${GREEN}>>> Successfully pulled $model${NC}"
                        return 0
                    else
                        echo -e "${RED}>>> Failed to pull $model${NC}"
                        return 1
                    fi
                }
                
                # Check if models are available
                if ! ollama list | grep -q "artifish/llama3.2-uncensored"; then
                    echo -e "${YELLOW}>>> Pulling primary AI model: artifish/llama3.2-uncensored${NC}"
                    echo -e "${YELLOW}>>> This is a large model and may take several minutes...${NC}"
                    if ! pull_model_with_timeout "artifish/llama3.2-uncensored" 600; then
                        echo -e "${RED}>>> Could not pull artifish/llama3.2-uncensored within the timeout period.${NC}"
                        echo -e "${YELLOW}>>> Will try to use a smaller model instead.${NC}"
                    fi
                else
                    echo -e "${GREEN}>>> Primary model artifish/llama3.2-uncensored is already available${NC}"
                fi
                
                if ! ollama list | grep -q "gemma:1b"; then
                    echo -e "${YELLOW}>>> Pulling fallback AI model: gemma:1b${NC}"
                    if ! pull_model_with_timeout "gemma:1b" 300; then
                        echo -e "${RED}>>> Could not pull gemma:1b within the timeout period.${NC}"
                        echo -e "${YELLOW}>>> The AI analysis features may not work correctly.${NC}"
                    fi
                else
                    echo -e "${GREEN}>>> Fallback model gemma:1b is already available${NC}"
                fi
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
        
        # Check network interfaces
        echo -e "${YELLOW}>>> Checking network interfaces...${NC}"
        primary_interface=$(ip route get 8.8.8.8 2>/dev/null | grep -oP "dev \K\S+")
        if [ -z "$primary_interface" ]; then
            echo -e "${RED}>>> Warning: Could not determine primary network interface${NC}"
            echo -e "${YELLOW}>>> Available interfaces:${NC}"
            ip link show | grep -E '^[0-9]+: ' | cut -d: -f2 | tr -d ' '
            echo -e "${YELLOW}>>> You may need to configure a network interface manually${NC}"
        else
            echo -e "${GREEN}>>> Primary network interface: ${primary_interface}${NC}"
            ip_addr=$(ip -f inet addr show $primary_interface | grep -oP 'inet \K[\d.]+')
            if [ -z "$ip_addr" ]; then
                echo -e "${RED}>>> Warning: No IPv4 address found on primary interface${NC}"
                echo -e "${YELLOW}>>> You may need to configure network settings manually${NC}"
            else
                echo -e "${GREEN}>>> Your primary IP address: ${ip_addr}${NC}"
                echo -e "${GREEN}>>> Network is properly configured${NC}"
            fi
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
directories=(
    "logs" "scan_results" "msf_resources" "generated_scripts" 
    "workspaces" "exfiltrated_data" "implant_logs"
)

echo -ne "${CYAN}Setting up directories ${NC}["
total=${#directories[@]}
current=0
for dir in "${directories[@]}"; do
    mkdir -p $dir 2>/dev/null
    
    # Ensure proper permissions for script execution
    if [ "$dir" = "generated_scripts" ]; then
        echo -e "${YELLOW}>>> Setting execution permissions for generated scripts directory...${NC}"
        chmod -R 755 "$dir"
        chown -R "$REAL_USER:$REAL_USER" "$dir" 2>/dev/null || true
    fi
    
    current=$((current + 1))
    progress=$((current * 40 / total))
    
    # Print progress bar
    printf "\r${CYAN}Setting up directories ${NC}["
    for ((i=0; i<progress; i++)); do
        printf "${GREEN}▓${NC}"
    done
    for ((i=progress; i<40; i++)); do
        printf " "
    done
    printf "] ${GREEN}%d/%d${NC}" $current $total
done
printf "\n"

# Verify script directories
echo -e "${YELLOW}>>> Verifying script directories...${NC}"
if [ -d "generated_scripts" ]; then
    echo -e "${GREEN}>>> Script directory exists and is ready${NC}"
    # Test write permissions
    touch "generated_scripts/test_permissions.txt" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}>>> Script directory is writable${NC}"
        rm "generated_scripts/test_permissions.txt"
    else
        echo -e "${RED}>>> Script directory is not writable. Fixing permissions...${NC}"
        sudo chmod -R 755 "generated_scripts"
        sudo chown -R "$REAL_USER:$REAL_USER" "generated_scripts" 2>/dev/null || true
    fi
else
    echo -e "${RED}>>> Script directory does not exist. Creating it...${NC}"
    mkdir -p "generated_scripts"
    chmod -R 755 "generated_scripts"
    chown -R "$REAL_USER:$REAL_USER" "generated_scripts" 2>/dev/null || true
fi

# Create virtual environment
echo -e "${YELLOW}>>> Creating virtual environment...${NC}"
animated_progress "${CYAN}Setting up Python virtual environment" 3
python3 -m venv venv > /dev/null 2>&1
echo -e "${GREEN}>>> Virtual environment created${NC}"
source venv/bin/activate

# Install dependencies
echo -e "${YELLOW}>>> Installing dependencies...${NC}"
echo -e "${CYAN}Upgrading pip...${NC}"
pip3 install --upgrade pip > /dev/null 2>&1 &
pip_pid=$!
spinner $pip_pid "${CYAN}Upgrading pip"

echo -e "${CYAN}Installing project dependencies...${NC}"

# Create a temporary cleaned requirements file
temp_req=$(mktemp)
grep -v '^\s*$\|^\s*\#' requirements.txt | sed '/^$/d' > "$temp_req"

# Count the number of valid packages
req_count=$(wc -l < "$temp_req")
echo -ne "${CYAN}Installing packages ${NC}["

count=0
while IFS= read -r line || [[ -n "$line" ]]; do
    # Skip empty lines and comments
    if [[ -z "$line" || "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]]; then
        continue
    fi
    
    # Clean the line of any leading/trailing whitespace
    line=$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    
    # Skip if the line is empty after cleaning
    if [[ -z "$line" ]]; then
        continue
    fi
    
    # Extract package name for progress tracking
    package_name=$(echo "$line" | cut -d'>' -f1 | cut -d'=' -f1 | cut -d'<' -f1 | sed 's/[[:space:]]*$//')
    
    # Install the package with error handling
    if ! pip3 install "$line" > /dev/null 2>&1; then
        echo -e "\n${RED}>>> Error installing package: $package_name${NC}"
        echo -e "${YELLOW}>>> Attempting to install with verbose output...${NC}"
        pip3 install "$line"
        if [ $? -ne 0 ]; then
            echo -e "${RED}>>> Failed to install package: $package_name${NC}"
            echo -e "${YELLOW}>>> Continuing with remaining packages...${NC}"
        fi
    fi
    
    # Update progress
    count=$((count + 1))
    progress=$((count * 40 / req_count))
    percent=$((count * 100 / req_count))
    
    # Different colors based on progress
    if [ $percent -lt 25 ]; then
        color="${BLUE}"
    elif [ $percent -lt 50 ]; then
        color="${CYAN}"
    elif [ $percent -lt 75 ]; then
        color="${YELLOW}"
    else
        color="${GREEN}"
    fi
    
    # Update progress bar
    printf "\r${CYAN}Installing packages ${NC}["
    for ((i=0; i<progress; i++)); do
        printf "${color}▓${NC}"
    done
    for ((i=progress; i<40; i++)); do
        printf " "
    done
    printf "] ${percent}%%"
    
done < "$temp_req"
printf "\n"

# Clean up temporary file
rm "$temp_req"

# Verify all packages were installed
echo -e "${YELLOW}>>> Verifying package installation...${NC}"
missing_packages=0
while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ -z "$line" || "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]]; then
        continue
    fi
    
    package_name=$(echo "$line" | cut -d'>' -f1 | cut -d'=' -f1 | cut -d'<' -f1 | sed 's/[[:space:]]*$//')
    if [[ -z "$package_name" ]]; then
        continue
    fi
    
    if ! pip3 show "$package_name" > /dev/null 2>&1; then
        echo -e "${RED}>>> Package not installed: $package_name${NC}"
        missing_packages=$((missing_packages + 1))
    fi
done < requirements.txt

if [ $missing_packages -gt 0 ]; then
    echo -e "${YELLOW}>>> $missing_packages packages failed to install. Attempting to install them individually...${NC}"
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ -z "$line" || "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]]; then
            continue
        fi
        
        package_name=$(echo "$line" | cut -d'>' -f1 | cut -d'=' -f1 | cut -d'<' -f1 | sed 's/[[:space:]]*$//')
        if [[ -z "$package_name" ]]; then
            continue
        fi
        
        if ! pip3 show "$package_name" > /dev/null 2>&1; then
            echo -e "${YELLOW}>>> Retrying installation of $package_name...${NC}"
            pip3 install "$line" --no-cache-dir
        fi
    done < requirements.txt
fi

# Install AI_MAL package
echo -e "${YELLOW}>>> Installing AI_MAL package...${NC}"
animated_progress "${CYAN}Installing AI_MAL" 2
if ! pip3 install -e . > /dev/null 2>&1; then
    echo -e "${RED}>>> Error installing AI_MAL package. Retrying with verbose output...${NC}"
    pip3 install -e .
    if [ $? -ne 0 ]; then
        echo -e "${RED}>>> Failed to install AI_MAL package. Please check the error messages above.${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}>>> AI_MAL package installed${NC}"

# Set permissions
echo -e "${YELLOW}>>> Setting permissions...${NC}"
chmod -R 755 "$INSTALL_DIR"
chown -R "$REAL_USER:$REAL_USER" "$INSTALL_DIR" 2>/dev/null || true

# Check Metasploit service
echo -e "${YELLOW}>>> Checking Metasploit service...${NC}"
if ! systemctl is-active --quiet postgresql; then
    echo -e "${YELLOW}>>> Starting PostgreSQL for Metasploit...${NC}"
    systemctl enable postgresql
    systemctl start postgresql
fi

# Initialize Metasploit database if needed
echo -e "${YELLOW}>>> Initializing Metasploit database...${NC}"
if ! pgrep -f msfrpcd > /dev/null; then
    msfdb init > /dev/null 2>&1
fi

# Create systemd service for persistence
echo -e "${YELLOW}>>> Creating systemd service for persistence...${NC}"
cat > /etc/systemd/system/metasploit.service << EOF
[Unit]
Description=Metasploit Framework
After=network.target postgresql.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/msfrpcd -P password -S -f
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable metasploit.service

# Configure sudoers permissions for AI_MAL
echo -e "${YELLOW}>>> Configuring sudoers permissions for AI_MAL...${NC}"
if [ ! -z "$SUDO_USER" ]; then
    echo "$SUDO_USER ALL=(ALL) NOPASSWD: /usr/bin/nmap" | sudo tee -a /etc/sudoers.d/ai_mal > /dev/null
    chmod 440 /etc/sudoers.d/ai_mal
fi

# Create bash completion for AI_MAL
echo -e "${YELLOW}>>> Creating bash completion for AI_MAL...${NC}"
cat > /etc/bash_completion.d/ai_mal << 'EOF'
_AI_MAL_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="--help --version --target --ports --scan-type --output --verbose --quiet --msf --exploit --vuln --os --services --full-auto"

    if [[ ${cur} == -* ]] ; then
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi
}
complete -F _AI_MAL_completion AI_MAL
EOF

# Make AI_MAL immediately available in current session
echo -e "${YELLOW}>>> Making AI_MAL immediately available in current session...${NC}"

# Create system-wide environment setup
echo -e "${YELLOW}>>> Creating system-wide environment setup...${NC}"
cat > /etc/profile.d/ai_mal_env.sh << 'EOF'
#!/bin/bash
# AI_MAL system-wide environment setup
export PATH="/home/kali/AI_MAL/venv/bin:$PATH"
export AI_MAL_HOME="/home/kali/AI_MAL"
alias AI_MAL='cd $AI_MAL_HOME && source venv/bin/activate && python -m AI_MAL.main'
EOF

chmod 644 /etc/profile.d/ai_mal_env.sh

# Create a system-wide executable
echo -e "${YELLOW}>>> Creating system-wide executable...${NC}"
cat > /usr/bin/AI_MAL << 'EOF'
#!/bin/bash
# AI_MAL system-wide executable
cd /home/kali/AI_MAL
source venv/bin/activate
exec python -m AI_MAL.main "$@"
EOF

chmod +x /usr/bin/AI_MAL

# Create a backup executable in /usr/local/bin
echo -e "${YELLOW}>>> Creating backup executable...${NC}"
cat > /usr/local/bin/AI_MAL << 'EOF'
#!/bin/bash
# Backup AI_MAL executable
cd /home/kali/AI_MAL
source venv/bin/activate
exec python -m AI_MAL.main "$@"
EOF

chmod +x /usr/local/bin/AI_MAL

# Create a systemd service to ensure environment is set up at boot
echo -e "${YELLOW}>>> Creating systemd service for environment setup...${NC}"
cat > /etc/systemd/system/ai_mal_env.service << 'EOF'
[Unit]
Description=AI_MAL Environment Setup
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'source /etc/profile.d/ai_mal_env.sh'
ExecStop=/bin/true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ai_mal_env.service

# Create a shell function that will be immediately available
echo -e "${YELLOW}>>> Creating shell function for immediate use...${NC}"
cat > /etc/profile.d/ai_mal_function.sh << 'EOF'
#!/bin/bash
function AI_MAL() {
    cd /home/kali/AI_MAL
    source venv/bin/activate
    python -m AI_MAL.main "$@"
}
export -f AI_MAL
EOF

chmod 644 /etc/profile.d/ai_mal_function.sh

# Source the environment and function in the current shell
source /etc/profile.d/ai_mal_env.sh
source /etc/profile.d/ai_mal_function.sh

# Add to PATH for current session
export PATH="/home/kali/AI_MAL/venv/bin:$PATH"

# Test the nmap functionality
echo -e "${YELLOW}>>> Testing nmap functionality...${NC}"
echo -e "${YELLOW}>>> Running a quick scan of localhost to verify nmap works...${NC}"
echo -ne "${CYAN}Running test scan ${NC}["
( nmap -sT -p 22,80 -T4 --privileged -Pn 127.0.0.1 > /tmp/nmap_test.log 2>&1 ) &
scan_pid=$!

# Show animated progress bar while scan is running
bar_size=40
count=0
while kill -0 $scan_pid 2>/dev/null; do
    # Calculate progress - this is just visual, not actual progress
    count=$((count + 1))
    if [ $count -gt $bar_size ]; then
        count=0
        # Clear bar and start again
        printf "\r${CYAN}Running test scan ${NC}["
        for ((i=0; i<bar_size; i++)); do
            printf " "
        done
        printf "]"
    fi
    
    # Print the progress bar with "filling" effect
    printf "\r${CYAN}Running test scan ${NC}["
    for ((i=0; i<count; i++)); do
        printf "${BLUE}▓${NC}"
    done
    for ((i=count; i<bar_size; i++)); do
        printf " "
    done
    printf "]"
    
    sleep 0.1
done

# Wait for scan to complete
wait $scan_pid
scan_status=$?

# Print complete progress bar
printf "\r${CYAN}Running test scan ${NC}["
for ((i=0; i<bar_size; i++)); do
    printf "${GREEN}▓${NC}"
done
printf "] ${GREEN}Done!${NC}\n"

if [ $scan_status -eq 0 ]; then
    echo -e "${GREEN}>>> Nmap test scan completed successfully${NC}"
    # Check if scan output contains expected elements
    if grep -q "scan report" /tmp/nmap_test.log && grep -q "Host is up" /tmp/nmap_test.log; then
        echo -e "${GREEN}>>> Nmap scan output looks valid${NC}"
    else
        echo -e "${YELLOW}>>> Nmap ran but output may not be complete. Check permissions.${NC}"
    fi
else
    echo -e "${RED}>>> Nmap test scan failed. Scanning may not work properly.${NC}"
    echo -e "${YELLOW}>>> Error details:${NC}"
    cat /tmp/nmap_test.log
fi
rm -f /tmp/nmap_test.log

echo -e "${GREEN}>>> Installation complete!${NC}"
echo -e "${GREEN}>>> You can now run AI_MAL from anywhere with: AI_MAL <target> [options]${NC}"
echo -e "${GREEN}>>> For example: AI_MAL 192.168.1.1 --msf --exploit --full-auto --vuln${NC}"

if [ "$SKIP_MODELS" = true ]; then
    echo -e "${YELLOW}>>> Note: AI models were not installed. For AI features to work, please run:${NC}"
    echo -e "${GREEN}>>>   ollama pull artifish/llama3.2-uncensored${NC}"
    echo -e "${GREEN}>>>   ollama pull gemma:1b${NC}"
else
    echo -e "${GREEN}>>> Ollama is installed and configured with artifish/llama3.2-uncensored model${NC}"
fi

# Suggestion to use when install completes
echo -e "${YELLOW}>>> TIP: To test AI_MAL, try running:${NC}"
echo -e "${GREEN}>>>   AI_MAL 127.0.0.1 --vuln --os --services${NC}"

# Display a fancy completion animation
echo ""
echo -ne "${YELLOW}▄${NC}"
sleep 0.05
for i in {1..40}; do
    echo -ne "${YELLOW}▄${NC}"
    sleep 0.01
done
echo ""

echo -e "${GREEN} ✓ Installation Complete! ${NC}"
echo -e "${CYAN} AI_MAL is now ready to use ${NC}"

echo -ne "${YELLOW}▀${NC}"
sleep 0.05
for i in {1..40}; do
    echo -ne "${YELLOW}▀${NC}"
    sleep 0.01
done
echo "" 