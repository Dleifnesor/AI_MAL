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
        echo -ne "${CYAN}Installing required packages ${NC}["
        packages=(
            "python3" "python3-pip" "python3-venv" "git" "nmap" "metasploit-framework" 
            "curl" "wget" "build-essential" "libssl-dev" "libffi-dev" "python3-nmap" 
            "smbclient" "libpcap-dev" "libnetfilter-queue-dev" "libnetfilter-queue1" 
            "libnetfilter-conntrack-dev" "libnetfilter-conntrack3" "python3-dev" 
            "python3-setuptools" "python3-wheel" "hping3" "apache2-utils" "bc"
        )

        total=${#packages[@]}
        current=0
        for package in "${packages[@]}"; do
            apt-get install -y $package > /dev/null 2>&1
            current=$((current + 1))
            progress=$((current * 40 / total))
            completed=$((current * 100 / total))
            
            # Different colors based on progress
            if [ $completed -lt 25 ]; then
                color="${BLUE}"
            elif [ $completed -lt 50 ]; then
                color="${CYAN}"
            elif [ $completed -lt 75 ]; then
                color="${YELLOW}"
            else
                color="${GREEN}"
            fi
            
            # Print progress bar
            printf "\r${CYAN}Installing required packages ${NC}["
            for ((i=0; i<progress; i++)); do
                printf "${color}▓${NC}"
            done
            for ((i=progress; i<40; i++)); do
                printf " "
            done
            printf "] ${completed}%%"
        done
        printf "\n"

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
# Count the number of valid packages in requirements.txt
req_count=$(grep -v '^\s*$\|^\s*\#' requirements.txt | grep -v '^$' | wc -l)
echo -ne "${CYAN}Installing packages ${NC}["

count=0
while IFS= read -r line || [[ -n "$line" ]]; do
    # Skip empty lines, comments, and lines with only whitespace
    if [[ -z "$line" || "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]]; then
        continue
    fi
    
    # Clean the line of any leading/trailing whitespace
    line=$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    
    # Skip if the line is empty after cleaning
    if [[ -z "$line" ]]; then
        continue
    fi
    
    # Install the package with error handling
    if ! pip3 install "$line" > /dev/null 2>&1; then
        echo -e "\n${RED}>>> Error installing package: $line${NC}"
        echo -e "${YELLOW}>>> Attempting to install with verbose output...${NC}"
        pip3 install "$line"
        if [ $? -ne 0 ]; then
            echo -e "${RED}>>> Failed to install package: $line${NC}"
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
    
done < requirements.txt
printf "\n"

# Verify all packages were installed
echo -e "${YELLOW}>>> Verifying package installation...${NC}"
missing_packages=0
while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" =~ ^#.* ]] && continue
    package_name=$(echo "$line" | cut -d'=' -f1 | cut -d'>' -f1 | cut -d'<' -f1)
    if ! pip3 show "$package_name" > /dev/null 2>&1; then
        echo -e "${RED}>>> Package not installed: $package_name${NC}"
        missing_packages=$((missing_packages + 1))
    fi
done < requirements.txt

if [ $missing_packages -gt 0 ]; then
    echo -e "${YELLOW}>>> $missing_packages packages failed to install. Attempting to install them individually...${NC}"
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" =~ ^#.* ]] && continue
        package_name=$(echo "$line" | cut -d'=' -f1 | cut -d'>' -f1 | cut -d'<' -f1)
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

# Check if Metasploit is running, if not start it
echo -e "${YELLOW}>>> Checking Metasploit service...${NC}"
if ! pgrep -x "postgres" > /dev/null; then
    echo -e "${YELLOW}>>> Starting PostgreSQL for Metasploit...${NC}"
    systemctl start postgresql
    systemctl enable postgresql
fi

if ! pgrep -f "msfrpcd" > /dev/null; then
    echo -e "${YELLOW}>>> Initializing Metasploit database...${NC}"
    suppress_output msfdb init
fi

# Create system-wide executable wrapper script
echo -e "${YELLOW}>>> Creating system-wide executable wrapper...${NC}"
cat > /usr/local/bin/AI_MAL << EOF
#!/bin/bash
# AI_MAL wrapper script
# This script automatically activates the virtual environment and starts all dependencies before running AI_MAL

# Path to the virtual environment and installation
INSTALL_DIR="$INSTALL_DIR"
VENV_PATH="\$INSTALL_DIR/venv"
PYTHON_PATH="\$VENV_PATH/bin/python"

# Function to check if a service is running
is_service_running() {
    systemctl is-active --quiet \$1
    return \$?
}

# Ensure needed directories exist
mkdir -p "\$INSTALL_DIR/logs" 2>/dev/null || true
mkdir -p "\$INSTALL_DIR/scan_results" 2>/dev/null || true
mkdir -p "\$INSTALL_DIR/msf_resources" 2>/dev/null || true
mkdir -p "\$INSTALL_DIR/generated_scripts" 2>/dev/null || true
mkdir -p "\$INSTALL_DIR/workspaces" 2>/dev/null || true
mkdir -p "\$INSTALL_DIR/exfiltrated_data" 2>/dev/null || true
mkdir -p "\$INSTALL_DIR/implant_logs" 2>/dev/null || true

# Check and start required services
# 1. Check PostgreSQL (required for Metasploit)
if ! is_service_running postgresql; then
    echo "Starting PostgreSQL service..."
    sudo systemctl start postgresql
fi

# 2. Check and start Ollama
if ! is_service_running ollama; then
    echo "Starting Ollama service..."
    sudo systemctl start ollama
    # Give Ollama time to initialize
    sleep 3
fi

# 3. Initialize Metasploit database if needed
if ! pgrep -f msfrpcd > /dev/null; then
    echo "Initializing Metasploit database..."
    sudo msfdb init > /dev/null 2>&1
fi

# 4. Set environment variables
export OLLAMA_MODEL="artifish/llama3.2-uncensored"
export OLLAMA_FALLBACK_MODEL="gemma:1b"
export LOG_DIR="\$INSTALL_DIR/logs"
export WORKSPACE_DIR="\$INSTALL_DIR/workspaces"
export MSF_RESOURCES_DIR="\$INSTALL_DIR/msf_resources"
export SCAN_RESULTS_DIR="\$INSTALL_DIR/scan_results"
export GENERATED_SCRIPTS_DIR="\$INSTALL_DIR/generated_scripts"
export EXFIL_DIR="\$INSTALL_DIR/exfiltrated_data"

# Activate the virtual environment and run AI_MAL with all arguments passed to this script
cd "\$INSTALL_DIR" && "\$PYTHON_PATH" -m AI_MAL.main "\$@"
EOF

# Make the wrapper executable
chmod +x /usr/local/bin/AI_MAL

# Double-check that the wrapper was created properly
if [ ! -x /usr/local/bin/AI_MAL ]; then
    echo -e "${RED}>>> Error: Failed to create executable wrapper at /usr/local/bin/AI_MAL${NC}"
    echo -e "${YELLOW}>>> Attempting to fix permissions...${NC}"
    cat > /usr/local/bin/AI_MAL << EOF
#!/bin/bash
# AI_MAL wrapper script
cd "$INSTALL_DIR" && "$INSTALL_DIR/venv/bin/python" -m AI_MAL.main "\$@"
EOF
    chmod +x /usr/local/bin/AI_MAL
fi

# Add to system PATH and make it persist across reboots
echo -e "${YELLOW}>>> Creating systemd service for persistence...${NC}"

# Create Metasploit autostart service if it doesn't exist
if [ ! -f /etc/systemd/system/metasploit.service ]; then
    cat > /etc/systemd/system/metasploit.service << EOF
[Unit]
Description=Metasploit Framework Service
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
ExecStartPre=/usr/bin/msfdb init
ExecStart=/usr/bin/msfconsole -q
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    # Enable the service but don't start it immediately
    systemctl enable metasploit.service
fi

# Reload systemd
systemctl daemon-reload

# Create a sudoers file for AI_MAL
echo -e "${YELLOW}>>> Configuring sudoers permissions for AI_MAL...${NC}"
cat > /etc/sudoers.d/ai_mal << EOF
# Allow AI_MAL to run specific privileged commands without password

# Commands needed for Metasploit
ALL ALL=(ALL) NOPASSWD: /usr/bin/msfdb
ALL ALL=(ALL) NOPASSWD: /usr/bin/msfconsole

# Commands needed for network operations
ALL ALL=(ALL) NOPASSWD: /usr/bin/nmap
ALL ALL=(ALL) NOPASSWD: /sbin/ip
ALL ALL=(ALL) NOPASSWD: /bin/systemctl start postgresql
ALL ALL=(ALL) NOPASSWD: /bin/systemctl start ollama
ALL ALL=(ALL) NOPASSWD: /usr/sbin/arp
ALL ALL=(ALL) NOPASSWD: /usr/sbin/arping
ALL ALL=(ALL) NOPASSWD: /bin/ip
ALL ALL=(ALL) NOPASSWD: /sbin/ifconfig
EOF

# Secure the sudoers file
chmod 0440 /etc/sudoers.d/ai_mal

# Make a link in /usr/bin as well for maximum compatibility
ln -sf /usr/local/bin/AI_MAL /usr/bin/AI_MAL 2>/dev/null || true

# Make sure AI_MAL is in the PATH
if ! grep -q "PATH=.*\/usr\/local\/bin" ~/.bashrc; then
    echo 'export PATH="/usr/local/bin:/usr/bin:$PATH"' >> ~/.bashrc
fi

# Also update the PATH for the current session
export PATH="/usr/local/bin:/usr/bin:$PATH"

# Create a bash completion script for AI_MAL
echo -e "${YELLOW}>>> Creating bash completion for AI_MAL...${NC}"
cat > /etc/bash_completion.d/AI_MAL << EOF
#!/bin/bash
# Bash completion for AI_MAL

_ai_mal_completions()
{
    local cur prev opts
    COMPREPLY=()
    cur="\${COMP_WORDS[COMP_CWORD]}"
    prev="\${COMP_WORDS[COMP_CWORD-1]}"
    
    # Basic options
    opts="--help --stealth --continuous --msf --version --os --services --vuln --dos --exfil --implant --ai-analysis --full-auto --iterations --custom-vuln --output-dir --output-format --quiet --no-gui --log-level --log-file"
    
    # Complete with options
    if [[ \${cur} == -* ]]; then
        COMPREPLY=( \$(compgen -W "\${opts}" -- \${cur}) )
        return 0
    fi
}

complete -F _ai_mal_completions AI_MAL
EOF

# Make the completion script executable
chmod +x /etc/bash_completion.d/AI_MAL

# Source the completion script immediately
source /etc/bash_completion.d/AI_MAL 2>/dev/null || true

# Create a temporary alias for the current shell session
echo -e "${YELLOW}>>> Making AI_MAL immediately available in current session...${NC}"
alias AI_MAL="/usr/local/bin/AI_MAL"
echo "alias AI_MAL='/usr/local/bin/AI_MAL'" >> ~/.bash_aliases
source ~/.bash_aliases 2>/dev/null || true

# Add the alias to .bashrc of the user who ran sudo
if [ ! -z "$SUDO_USER" ]; then
  REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
  if [ -f "$REAL_HOME/.bashrc" ]; then
    if ! grep -q "alias AI_MAL=" "$REAL_HOME/.bashrc"; then
      echo "alias AI_MAL='/usr/local/bin/AI_MAL'" >> "$REAL_HOME/.bashrc"
    fi
  fi
fi

# Create a shell wrapper that will be used for current session
echo '#!/bin/bash' > /tmp/AI_MAL_wrapper
echo "exec /usr/local/bin/AI_MAL \"\$@\"" >> /tmp/AI_MAL_wrapper
chmod +x /tmp/AI_MAL_wrapper
cp /tmp/AI_MAL_wrapper /usr/bin/AI_MAL
rm /tmp/AI_MAL_wrapper

# Create a shell script in /usr/bin that can't be overridden by PATH issues
echo -e "${YELLOW}>>> Creating unambiguous binary in /usr/bin...${NC}"
cat > /usr/bin/AI_MAL << EOF
#!/bin/bash
# Direct AI_MAL executor
exec "/usr/local/bin/AI_MAL" "\$@"
EOF
chmod 755 /usr/bin/AI_MAL

# If run with sudo, setup the environment for the actual user too
if [ ! -z "$SUDO_USER" ]; then
  REAL_USER="$SUDO_USER"
  REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
  
  echo -e "${YELLOW}>>> Setting up environment for user $REAL_USER...${NC}"
  
  # Ensure user has access to the AI_MAL directories
  chown -R "$REAL_USER" "$INSTALL_DIR"
  
  # Add the AI_MAL alias to user's bash_profile or bashrc
  if [ -f "$REAL_HOME/.bash_profile" ]; then
    if ! grep -q "alias AI_MAL=" "$REAL_HOME/.bash_profile"; then
      echo "alias AI_MAL='/usr/bin/AI_MAL'" >> "$REAL_HOME/.bash_profile"
    fi
  fi
  
  if [ -f "$REAL_HOME/.bashrc" ]; then
    if ! grep -q "alias AI_MAL=" "$REAL_HOME/.bashrc"; then
      echo "alias AI_MAL='/usr/bin/AI_MAL'" >> "$REAL_HOME/.bashrc"
    fi
  fi
  
  # Create .bash_aliases if it doesn't exist
  if [ ! -f "$REAL_HOME/.bash_aliases" ]; then
    touch "$REAL_HOME/.bash_aliases"
    chown "$REAL_USER" "$REAL_HOME/.bash_aliases"
  fi
  
  # Add alias to .bash_aliases
  if ! grep -q "alias AI_MAL=" "$REAL_HOME/.bash_aliases"; then
    echo "alias AI_MAL='/usr/bin/AI_MAL'" >> "$REAL_HOME/.bash_aliases"
  fi

  # Make all changes owned by the real user
  chown "$REAL_USER" "$REAL_HOME/.bash_aliases" 2>/dev/null || true
  chown "$REAL_USER" "$REAL_HOME/.bashrc" 2>/dev/null || true
  chown "$REAL_USER" "$REAL_HOME/.bash_profile" 2>/dev/null || true

# Export current function to make it immediately available
export -f AI_MAL 2>/dev/null || true

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

# Create a global profile script to ensure AI_MAL is always available
echo -e "${YELLOW}>>> Creating global profile to ensure AI_MAL is always available...${NC}"
cat > /etc/profile.d/ai_mal.sh << EOL
#!/bin/bash
# Global profile for AI_MAL
export PATH="/usr/bin:/usr/local/bin:\$PATH"
# Make sure the AI_MAL command is always available
if [ ! -x "/usr/bin/AI_MAL" ] && [ -x "/usr/local/bin/AI_MAL" ]; then
  alias AI_MAL="/usr/local/bin/AI_MAL"
fi
EOL
chmod 644 /etc/profile.d/ai_mal.sh

# Create a symlink in /bin as a fallback for other shells
echo -e "${YELLOW}>>> Creating symlink in /bin for maximum compatibility...${NC}"
ln -sf /usr/bin/AI_MAL /bin/AI_MAL 2>/dev/null || true

# Export current function to make it immediately available
export -f AI_MAL 2>/dev/null || true

# Define a shell function that will be immediately available in this shell
echo -e "${YELLOW}>>> Creating shell function for immediate use...${NC}"
# This is a trick that makes the function available in the current shell
cat > /tmp/ai_mal_function << EOF
function AI_MAL() {
  /usr/bin/AI_MAL "\$@"
}
EOF
# Source the function in the current shell
. /tmp/ai_mal_function
# If being run with sudo, try to make it available to the real user's shell too
if [ ! -z "$SUDO_USER" ]; then
  # Try using su to add the function to the user's shell
  su - "$SUDO_USER" -c "cat > ~/.ai_mal_function << EOF
function AI_MAL() {
  /usr/bin/AI_MAL \"\\\$@\"
}
EOF
  echo '. ~/.ai_mal_function' >> ~/.bashrc
  . ~/.ai_mal_function" 2>/dev/null || true
fi
rm /tmp/ai_mal_function

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