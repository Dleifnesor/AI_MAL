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

# Trap for cleanup on interruption
cleanup() {
    echo -e "\n${YELLOW}>>> Installation interrupted. Cleaning up...${NC}"
    # Kill any hanging processes
    kill_hanging_apt
    jobs -p | xargs -r kill
    exit 1
}

# Function to safely kill a possibly hanging apt process
kill_hanging_apt() {
    echo -e "${YELLOW}>>> Detected potential hanging apt process. Attempting to resolve...${NC}"
    
    # Find all apt/dpkg processes
    apt_pids=$(pgrep -f "apt|dpkg" || echo "")
    
    if [ -n "$apt_pids" ]; then
        echo -e "${YELLOW}>>> Found apt/dpkg processes: $apt_pids${NC}"
        echo -e "${YELLOW}>>> Sending SIGTERM to processes...${NC}"
        
        # Try gentle termination first
        for pid in $apt_pids; do
            kill -15 $pid 2>/dev/null
        done
        
        # Wait a bit and check if they're still running
        sleep 5
        
        # Get remaining processes
        remaining_pids=$(pgrep -f "apt|dpkg" || echo "")
        
        if [ -n "$remaining_pids" ]; then
            echo -e "${YELLOW}>>> Some processes still running. Sending SIGKILL...${NC}"
            for pid in $remaining_pids; do
                kill -9 $pid 2>/dev/null
            done
        fi
    fi
    
    # Wait for locks to clear
    echo -e "${YELLOW}>>> Waiting for apt/dpkg locks to clear...${NC}"
    sleep 10
    
    # Check for and remove lock files
    if [ -f /var/lib/dpkg/lock-frontend ]; then
        echo -e "${YELLOW}>>> Removing dpkg lock files...${NC}"
        rm -f /var/lib/dpkg/lock-frontend
        rm -f /var/lib/dpkg/lock
        rm -f /var/cache/apt/archives/lock
    fi
    
    # Repair potentially broken dpkg
    echo -e "${YELLOW}>>> Attempting to configure any unconfigured packages...${NC}"
    dpkg --configure -a
    
    echo -e "${GREEN}>>> Package management system should now be usable again${NC}"
}

# Set up trap for SIGINT (Ctrl+C) and SIGTERM
trap cleanup SIGINT SIGTERM

# Add a trap for long-running apt processes
trap_apt_hang() {
    # This function is called periodically during the script execution
    if [ -n "$APT_START_TIME" ]; then
        current_time=$(date +%s)
        elapsed=$((current_time - APT_START_TIME))
        
        # If an apt process has been running for more than 15 minutes (900 seconds)
        if [ $elapsed -gt 900 ]; then
            echo -e "${RED}>>> APT process has been running for $elapsed seconds, which is too long${NC}"
            kill_hanging_apt
            unset APT_START_TIME
        fi
    fi
}

# Set up trap for SIGALRM to check for hanging apt processes every minute
(while true; do sleep 60; kill -ALRM $$ 2>/dev/null || exit 0; done) &
WATCHDOG_PID=$!
trap "trap_apt_hang" ALRM

# Clean up the watchdog process on exit
trap "kill $WATCHDOG_PID 2>/dev/null || true; cleanup" EXIT

# Log file for detailed output
LOG_FILE="install_log_$(date +%Y%m%d_%H%M%S).txt"
echo "Starting installation at $(date)" > "$LOG_FILE"

# Function to log messages
log_message() {
    echo "$@" | tee -a "$LOG_FILE"
}

# Print a message showing log file is available
log_message "${YELLOW}>>> Detailed installation log will be saved to: $LOG_FILE${NC}"

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
SKIP_LIBSSL=false
for arg in "$@"; do
  case $arg in
    --no-models)
      SKIP_MODELS=true
      shift
      ;;
    --skip-libssl)
      SKIP_LIBSSL=true
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
        
        # Install base packages one by one with specific timeouts for problematic packages
        echo -e "${YELLOW}>>> Installing base packages...${NC}"
        
        # Install problematic packages with longer timeouts and noninteractive mode for all
        echo -e "${YELLOW}>>> Checking for libssl-dev package...${NC}"

        # Check if we should skip libssl-dev installation
        if [ "$SKIP_LIBSSL" = true ]; then
            echo -e "${YELLOW}>>> Skipping libssl-dev installation (--skip-libssl flag detected)${NC}"
            echo -e "${YELLOW}>>> Note: Some features requiring SSL/TLS might not work${NC}"
        else
            # Check if libssl-dev is already installed
            if dpkg -s libssl-dev &> /dev/null; then
                echo -e "${GREEN}>>> libssl-dev is already installed. Skipping installation.${NC}"
            else
                echo -e "${YELLOW}>>> Installing libssl-dev with extended timeout...${NC}"
                export DEBIAN_FRONTEND=noninteractive
                
                # Set the start time for apt watchdog
                APT_START_TIME=$(date +%s)
                
                # Try installing libssl-dev with an even longer timeout
                echo -e "${YELLOW}>>> Attempting to install libssl-dev (timeout: 600s)...${NC}"
                timeout 600 apt-get install -y libssl-dev
                libssl_result=$?
                
                # Clear the APT start time
                unset APT_START_TIME
                
                if [ $libssl_result -eq 124 ]; then
                    echo -e "${RED}>>> libssl-dev installation timed out after 600 seconds${NC}"
                    # Kill any hanging processes
                    kill_hanging_apt
                    
                    echo -e "${YELLOW}>>> Checking if libssl-dev is actually installed despite the timeout...${NC}"
                    if dpkg -s libssl-dev &> /dev/null; then
                        echo -e "${GREEN}>>> libssl-dev appears to be installed correctly despite timeout${NC}"
                    else
                        echo -e "${YELLOW}>>> Will attempt installation one more time with --no-install-recommends...${NC}"
                        APT_START_TIME=$(date +%s)
                        timeout 300 apt-get install -y --no-install-recommends libssl-dev
                        unset APT_START_TIME
                        
                        if dpkg -s libssl-dev &> /dev/null; then
                            echo -e "${GREEN}>>> libssl-dev installed successfully on second attempt${NC}"
                        else
                            echo -e "${RED}>>> Will continue without libssl-dev. Some features may not work.${NC}"
                            echo -e "${YELLOW}>>> You can retry later with: apt-get install -y libssl-dev${NC}"
                            echo -e "${YELLOW}>>> Or run this script with --skip-libssl to skip this package${NC}"
                        fi
                    fi
                elif [ $libssl_result -ne 0 ]; then
                    echo -e "${RED}>>> Failed to install libssl-dev. Will continue without it.${NC}"
                    echo -e "${YELLOW}>>> You may need to install it manually later with: apt-get install -y libssl-dev${NC}"
                else
                    echo -e "${GREEN}>>> Successfully installed libssl-dev${NC}"
                fi
            fi
        fi
        
        # Install other base packages with noninteractive mode
        base_packages=(
            "python3" "python3-pip" "python3-venv" "git" "curl" "wget" 
            "build-essential" "libffi-dev"
        )
        for package in "${base_packages[@]}"; do
            install_package "$package" 300
        done
        
        # Add a check for successful installation of essential packages
        echo -e "${YELLOW}>>> Verifying essential packages...${NC}"
        essential_packages=("python3" "python3-pip" "python3-venv")
        missing_essentials=false
        for package in "${essential_packages[@]}"; do
            if ! dpkg -s "$package" &> /dev/null; then
                echo -e "${RED}>>> Critical package $package is missing. Attempting reinstall...${NC}"
                install_package "$package" 300
                if ! dpkg -s "$package" &> /dev/null; then
                    echo -e "${RED}>>> Failed to install $package after retry. This may cause issues.${NC}"
                    missing_essentials=true
                fi
            fi
        done
        
        if [ "$missing_essentials" = true ]; then
            echo -e "${YELLOW}>>> Warning: Some essential packages could not be installed.${NC}"
            echo -e "${YELLOW}>>> Continuing with installation, but functionality may be limited.${NC}"
        else
            echo -e "${GREEN}>>> All essential packages verified!${NC}"
        fi

        # Install Metasploit Framework separately (large package)
        echo -e "${YELLOW}>>> Installing Metasploit Framework (may take some time)...${NC}"
        timeout 300 apt-get install -y metasploit-framework
        if [ $? -ne 0 ]; then
            log_message "${RED}>>> Error or timeout installing Metasploit. Will continue with other packages.${NC}"
        else
            log_message "${GREEN}>>> Metasploit Framework installed successfully.${NC}"
        fi

        # Install network packages one by one
        echo -e "${YELLOW}>>> Installing network packages...${NC}"
        network_packages=(
            "nmap" "python3-nmap" "smbclient" "libpcap-dev" "hping3"
            "libnetfilter-queue-dev" "libnetfilter-queue1" 
            "libnetfilter-conntrack-dev" "libnetfilter-conntrack3"
        )
        for package in "${network_packages[@]}"; do
            install_package "$package"
        done

        # Install Python packages one by one
        echo -e "${YELLOW}>>> Installing Python development packages...${NC}"
        python_packages=(
            "python3-dev" "python3-setuptools" "python3-wheel"
        )
        for package in "${python_packages[@]}"; do
            install_package "$package"
        done

        # Install additional utilities one by one
        echo -e "${YELLOW}>>> Installing additional utilities...${NC}"
        additional_packages=(
            "apache2-utils" "bc"
        )
        for package in "${additional_packages[@]}"; do
            install_package "$package"
        done

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
            timeout 300 curl -fsSL https://ollama.com/install.sh | sh -s -- -q
            
            # Start Ollama service
            echo -e "${YELLOW}>>> Starting Ollama service...${NC}"
            systemctl start ollama
            systemctl enable ollama
            
            # Wait for Ollama to start
            echo -e "${YELLOW}>>> Waiting for Ollama service to start...${NC}"
            sleep 10
            
            # Check if we should skip model downloads
            if [ "$SKIP_MODELS" = true ]; then
                echo -e "${YELLOW}>>> Skipping model downloads (--no-models flag detected)${NC}"
                echo -e "${YELLOW}>>> You will need to pull models manually later with:${NC}"
                echo -e "${GREEN}>>>   ollama pull artifish/llama3.2-uncensored${NC}"
                echo -e "${GREEN}>>>   ollama pull gemma:1b${NC}"
            else
                # Pull the specified models directly with timeout
                echo -e "${YELLOW}>>> Pulling primary AI model: artifish/llama3.2-uncensored (this may take a while)...${NC}"
                timeout 900 ollama pull artifish/llama3.2-uncensored
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}>>> Downloaded primary model successfully${NC}"
                else
                    echo -e "${YELLOW}>>> Could not download primary model (timed out or failed). Will try fallback model.${NC}"
                fi
                
                echo -e "${YELLOW}>>> Pulling fallback AI model: gemma:1b...${NC}"
                timeout 300 ollama pull gemma:1b
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}>>> Downloaded fallback model successfully${NC}"
                else
                    echo -e "${RED}>>> Could not download fallback model. AI analysis may not work.${NC}"
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
                # Check if models are available
                if ! ollama list | grep -q "artifish/llama3.2-uncensored"; then
                    echo -e "${YELLOW}>>> Pulling primary AI model: artifish/llama3.2-uncensored (this may take a while)...${NC}"
                    timeout 900 ollama pull artifish/llama3.2-uncensored
                    if [ $? -eq 0 ]; then
                        echo -e "${GREEN}>>> Downloaded primary model successfully${NC}"
                    else
                        echo -e "${YELLOW}>>> Could not download primary model (timed out or failed). Will try fallback model.${NC}"
                    fi
                else
                    echo -e "${GREEN}>>> Primary model artifish/llama3.2-uncensored is already available${NC}"
                fi
                
                if ! ollama list | grep -q "gemma:1b"; then
                    echo -e "${YELLOW}>>> Pulling fallback AI model: gemma:1b...${NC}"
                    timeout 300 ollama pull gemma:1b
                    if [ $? -eq 0 ]; then
                        echo -e "${GREEN}>>> Downloaded fallback model successfully${NC}"
                    else
                        echo -e "${RED}>>> Could not download fallback model. AI analysis may not work.${NC}"
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
timeout 60 pip3 install --upgrade pip

# Install packages directly with output visible
echo -e "${CYAN}Installing project dependencies individually...${NC}"

# Create a temporary requirements file without version constraints for fallback
echo -e "${YELLOW}>>> Creating fallback requirements file...${NC}"
cp requirements.txt requirements.simple.txt
# Extract just package names without version constraints
sed -i 's/[<>=!~].*//' requirements.simple.txt

# First try to install all packages at once with a timeout
echo -e "${YELLOW}>>> Attempting to install all requirements together...${NC}"
timeout 300 pip3 install -r requirements.txt
pip_status=$?

if [ $pip_status -eq 0 ]; then
    echo -e "${GREEN}>>> Successfully installed all dependencies!${NC}"
else
    echo -e "${YELLOW}>>> Bulk installation failed or timed out. Falling back to individual package installation...${NC}"
    
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
        
        # Install with output visible and timeout
        echo -e "${CYAN}Installing ${package_name}...${NC}"
        timeout 180 pip3 install "$line"
        
        if [ $? -ne 0 ]; then
            echo -e "${YELLOW}>>> Failed to install package with version constraints: $package_name. Trying without version constraints...${NC}"
            timeout 180 pip3 install "$package_name"
            
            if [ $? -ne 0 ]; then
                echo -e "${RED}>>> Failed to install package: $package_name. Continuing...${NC}"
            else
                echo -e "${GREEN}>>> Successfully installed: $package_name (without version constraints)${NC}"
            fi
        else
            echo -e "${GREEN}>>> Successfully installed: $package_name${NC}"
        fi
        
    done < requirements.txt
fi

# Install AI_MAL package
echo -e "${YELLOW}>>> Installing AI_MAL package...${NC}"
timeout 180 pip3 install -e .
if [ $? -ne 0 ]; then
    log_message "${RED}>>> Error installing AI_MAL package. Installation may be incomplete.${NC}"
    exit 1
else
    log_message "${GREEN}>>> AI_MAL package installed successfully${NC}"
fi

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

# Add a more robust completion check at the end of the script
echo -e "${YELLOW}>>> Performing final installation verification...${NC}"

# Keep track of verification errors
verification_errors=0

# 1. Check if required directories exist
echo -e "${CYAN}Verifying required directories...${NC}"
missing_dirs=()
for dir in "logs" "scan_results" "msf_resources" "generated_scripts" "workspaces"; do
    if [ ! -d "$dir" ]; then
        missing_dirs+=("$dir")
    fi
done

if [ ${#missing_dirs[@]} -gt 0 ]; then
    echo -e "${RED}>>> Some required directories are missing: ${missing_dirs[*]}${NC}"
    echo -e "${YELLOW}>>> Creating missing directories...${NC}"
    for dir in "${missing_dirs[@]}"; do
        mkdir -p "$dir"
        chmod 755 "$dir"
        echo -e "${GREEN}>>> Created directory: $dir${NC}"
    done
else
    echo -e "${GREEN}>>> All required directories verified${NC}"
fi

# 2. Check if Python virtual environment is properly installed
echo -e "${CYAN}Verifying Python virtual environment...${NC}"
if [ -d "venv" ] && [ -f "venv/bin/activate" ] && [ -f "venv/bin/python" ]; then
    echo -e "${GREEN}>>> Python virtual environment is properly installed${NC}"
    # Check if we can activate it
    if source venv/bin/activate 2>/dev/null; then
        echo -e "${GREEN}>>> Virtual environment can be activated${NC}"
        # Check if essential Python packages are installed
        if python -c "import rich, nmap, pathlib" 2>/dev/null; then
            echo -e "${GREEN}>>> Essential Python packages are installed${NC}"
        else
            echo -e "${RED}>>> Some essential Python packages are missing. You may need to reinstall them manually:${NC}"
            echo -e "${YELLOW}>>>   pip install rich python-nmap pathlib${NC}"
            ((verification_errors++))
        fi
    else
        echo -e "${RED}>>> Cannot activate virtual environment. This might indicate a problem.${NC}"
        echo -e "${YELLOW}>>> You might need to recreate it with: python3 -m venv venv${NC}"
        ((verification_errors++))
    fi
else
    echo -e "${RED}>>> Python virtual environment is missing or incomplete${NC}"
    echo -e "${YELLOW}>>> You might need to recreate it with: python3 -m venv venv${NC}"
    ((verification_errors++))
fi

# 3. Check nmap permissions and functionality
echo -e "${CYAN}Verifying nmap installation...${NC}"
if command -v nmap >/dev/null 2>&1; then
    echo -e "${GREEN}>>> nmap is installed${NC}"
    
    # Check if nmap has proper permissions
    if [ -f /usr/bin/nmap ]; then
        if [ -u /usr/bin/nmap ]; then
            echo -e "${GREEN}>>> nmap has setuid permissions${NC}"
        else
            echo -e "${YELLOW}>>> Setting setuid permission on nmap for privileged operations...${NC}"
            chmod +s /usr/bin/nmap
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}>>> Successfully set permissions on nmap${NC}"
            else
                echo -e "${RED}>>> Failed to set permissions on nmap. Some scans may require sudo.${NC}"
                ((verification_errors++))
            fi
        fi
    fi
    
    # Test if nmap works
    if timeout 10 nmap -V >/dev/null 2>&1; then
        echo -e "${GREEN}>>> nmap is functioning correctly${NC}"
    else
        echo -e "${RED}>>> nmap test failed. There might be issues with the installation.${NC}"
        ((verification_errors++))
    fi
else
    echo -e "${RED}>>> nmap is not installed or not in PATH${NC}"
    echo -e "${YELLOW}>>> Please install nmap manually: apt-get install -y nmap${NC}"
    ((verification_errors++))
fi

# 4. Check if Ollama is running
echo -e "${CYAN}Verifying Ollama service...${NC}"
if command -v ollama >/dev/null 2>&1; then
    echo -e "${GREEN}>>> Ollama is installed${NC}"
    
    # Check if Ollama service is running
    if timeout 5 curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
        echo -e "${GREEN}>>> Ollama service is running${NC}"
        
        # Check if models are available
        if ollama list 2>/dev/null | grep -q "artifish/llama3.2-uncensored\|gemma:1b"; then
            echo -e "${GREEN}>>> At least one AI model is available${NC}"
        else
            echo -e "${YELLOW}>>> No AI models detected. AI analysis won't work.${NC}"
            echo -e "${YELLOW}>>> You can install models with:${NC}"
            echo -e "${YELLOW}>>>   ollama pull artifish/llama3.2-uncensored${NC}"
            echo -e "${YELLOW}>>>   ollama pull gemma:1b${NC}"
            ((verification_errors++))
        fi
    else
        echo -e "${YELLOW}>>> Ollama service is not running${NC}"
        echo -e "${YELLOW}>>> Starting Ollama service...${NC}"
        systemctl start ollama >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}>>> Successfully started Ollama service${NC}"
            sleep 5  # Give it time to start up
            
            # Check again if it's running
            if timeout 5 curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
                echo -e "${GREEN}>>> Ollama service is now running${NC}"
            else
                echo -e "${RED}>>> Failed to start Ollama service${NC}"
                ((verification_errors++))
            fi
        else
            echo -e "${RED}>>> Failed to start Ollama service${NC}"
            ((verification_errors++))
        fi
    fi
else
    echo -e "${YELLOW}>>> Ollama is not installed${NC}"
    echo -e "${YELLOW}>>> AI analysis functionality will not be available${NC}"
    echo -e "${YELLOW}>>> You can install Ollama with: curl -fsSL https://ollama.com/install.sh | sh${NC}"
    ((verification_errors++))
fi

# 5. Check if AI_MAL executable is available
echo -e "${CYAN}Verifying AI_MAL executable...${NC}"
if [ -f "/usr/local/bin/AI_MAL" ]; then
    echo -e "${GREEN}>>> AI_MAL executable is available${NC}"
    
    # Check if it's executable
    if [ -x "/usr/local/bin/AI_MAL" ]; then
        echo -e "${GREEN}>>> AI_MAL executable has proper permissions${NC}"
    else
        echo -e "${YELLOW}>>> Setting executable permissions on AI_MAL...${NC}"
        chmod +x "/usr/local/bin/AI_MAL"
    fi
else
    echo -e "${YELLOW}>>> Creating AI_MAL executable...${NC}"
    cat > /usr/local/bin/AI_MAL << 'EOF'
#!/bin/bash
cd $(dirname "$(readlink -f "$0")")/../AI_MAL
source venv/bin/activate 2>/dev/null || echo "Error: Virtual environment not found"
python -m AI_MAL.main "$@"
EOF
    chmod +x /usr/local/bin/AI_MAL
    echo -e "${GREEN}>>> Created AI_MAL executable at /usr/local/bin/AI_MAL${NC}"
fi

# Final status report
if [ $verification_errors -eq 0 ]; then
    echo -e "${GREEN}>>> All verification checks passed! Installation is complete and ready to use.${NC}"
else
    echo -e "${YELLOW}>>> Installation completed with $verification_errors warning(s).${NC}"
    echo -e "${YELLOW}>>> Some functionality might be limited. Check the logs above for details.${NC}"
fi

echo -e "${GREEN}>>> You can now run AI_MAL with:${NC} ${YELLOW}AI_MAL <target> [options]${NC}"
echo -e "${GREEN}>>> Example:${NC} ${YELLOW}AI_MAL 192.168.1.1 --vuln --os --services${NC}"
echo -e "${GREEN}>>> For help, run:${NC} ${YELLOW}AI_MAL --help${NC}"

echo ""
echo -e "${GREEN}▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄${NC}"
echo -e "${GREEN} ✓ Installation ${verification_errors -eq 0 && echo "Complete" || echo "Completed with warnings"} ${NC}"
echo -e "${GREEN} AI_MAL is now ready to use ${NC}"
echo -e "${GREEN}▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀${NC}"

exit 0 