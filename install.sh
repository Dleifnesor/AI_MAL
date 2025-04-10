#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Installation flags and checkpoint tracking
VERIFY_INSTALLATION=true
INSTALLATION_LOG="/tmp/ai_mal_install.log"
CHECKPOINT_FILE="/tmp/ai_mal_checkpoint.txt"

# Start with a clean log and checkpoint
rm -f "$INSTALLATION_LOG" "$CHECKPOINT_FILE"
touch "$INSTALLATION_LOG" "$CHECKPOINT_FILE"

# Function to log information
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1" | tee -a "$INSTALLATION_LOG"
}

# Function to log errors
log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" | tee -a "$INSTALLATION_LOG"
}

# Function to save checkpoint
save_checkpoint() {
    echo "$1" >> "$CHECKPOINT_FILE"
    log_info "Checkpoint: $1 completed"
}

# Function to check if checkpoint exists
check_checkpoint() {
    grep -q "^$1$" "$CHECKPOINT_FILE"
    return $?
}

# Progress bar function
progress_bar() {
    local width=50
    local percent=$1
    local filled=$((width * percent / 100))
    local empty=$((width - filled))
    
    # Save cursor position
    tput sc
    
    # Print progress bar
    printf "\r["
    printf "%${filled}s" | tr " " "="
    printf "%${empty}s" | tr " " " "
    printf "] %3d%%" $percent
    
    # If 100%, add a newline
    if [ "$percent" -eq 100 ]; then
        printf "\n"
    fi
}

# Function to complete progress and print newline
complete_progress() {
    local message="$1"
    # Finish any progress bar and add a newline
    printf "\n${GREEN}>>> %s${NC}\n" "$message"
}

# Function to reset terminal
reset_terminal() {
    if command -v tput &>/dev/null; then
        tput sgr0
        tput cnorm
        tput cup 0 0
        echo -e "\r"
    fi
}

# Function to handle errors
handle_error() {
    log_error "$1"
    echo -e "\n${RED}Error: $1${NC}"
    echo -e "${YELLOW}Check the installation log at ${INSTALLATION_LOG} for more details${NC}"
    reset_terminal
    exit 1
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    handle_error "Please run as root (sudo ./install.sh)"
fi

# Function to check if a package is available
check_package_availability() {
    local package=$1
    apt-cache search "^$package$" 2>/dev/null | grep -q "^$package "
    return $?
}

# Function to safely install a package with progress bar
safe_install_package() {
    local package=$1
    local is_essential=${2:-true}
    
    # Check if already installed
    if dpkg -s "$package" &>/dev/null; then
        log_info "Package $package is already installed"
        return 0
    fi
    
    log_info "Installing package: $package"
    
    # Check if package is available
    if ! check_package_availability "$package"; then
        # Try alternatives
        log_info "Package $package not found in repositories, checking alternatives"
        case "$package" in
            "libssl-dev")
                alternatives=("libssl1.1-dev" "libssl3-dev" "libssl1.0-dev" "libssl1.0.2-dev")
                ;;
            *)
                alternatives=()
                ;;
        esac
        
        for alt in "${alternatives[@]}"; do
            log_info "Trying alternative package: $alt"
            if check_package_availability "$alt"; then
                DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$alt" >>"$INSTALLATION_LOG" 2>&1
                if [ $? -eq 0 ]; then
                    log_info "Successfully installed alternative package: $alt"
                    return 0
                else
                    log_error "Failed to install alternative package: $alt"
                fi
            fi
        done
        
        echo -e "\n${RED}>>> Package $package and alternatives not available. Installation cannot continue.${NC}"
        log_error "Package $package and alternatives not available"
        return 1
    fi
    
    # Install with progress bar
    {
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$package" >>"$INSTALLATION_LOG" 2>&1
    } || {
        log_info "Package installation failed, trying with --fix-missing"
        DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing --no-install-recommends "$package" >>"$INSTALLATION_LOG" 2>&1
    } || {
        echo -e "\n${RED}>>> Failed to install essential package $package. Installation cannot continue.${NC}"
        log_error "Failed to install essential package $package"
        return 1
    }
    
    # Verify package installation
    if dpkg -s "$package" &>/dev/null; then
        log_info "Package $package successfully installed"
        return 0
    else
        log_error "Package $package installation verification failed"
        return 1
    fi
}

# Function to install system dependencies with progress bar
install_system_dependencies() {
    if check_checkpoint "system_dependencies"; then
        echo -e "${GREEN}System dependencies already installed. Skipping...${NC}"
        return 0
    fi

    echo -e "${CYAN}Installing system dependencies...${NC}"
    log_info "Starting system dependencies installation"
    
    # Update package lists
    apt-get update >>"$INSTALLATION_LOG" 2>&1
    
    # Install essential packages
    local packages=(
        "build-essential" "python3-dev" "python3-pip" "python3-venv" "libssl-dev"
        "libldap2-dev" "libsasl2-dev" "nmap" "apache2-utils" "hping3"
        "postgresql" "curl" "wget" "git" "libpcap-dev" "libxml2-dev"
        "libxslt1-dev" "zlib1g-dev" "libffi-dev" "libsqlite3-dev"
        "libreadline-dev" "libbz2-dev" "libncurses5-dev" "libgdbm-dev"
        "liblzma-dev" "tk-dev" "uuid-dev" "libbluetooth-dev" "libcups2-dev"
        "libdbus-1-dev" "libexpat1-dev" "libfontconfig1-dev" "libfreetype6-dev"
        "libglib2.0-dev" "libgmp-dev" "libjpeg-dev" "libkrb5-dev" "libltdl-dev"
        "libmpc-dev" "libmpfr-dev" "libmysqlclient-dev" "libpango1.0-dev"
        "libpcre3-dev" "libpng-dev" "libpq-dev" "libsasl2-dev" "libsqlite3-dev"
        "libssl-dev" "libtiff5-dev" "libtool" "libwebp-dev" "libxcb1-dev"
        "libxcb-render0-dev" "libxcb-shm0-dev" "libxcb-xfixes0-dev" "libxext-dev"
        "libxrender-dev" "libxslt1-dev" "libyaml-dev" "make" "pkg-config"
        "procps" "python3-dev" "python3-pip" "python3-setuptools" "python3-venv"
        "ruby" "ruby-dev" "rubygems" "samba" "samba-common" "samba-common-bin"
        "samba-libs" "sqlite3" "tcl-dev" "tk-dev" "unixodbc-dev" "wget"
        "x11proto-core-dev" "x11proto-input-dev" "x11proto-kb-dev"
        "x11proto-render-dev" "x11proto-xext-dev" "xorg-sgml-doctools"
        "xtrans-dev" "zlib1g-dev"
    )
    
    local total=${#packages[@]}
    local count=0
    local failed_packages=()
    
    echo -e "${CYAN}Installing ${total} packages...${NC}"
    
    for package in "${packages[@]}"; do
        count=$((count + 1))
        echo -ne "${CYAN}[$count/$total] Installing $package...${NC} "
        safe_install_package "$package" || failed_packages+=("$package")
        echo -e "${GREEN}Done${NC}"
    done
    
    # Check if any packages failed to install
    if [ ${#failed_packages[@]} -gt 0 ]; then
        log_error "Failed to install the following packages: ${failed_packages[*]}"
        handle_error "Failed to install some system dependencies"
    fi
    
    complete_progress "System dependencies installed"
    log_info "System dependencies installation completed"
    save_checkpoint "system_dependencies"
}

# Function to install Python dependencies with progress bar
install_python_dependencies() {
    if check_checkpoint "python_dependencies"; then
        echo -e "${GREEN}Python dependencies already installed. Skipping...${NC}"
        return 0
    fi

    echo -e "${CYAN}Installing Python dependencies...${NC}"
    log_info "Starting Python dependencies installation"
    
    # Create and activate virtual environment
    echo -ne "${CYAN}Creating virtual environment...${NC} "
    python3 -m venv venv >>"$INSTALLATION_LOG" 2>&1 || handle_error "Failed to create virtual environment"
    source venv/bin/activate
    echo -e "${GREEN}Done${NC}"
    
    # Verify the virtual environment is activated
    if [ -z "$VIRTUAL_ENV" ]; then
        log_error "Failed to activate virtual environment"
        handle_error "Virtual environment activation failed"
    fi
    
    # Upgrade pip
    echo -ne "${CYAN}Upgrading pip...${NC} "
    pip install --upgrade pip >>"$INSTALLATION_LOG" 2>&1 || log_error "Failed to upgrade pip"
    echo -e "${GREEN}Done${NC}"
    
    # Install Python packages
    local packages=(
        "rich" "python-nmap" "pathlib" "requests" "numpy" "pandas"
        "argparse" "pyyaml" "cryptography" "tqdm" "paramiko" "scapy"
        "colorama" "prompt_toolkit" "beautifulsoup4" "lxml" "python-ldap"
        "psycopg2-binary" "metasploit-framework" "pymetasploit3" "pyOpenSSL"
        "pycrypto" "pycryptodome" "pycryptodomex" "pyasn1" "pyasn1-modules"
        "rsa" "idna" "certifi" "chardet" "urllib3" "six" "setuptools"
        "wheel" "cffi" "pycparser" "cryptography" "bcrypt"
    )
    
    local total=${#packages[@]}
    local count=0
    local failed_packages=()
    
    echo -e "${CYAN}Installing ${total} Python packages...${NC}"
    
    for package in "${packages[@]}"; do
        count=$((count + 1))
        echo -ne "${CYAN}[$count/$total] Installing $package...${NC} "
        log_info "Installing Python package: $package"
        
        pip install "$package" >>"$INSTALLATION_LOG" 2>&1 || {
            log_info "Standard installation failed for $package, trying with --no-deps"
            pip install --no-deps "$package" >>"$INSTALLATION_LOG" 2>&1 || {
                echo -e "${YELLOW}Failed${NC}"
                log_error "Failed to install Python package: $package"
                failed_packages+=("$package")
                continue
            }
        }
        echo -e "${GREEN}Done${NC}"
    done
    
    # Report on failed packages
    if [ ${#failed_packages[@]} -gt 0 ]; then
        log_error "The following Python packages failed to install: ${failed_packages[*]}"
        echo -e "${YELLOW}>>> Some Python packages failed to install. Check the log for details.${NC}"
    fi
    
    complete_progress "Python dependencies installed"
    log_info "Python dependencies installation completed"
    save_checkpoint "python_dependencies"
}

# Function to install and configure Metasploit
install_metasploit() {
    if check_checkpoint "metasploit"; then
        echo -e "${GREEN}Metasploit already installed. Skipping...${NC}"
        return 0
    fi

    echo -e "${CYAN}Installing Metasploit...${NC}"
    log_info "Starting Metasploit installation"
    
    # Install Metasploit
    echo -ne "${CYAN}Installing Metasploit Framework...${NC} "
    safe_install_package "metasploit-framework" || handle_error "Failed to install Metasploit"
    echo -e "${GREEN}Done${NC}"
    
    # Start PostgreSQL
    echo -ne "${CYAN}Starting PostgreSQL service...${NC} "
    log_info "Starting PostgreSQL service"
    systemctl start postgresql >>"$INSTALLATION_LOG" 2>&1
    systemctl enable postgresql >>"$INSTALLATION_LOG" 2>&1
    
    # Verify PostgreSQL is running
    if ! systemctl is-active --quiet postgresql; then
        echo -e "${YELLOW}Failed${NC}"
        log_error "PostgreSQL is not running"
        echo -e "${YELLOW}>>> Warning: PostgreSQL is not running. Trying to start it...${NC}"
        systemctl start postgresql >>"$INSTALLATION_LOG" 2>&1 || {
            log_error "Failed to start PostgreSQL"
            echo -e "${YELLOW}>>> Warning: Could not start PostgreSQL. Metasploit may not work correctly.${NC}"
        }
    else
        echo -e "${GREEN}Done${NC}"
    fi
    
    # Initialize Metasploit database
    if [ ! -f ~/.msf4/db_initialized ]; then
        echo -ne "${CYAN}Initializing Metasploit database...${NC} "
        log_info "Initializing Metasploit database"
        msfdb init >>"$INSTALLATION_LOG" 2>&1
        touch ~/.msf4/db_initialized
        echo -e "${GREEN}Done${NC}"
    else
        echo -e "${GREEN}Metasploit database already initialized${NC}"
    fi
    
    # Verify Metasploit installation
    echo -ne "${CYAN}Verifying Metasploit installation...${NC} "
    if ! command -v msfconsole &>/dev/null; then
        echo -e "${RED}Failed${NC}"
        log_error "Metasploit installation verification failed"
        handle_error "Metasploit installation could not be verified"
    else
        echo -e "${GREEN}Done${NC}"
    fi
    
    complete_progress "Metasploit installed and configured"
    log_info "Metasploit installation completed"
    save_checkpoint "metasploit"
}

# Function to install AI models with progress bar
install_ai_models() {
    if check_checkpoint "ai_models"; then
        echo -e "${GREEN}AI models already installed. Skipping...${NC}"
        return 0
    fi

    echo -e "${CYAN}Installing AI models...${NC}"
    log_info "Starting AI models installation"
    
    # Install Ollama
    if ! command -v ollama &> /dev/null; then
        echo -ne "${CYAN}Installing Ollama...${NC} "
        log_info "Installing Ollama"
        curl -fsSL https://ollama.com/install.sh | sh >>"$INSTALLATION_LOG" 2>&1 || {
            echo -e "${RED}Failed${NC}"
            log_error "Failed to install Ollama"
            handle_error "Failed to install Ollama"
        }
        echo -e "${GREEN}Done${NC}"
    else
        echo -e "${GREEN}Ollama already installed${NC}"
    fi
    
    # Verify Ollama installation
    if ! command -v ollama &>/dev/null; then
        log_error "Ollama installation verification failed"
        handle_error "Ollama installation could not be verified"
    fi
    
    # Start Ollama service
    echo -ne "${CYAN}Starting Ollama service...${NC} "
    log_info "Starting Ollama service"
    systemctl start ollama >>"$INSTALLATION_LOG" 2>&1
    systemctl enable ollama >>"$INSTALLATION_LOG" 2>&1
    echo -e "${GREEN}Done${NC}"
    
    # Wait for Ollama to start
    echo -ne "${CYAN}Waiting for Ollama service to start...${NC} "
    log_info "Waiting for Ollama service to start"
    count=0
    max_attempts=30
    while ! curl -s http://localhost:11434/api/tags >/dev/null 2>&1; do
        sleep 1
        count=$((count + 1))
        if [ $count -ge $max_attempts ]; then
            echo -e "${YELLOW}Timeout${NC}"
            log_error "Ollama service failed to start after $max_attempts seconds"
            echo -e "${YELLOW}>>> Warning: Ollama service did not start. AI features may not work.${NC}"
            break
        fi
    done
    if [ $count -lt $max_attempts ]; then
        echo -e "${GREEN}Done${NC}"
    fi
    
    # Install models with progress
    echo -e "${CYAN}Downloading AI models (this may take a while)...${NC}"
    
    # Download first model
    echo -ne "${CYAN}Downloading model: artifish/llama3.2-uncensored...${NC} "
    log_info "Downloading AI model: artifish/llama3.2-uncensored"
    ollama pull artifish/llama3.2-uncensored >>"$INSTALLATION_LOG" 2>&1
    echo -e "${GREEN}Done${NC}"
    
    # Download second model
    echo -ne "${CYAN}Downloading model: gemma:7b...${NC} "
    log_info "Downloading AI model: gemma:7b"
    ollama pull gemma:7b >>"$INSTALLATION_LOG" 2>&1
    echo -e "${GREEN}Done${NC}"
    
    # Verify models were downloaded
    echo -ne "${CYAN}Verifying AI models...${NC} "
    log_info "Verifying AI models"
    models_ok=true
    
    if ! ollama list | grep -q "artifish/llama3.2-uncensored"; then
        models_ok=false
        log_error "Artifish Llama model not found"
        echo -e "${YELLOW}>>> Warning: Artifish Llama model not found.${NC}"
    fi
    
    if ! ollama list | grep -q "gemma:7b"; then
        models_ok=false
        log_error "Gemma model not found"
        echo -e "${YELLOW}>>> Warning: Gemma model not found.${NC}"
    fi
    
    if $models_ok; then
        echo -e "${GREEN}Done${NC}"
    else
        echo -e "${YELLOW}Some models missing${NC}"
    fi
    
    complete_progress "AI models installation completed"
    log_info "AI models installation completed"
    save_checkpoint "ai_models"
}

# Function to create directories
create_directories() {
    if check_checkpoint "directories"; then
        echo -e "${GREEN}Directories already created. Skipping...${NC}"
        return 0
    fi

    echo -e "${CYAN}Creating directories...${NC}"
    log_info "Creating necessary directories"
    
    # Create base directory
    echo -ne "${CYAN}Creating base directory...${NC} "
    mkdir -p /opt/AI_MAL >>"$INSTALLATION_LOG" 2>&1 || handle_error "Failed to create base directory"
    echo -e "${GREEN}Done${NC}"
    
    # Create subdirectories
    echo -ne "${CYAN}Creating log directories...${NC} "
    mkdir -p /var/log/AI_MAL >>"$INSTALLATION_LOG" 2>&1 || handle_error "Failed to create log directory"
    echo -e "${GREEN}Done${NC}"
    
    echo -ne "${CYAN}Creating results directory...${NC} "
    mkdir -p /opt/AI_MAL/results >>"$INSTALLATION_LOG" 2>&1 || handle_error "Failed to create results directory"
    echo -e "${GREEN}Done${NC}"
    
    echo -ne "${CYAN}Creating scripts directory...${NC} "
    mkdir -p /opt/AI_MAL/scripts >>"$INSTALLATION_LOG" 2>&1 || handle_error "Failed to create scripts directory"
    echo -e "${GREEN}Done${NC}"
    
    echo -ne "${CYAN}Creating application logs directory...${NC} "
    mkdir -p /opt/AI_MAL/logs >>"$INSTALLATION_LOG" 2>&1 || handle_error "Failed to create logs directory"
    echo -e "${GREEN}Done${NC}"
    
    # Set permissions
    echo -ne "${CYAN}Setting directory permissions...${NC} "
    chmod 755 /var/log/AI_MAL
    chmod 755 /opt/AI_MAL
    chmod 755 /opt/AI_MAL/results
    chmod 755 /opt/AI_MAL/scripts
    chmod 755 /opt/AI_MAL/logs
    echo -e "${GREEN}Done${NC}"
    
    # Verify directories were created
    echo -ne "${CYAN}Verifying directories...${NC} "
    all_dirs_exist=true
    for dir in "/opt/AI_MAL" "/var/log/AI_MAL" "/opt/AI_MAL/results" "/opt/AI_MAL/scripts" "/opt/AI_MAL/logs"; do
        if [ ! -d "$dir" ]; then
            all_dirs_exist=false
            log_error "Directory $dir was not created"
            echo -e "${RED}Failed: $dir not found${NC}"
        fi
    done
    
    if $all_dirs_exist; then
        echo -e "${GREEN}Done${NC}"
    else
        handle_error "Failed to create some directories"
    fi
    
    # Create symlink
    echo -ne "${CYAN}Creating command symlink...${NC} "
    ln -sf /opt/AI_MAL/AI_MAL /usr/local/bin/AI_MAL
    echo -e "${GREEN}Done${NC}"
    
    complete_progress "Directories created"
    log_info "Directory creation completed"
    save_checkpoint "directories"
}

# Function to set up environment variables
setup_environment() {
    if check_checkpoint "environment"; then
        echo -e "${GREEN}Environment already configured. Skipping...${NC}"
        return 0
    fi

    echo -e "${CYAN}Setting up environment...${NC}"
    log_info "Setting up environment variables"
    
    # Create environment file
    echo -ne "${CYAN}Creating environment directory...${NC} "
    mkdir -p /etc/AI_MAL >>"$INSTALLATION_LOG" 2>&1 || handle_error "Failed to create environment directory"
    echo -e "${GREEN}Done${NC}"
    
    echo -ne "${CYAN}Creating environment file...${NC} "
    cat > /etc/AI_MAL/environment << EOF
# AI_MAL Environment Variables
export DEBUG=1
export OLLAMA_HOST=http://localhost:11434
export OLLAMA_MODEL=artifish/llama3.2-uncensored
export OLLAMA_FALLBACK_MODEL=gemma:7b
export AI_MAL_LOG_DIR=/var/log/AI_MAL
export AI_MAL_RESULTS_DIR=/opt/AI_MAL/results
export AI_MAL_SCRIPTS_DIR=/opt/AI_MAL/scripts
EOF
    
    # Verify environment file was created
    if [ ! -f "/etc/AI_MAL/environment" ]; then
        echo -e "${RED}Failed${NC}"
        log_error "Environment file not created"
        handle_error "Failed to create environment file"
    else
        echo -e "${GREEN}Done${NC}"
    fi
    
    # Create profile.d entry for system-wide availability
    echo -ne "${CYAN}Creating system-wide profile entry...${NC} "
    cat > /etc/profile.d/ai_mal.sh << EOF
#!/bin/bash
source /etc/AI_MAL/environment
EOF
    
    chmod +x /etc/profile.d/ai_mal.sh
    echo -e "${GREEN}Done${NC}"
    
    # Source the environment file
    echo -ne "${CYAN}Activating environment...${NC} "
    source /etc/AI_MAL/environment
    echo -e "${GREEN}Done${NC}"
    
    complete_progress "Environment configured"
    log_info "Environment setup completed"
    save_checkpoint "environment"
}

# Function to install the package
install_package() {
    if check_checkpoint "package"; then
        echo -e "${GREEN}Package already installed. Skipping...${NC}"
        return 0
    fi

    echo -e "${CYAN}Installing AI_MAL package...${NC}"
    log_info "Installing AI_MAL package"
    
    # Copy files to installation directory
    echo -ne "${CYAN}Copying files to installation directory...${NC} "
    cp -r . /opt/AI_MAL/ >>"$INSTALLATION_LOG" 2>&1 || handle_error "Failed to copy files to installation directory"
    echo -e "${GREEN}Done${NC}"
    
    # Create empty log directories if they don't exist
    echo -ne "${CYAN}Ensuring log directories exist...${NC} "
    mkdir -p /opt/AI_MAL/logs >>"$INSTALLATION_LOG" 2>&1
    echo -e "${GREEN}Done${NC}"
    
    # Make scripts executable
    echo -ne "${CYAN}Setting script permissions...${NC} "
    if [ -d "/opt/AI_MAL/scripts" ]; then
        chmod +x /opt/AI_MAL/scripts/*.py 2>/dev/null
        chmod +x /opt/AI_MAL/scripts/*.sh 2>/dev/null
        chmod +x /opt/AI_MAL/scripts/*.rb 2>/dev/null
        echo -e "${GREEN}Done${NC}"
    else
        echo -e "${YELLOW}No scripts directory${NC}"
    fi
    
    # Install Python package
    echo -ne "${CYAN}Installing Python package...${NC} "
    cd /opt/AI_MAL
    python3 setup.py install >>"$INSTALLATION_LOG" 2>&1 || {
        echo -e "${YELLOW}Failed with setup.py${NC}"
        log_error "Failed to install Python package with setup.py"
        echo -e "${CYAN}Trying with pip...${NC} "
        pip install -e . >>"$INSTALLATION_LOG" 2>&1 || {
            echo -e "${RED}Failed${NC}"
            handle_error "Failed to install package with pip"
        }
    }
    echo -e "${GREEN}Done${NC}"
    
    # Verify executable is available
    echo -ne "${CYAN}Creating executable wrapper...${NC} "
    if [ ! -f "/opt/AI_MAL/AI_MAL" ]; then
        log_info "Creating executable wrapper"
        cat > /opt/AI_MAL/AI_MAL << EOF
#!/bin/bash
# AI_MAL wrapper script

# Source environment variables
if [ -f /etc/AI_MAL/environment ]; then
    source /etc/AI_MAL/environment
fi

# Run the main scanner
python3 -m AI_MAL.main.scanner "\$@"
EOF
        chmod +x /opt/AI_MAL/AI_MAL
    fi
    echo -e "${GREEN}Done${NC}"
    
    # Verify the symlink
    echo -ne "${CYAN}Creating command symlink...${NC} "
    ln -sf /opt/AI_MAL/AI_MAL /usr/local/bin/AI_MAL
    echo -e "${GREEN}Done${NC}"
    
    # Verify the command works
    echo -ne "${CYAN}Verifying command availability...${NC} "
    if ! command -v AI_MAL &>/dev/null; then
        echo -e "${YELLOW}Warning${NC}"
        log_error "AI_MAL command not available"
        echo -e "${YELLOW}>>> Warning: AI_MAL command could not be verified. You may need to create a symbolic link manually.${NC}"
    else
        echo -e "${GREEN}Done${NC}"
    fi
    
    complete_progress "Package installed"
    log_info "Package installation completed"
    save_checkpoint "package"
}

# Function to verify installation
verify_installation() {
    echo -e "${CYAN}Verifying installation...${NC}"
    log_info "Verifying installation"
    
    local all_good=true
    
    # Check directories
    echo -ne "${CYAN}Checking directory structure...${NC} "
    dir_check_ok=true
    for dir in "/opt/AI_MAL" "/var/log/AI_MAL" "/opt/AI_MAL/results" "/opt/AI_MAL/scripts" "/opt/AI_MAL/logs"; do
        if [ ! -d "$dir" ]; then
            dir_check_ok=false
            log_error "Directory $dir not found"
        fi
    done
    
    if $dir_check_ok; then
        echo -e "${GREEN}Ok${NC}"
    else
        echo -e "${YELLOW}Issues found${NC}"
        echo -e "${YELLOW}>>> Warning: Some directories are missing.${NC}"
        all_good=false
    fi
    
    # Check environment file
    echo -ne "${CYAN}Checking environment configuration...${NC} "
    if [ ! -f "/etc/AI_MAL/environment" ]; then
        echo -e "${YELLOW}Not found${NC}"
        log_error "Environment file not found"
        echo -e "${YELLOW}>>> Warning: Environment file not found${NC}"
        all_good=false
    else
        echo -e "${GREEN}Ok${NC}"
    fi
    
    # Check executable
    echo -ne "${CYAN}Checking AI_MAL command...${NC} "
    if ! command -v AI_MAL &>/dev/null; then
        echo -e "${YELLOW}Not available${NC}"
        log_error "AI_MAL command not available"
        echo -e "${YELLOW}>>> Warning: AI_MAL command not available${NC}"
        all_good=false
    else
        echo -e "${GREEN}Ok${NC}"
    fi
    
    # Check Metasploit
    echo -ne "${CYAN}Checking Metasploit...${NC} "
    if ! command -v msfconsole &>/dev/null; then
        echo -e "${YELLOW}Not available${NC}"
        log_error "Metasploit not available"
        echo -e "${YELLOW}>>> Warning: Metasploit not available${NC}"
        all_good=false
    else
        echo -e "${GREEN}Ok${NC}"
    fi
    
    # Check Ollama
    echo -ne "${CYAN}Checking Ollama...${NC} "
    if ! command -v ollama &>/dev/null; then
        echo -e "${YELLOW}Not available${NC}"
        log_error "Ollama not available"
        echo -e "${YELLOW}>>> Warning: Ollama not available${NC}"
        all_good=false
    else
        echo -e "${GREEN}Ok${NC}"
    fi
    
    # Final verification result
    if $all_good; then
        complete_progress "Installation verification successful"
        log_info "Installation verification completed successfully"
    else
        echo -e "${YELLOW}>>> Installation verification found issues. Check the log for details: ${INSTALLATION_LOG}${NC}"
        log_error "Installation verification found issues"
    fi
}

# Main installation process
main() {
    echo -e "\n${YELLOW}>>> AI_MAL Installation${NC}"
    echo -e "${YELLOW}>>> This script will install all necessary components${NC}\n"
    log_info "Starting AI_MAL installation"
    
    # Update system
    echo -e "${CYAN}Updating system...${NC}"
    echo -ne "${CYAN}Updating package lists...${NC} "
    log_info "Updating system packages"
    apt-get update >>"$INSTALLATION_LOG" 2>&1
    echo -e "${GREEN}Done${NC}"
    
    echo -ne "${CYAN}Upgrading installed packages...${NC} "
    apt-get upgrade -y >>"$INSTALLATION_LOG" 2>&1
    echo -e "${GREEN}Done${NC}"
    
    # Install components
    install_system_dependencies
    install_python_dependencies
    install_metasploit
    install_ai_models
    create_directories
    setup_environment
    install_package
    
    if $VERIFY_INSTALLATION; then
        verify_installation
    fi
    
    echo -e "\n${GREEN}>>> AI_MAL installation completed successfully${NC}"
    echo -e "${YELLOW}>>> Please restart your terminal or run 'source /etc/AI_MAL/environment'${NC}"
    log_info "AI_MAL installation completed successfully"
    
    # Show final instructions
    echo -e "\n${CYAN}Installation Summary:${NC}"
    echo -e "  - Installation Log: ${INSTALLATION_LOG}"
    echo -e "  - Environment File: /etc/AI_MAL/environment"
    echo -e "  - Installation Directory: /opt/AI_MAL"
    echo -e "  - Command: AI_MAL <target> [options]"
    echo -e "  - Example: AI_MAL 192.168.1.1 --full-auto --ai-analysis"
}

# Run main installation
main

# Reset terminal
reset_terminal
exit 0 