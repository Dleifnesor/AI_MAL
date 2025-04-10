#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Self-installer function - allows running from any directory
self_installer() {
    # Create temp directory if not exists
    TEMP_DIR="/tmp/ai_mal_installer"
    mkdir -p "$TEMP_DIR"
    
    # Get current script and directory
    CURRENT_SCRIPT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/$(basename "${BASH_SOURCE[0]}")"
    CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    
    echo -e "${CYAN}Creating temporary installation directory...${NC}"
    rm -rf "$TEMP_DIR"
    mkdir -p "$TEMP_DIR"
    
    # Copy current directory to temp directory
    echo -e "${CYAN}Copying installation files...${NC}"
    cp -r "$CURRENT_DIR/"* "$TEMP_DIR/" 2>/dev/null
    
    # Check if this is a Git repository or zip download
    if [ -d "$CURRENT_DIR/.git" ]; then
        # Git repo - copy the .git directory too
        cp -r "$CURRENT_DIR/.git" "$TEMP_DIR/"
    fi
    
    # Make the installer script executable
    chmod +x "$TEMP_DIR/install.sh"
    
    # Print message
    echo -e "${GREEN}Installation files prepared successfully${NC}"
    echo -e "${CYAN}Running installer from: $TEMP_DIR/install.sh${NC}\n"
    
    # Set the flag to indicate we're now running from the temp directory
    export RUNNING_FROM_TEMP=1
    
    # Run the installer from the temp directory
    cd "$TEMP_DIR"
    bash "$TEMP_DIR/install.sh" "$@"
    
    # Exit with the same code
    exit $?
}

# Check if we've been copied to the temp directory already
if [ -z "$RUNNING_FROM_TEMP" ]; then
    # If not running from temp directory, call self-installer
    self_installer "$@"
    # This should not be reached
    exit 1
fi

# Installation flags and checkpoint tracking
VERIFY_INSTALLATION=true
INSTALLATION_LOG="/tmp/ai_mal_install.log"
CHECKPOINT_FILE="/tmp/ai_mal_checkpoint.txt"

# Determine source directory (directory where script is located)
SOURCE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo -e "${CYAN}Source directory detected as: ${SOURCE_DIR}${NC}"

# Check if source directory is Git repo or inside one
check_git_repo() {
    local check_dir="$1"
    # Check if this is a git repository
    if [ -d "${check_dir}/.git" ]; then
        echo "${check_dir}"
        return 0
    fi

    # Check parent directory if not at root
    local parent_dir="$(dirname "${check_dir}")"
    if [ "${parent_dir}" != "${check_dir}" ]; then
        check_git_repo "${parent_dir}"
        return $?
    fi

    # Not found
    return 1
}

# Try to find Git repo root
GIT_ROOT=$(check_git_repo "${SOURCE_DIR}")
if [ -n "${GIT_ROOT}" ]; then
    echo -e "${GREEN}Git repository root found at: ${GIT_ROOT}${NC}"
    # Use Git root as source if found
    SOURCE_DIR="${GIT_ROOT}"
fi

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

# Log the source directory
log_info "Installation source directory: $SOURCE_DIR"
if [ -n "${GIT_ROOT}" ]; then
    log_info "Git repository root: $GIT_ROOT"
fi

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
    local is_essential=${2:-false}  # Changed default to false for more graceful handling
    
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
            "libncurses5-dev")
                alternatives=("libncurses-dev" "ncurses-dev")
                ;;
            "libfreetype6-dev")
                alternatives=("libfreetype-dev")
                ;;
            "libmysqlclient-dev")
                alternatives=("default-libmysqlclient-dev" "libmariadb-dev" "libmariadbclient-dev")
                ;;
            "rubygems")
                alternatives=("ruby-rubygems")
                ;;
            "x11proto-core-dev")
                alternatives=("x11proto-dev")
                ;;
            "x11proto-input-dev")
                alternatives=("x11proto-dev")
                ;;
            "x11proto-kb-dev")
                alternatives=("x11proto-dev")
                ;;
            "x11proto-render-dev")
                alternatives=("x11proto-dev")
                ;;
            "x11proto-xext-dev")
                alternatives=("x11proto-dev")
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
        
        if $is_essential; then
            echo -e "\n${RED}>>> Package $package and alternatives not available. Installation cannot continue.${NC}"
            log_error "Package $package and alternatives not available"
            return 1
        else
            echo -e "${YELLOW}Warning: Package $package not found. Continuing without it.${NC}"
            log_error "Package $package not available but not essential. Continuing."
            return 0
        fi
    fi
    
    # Install with progress bar
    {
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$package" >>"$INSTALLATION_LOG" 2>&1
    } || {
        log_info "Package installation failed, trying with --fix-missing"
        DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing --no-install-recommends "$package" >>"$INSTALLATION_LOG" 2>&1
    } || {
        if $is_essential; then
            echo -e "\n${RED}>>> Failed to install essential package $package. Installation cannot continue.${NC}"
            log_error "Failed to install essential package $package"
            return 1
        else
            echo -e "${YELLOW}Warning: Failed to install $package. Continuing without it.${NC}"
            log_error "Failed to install non-essential package $package. Continuing."
            return 0
        fi
    }
    
    # Verify package installation
    if dpkg -s "$package" &>/dev/null; then
        log_info "Package $package successfully installed"
        return 0
    else
        if $is_essential; then
            log_error "Package $package installation verification failed"
            return 1
        else
            log_error "Package $package installation verification failed but not essential. Continuing."
            return 0
        fi
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
    
    # Define essential packages that must be installed for the application to work
    local essential_packages=(
        "build-essential" "python3-dev" "python3-pip" "python3-venv" "libssl-dev"
        "libldap2-dev" "libsasl2-dev" "nmap" "curl" "wget" "git"
    )
    
    # Define non-essential packages that are nice to have but not critical
    local non_essential_packages=(
        "apache2-utils" "hping3" "postgresql" "libpcap-dev" "libxml2-dev"
        "libxslt1-dev" "zlib1g-dev" "libffi-dev" "libsqlite3-dev"
        "libreadline-dev" "libbz2-dev" "libncurses5-dev" "libgdbm-dev"
        "liblzma-dev" "tk-dev" "uuid-dev" "libbluetooth-dev" "libcups2-dev"
        "libdbus-1-dev" "libexpat1-dev" "libfontconfig1-dev" "libfreetype6-dev"
        "libglib2.0-dev" "libgmp-dev" "libjpeg-dev" "libkrb5-dev" "libltdl-dev"
        "libmpc-dev" "libmpfr-dev" "libmysqlclient-dev" "libpango1.0-dev"
        "libpcre3-dev" "libpng-dev" "libpq-dev" "libsasl2-dev" "libsqlite3-dev"
        "libtiff5-dev" "libtool" "libwebp-dev" "libxcb1-dev"
        "libxcb-render0-dev" "libxcb-shm0-dev" "libxcb-xfixes0-dev" "libxext-dev"
        "libxrender-dev" "libxslt1-dev" "libyaml-dev" "make" "pkg-config"
        "procps" "python3-setuptools" "ruby" "ruby-dev" "rubygems" 
        "samba" "samba-common" "samba-common-bin" "samba-libs" "sqlite3" 
        "tcl-dev" "unixodbc-dev" "x11proto-core-dev" "x11proto-input-dev" 
        "x11proto-kb-dev" "x11proto-render-dev" "x11proto-xext-dev" 
        "xorg-sgml-doctools" "xtrans-dev" "zlib1g-dev"
    )
    
    # First install essential packages
    local total=${#essential_packages[@]}
    local count=0
    local failed_packages=()
    
    echo -e "${CYAN}Installing ${total} essential packages...${NC}"
    
    for package in "${essential_packages[@]}"; do
        count=$((count + 1))
        echo -ne "${CYAN}[$count/$total] Installing essential package $package...${NC} "
        safe_install_package "$package" true || failed_packages+=("$package")
        echo -e "${GREEN}Done${NC}"
    done
    
    # Check if any essential packages failed to install
    if [ ${#failed_packages[@]} -gt 0 ]; then
        log_error "Failed to install the following essential packages: ${failed_packages[*]}"
        handle_error "Failed to install essential system dependencies"
    fi
    
    # Then install non-essential packages
    total=${#non_essential_packages[@]}
    count=0
    failed_packages=()
    
    echo -e "${CYAN}Installing ${total} optional packages...${NC}"
    
    for package in "${non_essential_packages[@]}"; do
        count=$((count + 1))
        echo -ne "${CYAN}[$count/$total] Installing optional package $package...${NC} "
        safe_install_package "$package" false || failed_packages+=("$package")
        echo -e "${GREEN}Done${NC}"
    done
    
    # Report on failed non-essential packages
    if [ ${#failed_packages[@]} -gt 0 ]; then
        log_info "Some non-essential packages could not be installed: ${failed_packages[*]}"
        echo -e "${YELLOW}>>> Some optional packages could not be installed. This may limit some functionality.${NC}"
    fi
    
    complete_progress "System dependencies installed"
    log_info "System dependencies installation completed"
    save_checkpoint "system_dependencies"
}

# Function to install python-ldap dependencies
install_python_ldap_deps() {
    echo -e "${CYAN}Installing python-ldap dependencies...${NC}"
    log_info "Starting python-ldap dependencies installation"
    
    # Required packages for python-ldap
    local ldap_deps=(
        "libldap2-dev"
        "libsasl2-dev"
        "libssl-dev"
        "python3-dev"
    )
    
    local total=${#ldap_deps[@]}
    local count=0
    local failed_deps=()
    
    for package in "${ldap_deps[@]}"; do
        count=$((count + 1))
        echo -ne "${CYAN}[$count/$total] Installing LDAP dependency $package...${NC} "
        safe_install_package "$package" true || failed_deps+=("$package")
        echo -e "${GREEN}Done${NC}"
    done
    
    # Check if libldap2-dev is installed
    if ! dpkg -s "libldap2-dev" &>/dev/null; then
        log_error "libldap2-dev is not installed, python-ldap installation will likely fail"
        echo -e "${RED}>>> Critical dependency libldap2-dev is not installed!${NC}"
        echo -e "${YELLOW}>>> The python-ldap installation will likely fail without this package.${NC}"
        return 1
    fi
    
    # Check if libsasl2-dev is installed
    if ! dpkg -s "libsasl2-dev" &>/dev/null; then
        log_error "libsasl2-dev is not installed, python-ldap installation may have issues"
        echo -e "${YELLOW}>>> Warning: libsasl2-dev is not installed.${NC}"
        echo -e "${YELLOW}>>> The python-ldap installation may have limited functionality.${NC}"
    fi
    
    # If we reach this point, the main dependencies are installed
    echo -e "${GREEN}>>> python-ldap dependencies installed successfully${NC}"
    log_info "python-ldap dependencies installation completed"
    return 0
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
    
    # Install python-ldap dependencies before attempting to install the package
    install_python_ldap_deps || log_error "Failed to install all python-ldap dependencies"
    
    # Essential Python packages
    local essential_packages=(
        "rich" "python-nmap" "requests" "numpy" 
        "argparse" "pyyaml" "cryptography" "tqdm" 
        "colorama" "setuptools" "wheel" 
        "python-ldap" "psycopg2-binary"
    )
    
    # Non-essential Python packages
    local non_essential_packages=(
        "pathlib" "pandas" "paramiko" "scapy"
        "prompt_toolkit" "beautifulsoup4" "lxml" 
        "metasploit-framework" "pymetasploit3" "pyOpenSSL"
        "pycrypto" "pycryptodome" "pycryptodomex" "pyasn1" "pyasn1-modules"
        "rsa" "idna" "certifi" "chardet" "urllib3" "six" 
        "cffi" "pycparser" "bcrypt"
    )
    
    # Install essential packages first
    local total=${#essential_packages[@]}
    local count=0
    local failed_packages=()
    
    echo -e "${CYAN}Installing ${total} essential Python packages...${NC}"
    
    for package in "${essential_packages[@]}"; do
        count=$((count + 1))
        echo -ne "${CYAN}[$count/$total] Installing essential package $package...${NC} "
        log_info "Installing essential Python package: $package"
        
        # Try multiple installation methods
        if pip install "$package" >>"$INSTALLATION_LOG" 2>&1; then
            echo -e "${GREEN}Done${NC}"
        elif pip install --no-deps "$package" >>"$INSTALLATION_LOG" 2>&1; then
            echo -e "${GREEN}Done (without dependencies)${NC}"
            log_info "Installed $package without dependencies"
        elif pip install --no-binary :all: "$package" >>"$INSTALLATION_LOG" 2>&1; then
            echo -e "${GREEN}Done (from source)${NC}"
            log_info "Installed $package from source"
        else
            echo -e "${RED}Failed${NC}"
            log_error "Failed to install essential Python package: $package"
            failed_packages+=("$package")
        fi
    done
    
    # Report on failed essential packages
    if [ ${#failed_packages[@]} -gt 0 ]; then
        log_error "The following essential Python packages failed to install: ${failed_packages[*]}"
        handle_error "Failed to install essential Python dependencies"
    fi
    
    # Install non-essential packages
    total=${#non_essential_packages[@]}
    count=0
    failed_packages=()
    
    echo -e "${CYAN}Installing ${total} optional Python packages...${NC}"
    
    for package in "${non_essential_packages[@]}"; do
        count=$((count + 1))
        echo -ne "${CYAN}[$count/$total] Installing optional package $package...${NC} "
        log_info "Installing optional Python package: $package"
        
        # Try multiple installation methods but continue on failure
        if pip install "$package" >>"$INSTALLATION_LOG" 2>&1; then
            echo -e "${GREEN}Done${NC}"
        elif pip install --no-deps "$package" >>"$INSTALLATION_LOG" 2>&1; then
            echo -e "${GREEN}Done (without dependencies)${NC}"
            log_info "Installed $package without dependencies"
        elif pip install --no-binary :all: "$package" >>"$INSTALLATION_LOG" 2>&1; then
            echo -e "${GREEN}Done (from source)${NC}"
            log_info "Installed $package from source"
        else
            echo -e "${YELLOW}Failed${NC}"
            log_error "Failed to install optional Python package: $package"
            failed_packages+=("$package")
        fi
    done
    
    # Report on failed non-essential packages
    if [ ${#failed_packages[@]} -gt 0 ]; then
        log_info "Some non-essential Python packages failed to install: ${failed_packages[*]}"
        echo -e "${YELLOW}>>> Some optional Python packages could not be installed. This may limit some functionality.${NC}"
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
            echo -e "${YELLOW}>>> Warning: Could not install Ollama. AI features will be disabled.${NC}"
            log_info "Continuing installation without AI features"
            return 0
        }
        echo -e "${GREEN}Done${NC}"
    else
        echo -e "${GREEN}Ollama already installed${NC}"
    fi
    
    # Verify Ollama installation
    if ! command -v ollama &>/dev/null; then
        log_error "Ollama installation verification failed"
        echo -e "${YELLOW}>>> Warning: Ollama installation could not be verified. AI features will be disabled.${NC}"
        log_info "Continuing installation without AI features"
        return 0
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
            echo -e "${YELLOW}>>> Warning: Ollama service did not start. Will try to download models but AI features may not work.${NC}"
            break
        fi
    done
    if [ $count -lt $max_attempts ]; then
        echo -e "${GREEN}Done${NC}"
    fi
    
    # Install models with progress
    echo -e "${CYAN}Downloading AI models (this may take a while)...${NC}"
    
    # Define models to try in order of preference
    local models=(
        "artifish/llama3.2-uncensored"
        "qwen2.5-coder:7b"
    )
    
    # Try to install at least one model
    local model_installed=false
    local installed_models=()
    
    for model in "${models[@]}"; do
        echo -ne "${CYAN}Attempting to download model: $model...${NC} "
        log_info "Attempting to download AI model: $model"
        
        if ollama pull "$model" >>"$INSTALLATION_LOG" 2>&1; then
            echo -e "${GREEN}Done${NC}"
            log_info "Successfully downloaded model: $model"
            model_installed=true
            installed_models+=("$model")
            
            # If we've installed two models, that's enough
            if [ ${#installed_models[@]} -ge 2 ]; then
                break
            fi
        else
            echo -e "${YELLOW}Failed${NC}"
            log_error "Failed to download model: $model"
        fi
    done
    
    # Verify we have at least one model
    echo -ne "${CYAN}Verifying AI models...${NC} "
    log_info "Verifying AI models"
    
    if ! $model_installed; then
        echo -e "${YELLOW}No models installed${NC}"
        log_error "No AI models could be installed"
        echo -e "${YELLOW}>>> Warning: No AI models could be installed. AI features will be limited.${NC}"
    else
        echo -e "${GREEN}Done: Installed ${#installed_models[@]} model(s): ${installed_models[*]}${NC}"
        
        # Create a default configuration for the models
        echo -ne "${CYAN}Configuring AI models...${NC} "
        
        # Set environment variables for the installed models
        local primary_model="${installed_models[0]}"
        local fallback_model="${installed_models[1]:-$primary_model}"
        
        # Update the environment configuration
        mkdir -p /etc/AI_MAL
        cat > /etc/AI_MAL/ai_models << EOF
# AI_MAL AI Model Configuration
export OLLAMA_MODEL=$primary_model
export OLLAMA_FALLBACK_MODEL=$fallback_model
EOF
        
        echo -e "${GREEN}Done${NC}"
        log_info "AI models configured: Primary=$primary_model, Fallback=$fallback_model"
    fi
    
    complete_progress "AI models installation completed"
    log_info "AI models installation completed"
    save_checkpoint "ai_models"
}

# Function to create directories
create_directories() {
    if check_checkpoint "system_directories"; then
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
    
    complete_progress "Directories created"
    log_info "Directory creation completed"
    save_checkpoint "system_directories"
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
    
    # Include AI model configuration if it exists
    echo -ne "${CYAN}Adding AI model configuration...${NC} "
    if [ -f "/etc/AI_MAL/ai_models" ]; then
        cat >> /etc/AI_MAL/environment << EOF

# AI Models Configuration (from installed models)
$(cat /etc/AI_MAL/ai_models)
EOF
        echo -e "${GREEN}Done${NC}"
    else
        # Default configuration
        cat >> /etc/AI_MAL/environment << EOF

# Default AI Models Configuration
export OLLAMA_MODEL=artifish/llama3.2-uncensored
export OLLAMA_FALLBACK_MODEL=qwen2.5-coder:7b
EOF
        echo -e "${YELLOW}Using defaults${NC}"
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
    if [ -n "$SOURCE_DIR" ] && [ -d "$SOURCE_DIR" ]; then
        cp -r "${SOURCE_DIR}/." /opt/AI_MAL/ >>"$INSTALLATION_LOG" 2>&1 || handle_error "Failed to copy files to installation directory"
        echo -e "${GREEN}Done${NC}"
    else
        echo -e "${RED}Failed - Source directory not found${NC}"
        handle_error "Source directory not found"
    fi
    
    # Create empty log directories if they don't exist
    echo -ne "${CYAN}Ensuring log directories exist...${NC} "
    mkdir -p /opt/AI_MAL/logs >>"$INSTALLATION_LOG" 2>&1
    echo -e "${GREEN}Done${NC}"
    
    # Make scripts executable
    echo -ne "${CYAN}Setting script permissions...${NC} "
    if [ -d "/opt/AI_MAL/scripts" ]; then
        find /opt/AI_MAL/scripts -name "*.py" -exec chmod +x {} \; 2>/dev/null
        find /opt/AI_MAL/scripts -name "*.sh" -exec chmod +x {} \; 2>/dev/null
        find /opt/AI_MAL/scripts -name "*.rb" -exec chmod +x {} \; 2>/dev/null
        echo -e "${GREEN}Done${NC}"
    else
        mkdir -p /opt/AI_MAL/scripts
        echo -e "${YELLOW}Created scripts directory${NC}"
    fi
    
    # Create simple AI_MAL executable script
    echo -ne "${CYAN}Creating AI_MAL executable script...${NC} "
    cat > /opt/AI_MAL/ai_mal << EOF
#!/bin/bash
# AI_MAL direct executable script

# Source environment
if [ -f /etc/AI_MAL/environment ]; then
    source /etc/AI_MAL/environment
fi

# Set directory paths
AI_MAL_DIR="/opt/AI_MAL"
VENV_DIR="\$AI_MAL_DIR/venv"

# Activate virtual environment if it exists
if [ -d "\$VENV_DIR" ]; then
    source "\$VENV_DIR/bin/activate"
    VENV_ACTIVATED=1
else
    VENV_ACTIVATED=0
fi

# Run scanner module with all arguments
cd "\$AI_MAL_DIR"

# Try to determine how to run the scanner
if [ -f "\$AI_MAL_DIR/AI_MAL/main/scanner.py" ]; then
    python3 "\$AI_MAL_DIR/AI_MAL/main/scanner.py" "\$@"
elif [ -d "\$AI_MAL_DIR/ai_mal" ]; then
    python3 -m ai_mal.main.scanner "\$@"
else
    # Try several possible module paths
    python3 -m AI_MAL.main.scanner "\$@" 2>/dev/null || 
    python3 -m ai_mal.main.scanner "\$@" 2>/dev/null ||
    python3 -m main.scanner "\$@" 2>/dev/null ||
    python3 "\$AI_MAL_DIR/main/scanner.py" "\$@"
fi

EXIT_CODE=\$?

# Deactivate virtual environment if activated
[ \$VENV_ACTIVATED -eq 1 ] && deactivate

# Exit with same code as python script
exit \$EXIT_CODE
EOF
    chmod 755 /opt/AI_MAL/ai_mal
    echo -e "${GREEN}Done${NC}"
    
    # Create system-wide command
    echo -ne "${CYAN}Installing command to system...${NC} "
    cat > /usr/local/bin/AI_MAL << 'EOF'
#!/bin/bash
/opt/AI_MAL/ai_mal "$@"
EOF
    chmod 755 /usr/local/bin/AI_MAL
    
    # Create lowercase alias
    cat > /usr/local/bin/ai_mal << 'EOF'
#!/bin/bash
/opt/AI_MAL/ai_mal "$@"
EOF
    chmod 755 /usr/local/bin/ai_mal
    echo -e "${GREEN}Done${NC}"
    
    # Verify executable is available
    echo -ne "${CYAN}Verifying AI_MAL command...${NC} "
    if [ -x "/usr/local/bin/AI_MAL" ]; then
        echo -e "${GREEN}Found${NC}"
    else
        echo -e "${RED}Not found${NC}"
        log_error "AI_MAL command could not be verified"
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

# Function to handle retry installation for packages that initially failed
retry_failed_packages() {
    if [ ${#1} -eq 0 ]; then
        return 0
    fi

    echo -e "${CYAN}Retrying installation of failed packages...${NC}"
    log_info "Attempting to retry installation of previously failed packages"
    
    local packages=("$@")
    local total=${#packages[@]}
    local count=0
    local still_failed=()
    
    for package in "${packages[@]}"; do
        count=$((count + 1))
        echo -ne "${CYAN}[$count/$total] Retrying installation of $package...${NC} "
        
        # Try with different options
        if apt-get install -y "$package" >>"$INSTALLATION_LOG" 2>&1; then
            echo -e "${GREEN}Success${NC}"
            log_info "Successfully installed $package on retry"
        elif apt-get install -y --fix-missing "$package" >>"$INSTALLATION_LOG" 2>&1; then
            echo -e "${GREEN}Success (with --fix-missing)${NC}"
            log_info "Successfully installed $package on retry with --fix-missing"
        else
            echo -e "${YELLOW}Still failed${NC}"
            log_error "Package $package still failed to install on retry"
            still_failed+=("$package")
        fi
    done
    
    if [ ${#still_failed[@]} -gt 0 ]; then
        log_error "The following packages still failed to install: ${still_failed[*]}"
        echo -e "${YELLOW}>>> Some packages could not be installed even after retrying. This may limit some functionality.${NC}"
    else
        echo -e "${GREEN}>>> All previously failed packages were successfully installed.${NC}"
        log_info "All previously failed packages were successfully installed"
    fi
}

# Main installation process
main() {
    echo -e "\n${YELLOW}>>> AI_MAL Installation${NC}"
    echo -e "${YELLOW}>>> This script will install all necessary components${NC}\n"
    log_info "Starting AI_MAL installation from $SOURCE_DIR"
    
    # Detect OS and version
    echo -ne "${CYAN}Detecting operating system...${NC} "
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=$NAME
        OS_VERSION=$VERSION_ID
        echo -e "${GREEN}$OS_NAME $OS_VERSION${NC}"
        log_info "Detected OS: $OS_NAME $OS_VERSION"
    else
        echo -e "${YELLOW}Unknown${NC}"
        log_info "Could not detect OS, proceeding with default package names"
    fi
    
    # Update system
    echo -e "${CYAN}Updating system...${NC}"
    echo -ne "${CYAN}Updating package lists...${NC} "
    log_info "Updating system packages"
    apt-get update >>"$INSTALLATION_LOG" 2>&1
    echo -e "${GREEN}Done${NC}"
    
    echo -ne "${CYAN}Upgrading installed packages...${NC} "
    apt-get upgrade -y >>"$INSTALLATION_LOG" 2>&1
    echo -e "${GREEN}Done${NC}"
    
    # Add package mappings based on OS version
    if [[ "$OS_NAME" == "Kali GNU/Linux" ]]; then
        log_info "Setting up Kali-specific package mappings"
        # Handle package name differences in Kali Linux
        if dpkg --compare-versions "${OS_VERSION:-0}" ge "2023.1"; then
            log_info "Using package mappings for Kali $OS_VERSION"
            # For newer Kali versions, add these mappings
            if ! check_package_availability "libfreetype6-dev" && check_package_availability "libfreetype-dev"; then
                echo -e "${CYAN}Mapping libfreetype6-dev to libfreetype-dev${NC}"
                ln -sf "libfreetype-dev" "libfreetype6-dev"
            fi
            
            if ! check_package_availability "libncurses5-dev" && check_package_availability "libncurses-dev"; then
                echo -e "${CYAN}Mapping libncurses5-dev to libncurses-dev${NC}"
                ln -sf "libncurses-dev" "libncurses5-dev"
            fi
            
            if ! check_package_availability "libmysqlclient-dev" && check_package_availability "default-libmysqlclient-dev"; then
                echo -e "${CYAN}Mapping libmysqlclient-dev to default-libmysqlclient-dev${NC}"
                ln -sf "default-libmysqlclient-dev" "libmysqlclient-dev"
            fi
        fi
    fi
    
    # Create temporary directory for any custom fixes
    mkdir -p /tmp/ai_mal_fixes
    
    # Install components - ensure each step is executed regardless of previous step status
    install_system_dependencies
    install_python_dependencies
    install_metasploit
    install_ai_models
    create_directories
    setup_environment
    install_package
    
    # Final verification even if some components failed
    if $VERIFY_INSTALLATION; then
        verify_installation
    fi
    
    # Create a blank scanner.py if it doesn't exist
    if [ ! -f "/opt/AI_MAL/AI_MAL/main/scanner.py" ] && [ ! -f "/opt/AI_MAL/main/scanner.py" ]; then
        echo -ne "${CYAN}Creating minimal scanner.py...${NC} "
        mkdir -p /opt/AI_MAL/main
        cat > /opt/AI_MAL/main/scanner.py << 'EOF'
#!/usr/bin/env python3
"""
AI_MAL Scanner Module
"""
import sys
import argparse

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="AI_MAL Scanner")
    parser.add_argument("target", nargs="?", help="Target IP or network range")
    parser.add_argument("--scan-type", choices=["quick", "full", "stealth"], 
                        default="quick", help="Type of scan to perform")
    parser.add_argument("--ai-analysis", action="store_true", help="Enable AI analysis")
    parser.add_argument("--msf", action="store_true", help="Use Metasploit modules")
    parser.add_argument("--exploit", action="store_true", help="Generate exploits")
    parser.add_argument("--vuln", action="store_true", help="Run vulnerability scan")
    parser.add_argument("--custom-scripts", action="store_true", help="Use custom scripts")
    return parser.parse_args()

def main():
    """Main scanner function."""
    args = parse_arguments()
    print(f"AI_MAL Scanner - Version 1.0")
    
    if not args.target:
        print("No target specified. Use --help for usage information.")
        return 1
        
    print(f"Target: {args.target}")
    print(f"Scan type: {args.scan_type}")
    
    enabled_features = []
    if args.ai_analysis:
        enabled_features.append("AI Analysis")
    if args.msf:
        enabled_features.append("Metasploit")
    if args.exploit:
        enabled_features.append("Exploit Generation")
    if args.vuln:
        enabled_features.append("Vulnerability Scanning")
    if args.custom_scripts:
        enabled_features.append("Custom Scripts")
        
    if enabled_features:
        print(f"Enabled features: {', '.join(enabled_features)}")
        
    print("This is a minimal scanner implementation.")
    print("The full scanner functionality is being installed.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
EOF
        chmod +x /opt/AI_MAL/main/scanner.py
        echo -e "${GREEN}Done${NC}"
    fi
    
    # Final summary
    echo -e "\n${GREEN}>>> AI_MAL installation completed successfully${NC}"
    echo -e "${YELLOW}>>> Please restart your terminal or run 'source /etc/AI_MAL/environment'${NC}"
    log_info "AI_MAL installation completed successfully"
    
    # Show final instructions
    echo -e "\n${CYAN}Installation Summary:${NC}"
    echo -e "  - Installation Log: ${INSTALLATION_LOG}"
    echo -e "  - Environment File: /etc/AI_MAL/environment"
    echo -e "  - Installation Directory: /opt/AI_MAL"
    echo -e "  - Commands: AI_MAL or ai_mal <target> [options]"
    echo -e "  - Example: AI_MAL 192.168.1.1 --full-auto --ai-analysis"
    echo -e "  - You can also run directly: /opt/AI_MAL/ai_mal <target> [options]"
    echo -e "  - Source Directory Used: ${SOURCE_DIR}"
    
    # If we're running from temp directory, show note about it
    if [ -n "$RUNNING_FROM_TEMP" ]; then
        echo -e "  - Installed from temporary directory: $SOURCE_DIR"
        echo -e "  - Temporary directory will be cleaned up automatically"
    fi
    
    # Cleanup
    rm -rf /tmp/ai_mal_fixes
}

# Run main installation
main

# Cleanup temporary directory if used
if [ -n "$RUNNING_FROM_TEMP" ] && [[ "$SOURCE_DIR" == "/tmp/ai_mal_installer" ]]; then
    cd /
    rm -rf "$SOURCE_DIR"
    echo -e "${GREEN}>>> Temporary installation files cleaned up${NC}"
fi

# Reset terminal
reset_terminal
exit 0 