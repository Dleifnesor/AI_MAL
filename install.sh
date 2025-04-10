#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Progress bar function
progress_bar() {
    local width=50
    local percent=$1
    local filled=$((width * percent / 100))
    local empty=$((width - filled))
    printf "\r["
    printf "%${filled}s" | tr " " "="
    printf "%${empty}s" | tr " " " "
    printf "] %3d%%" $percent
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
    echo -e "\n${RED}Error: $1${NC}"
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
    apt-cache search "^$package$" | grep -q "^$package "
    return $?
}

# Function to safely install a package with progress bar
safe_install_package() {
    local package=$1
    local is_essential=${2:-true}
    
    # Check if already installed
    if dpkg -s "$package" &>/dev/null; then
        return 0
    fi
    
    # Check if package is available
    if ! check_package_availability "$package"; then
        # Try alternatives
        case "$package" in
            "libssl-dev")
                alternatives=("libssl1.1-dev" "libssl3-dev" "libssl1.0-dev" "libssl1.0.2-dev")
                ;;
            *)
                alternatives=()
                ;;
        esac
        
        for alt in "${alternatives[@]}"; do
            if check_package_availability "$alt"; then
                DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$alt" >/dev/null 2>&1
                if [ $? -eq 0 ]; then
                    return 0
                fi
            fi
        done
        
        echo -e "\n${RED}>>> Package $package and alternatives not available. Installation cannot continue.${NC}"
        return 1
    fi
    
    # Install with progress bar
    {
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$package" >/dev/null 2>&1
    } || {
        DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing --no-install-recommends "$package" >/dev/null 2>&1
    } || {
        echo -e "\n${RED}>>> Failed to install essential package $package. Installation cannot continue.${NC}"
        return 1
    }
    
    return 0
}

# Function to install system dependencies with progress bar
install_system_dependencies() {
    echo -e "${CYAN}Installing system dependencies...${NC}"
    
    # Update package lists
    apt-get update >/dev/null 2>&1
    
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
    
    for package in "${packages[@]}"; do
        count=$((count + 1))
        progress_bar $((count * 100 / total))
        safe_install_package "$package" || handle_error "Failed to install $package"
    done
    
    echo -e "\n${GREEN}>>> System dependencies installed${NC}"
}

# Function to install Python dependencies with progress bar
install_python_dependencies() {
    echo -e "${CYAN}Installing Python dependencies...${NC}"
    
    # Create and activate virtual environment
    python3 -m venv venv >/dev/null 2>&1
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip >/dev/null 2>&1
    
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
    
    for package in "${packages[@]}"; do
        count=$((count + 1))
        progress_bar $((count * 100 / total))
        pip install "$package" >/dev/null 2>&1 || {
            pip install --no-deps "$package" >/dev/null 2>&1 || {
                echo -e "\n${YELLOW}>>> Warning: Failed to install $package. Some functionality may be limited.${NC}"
            }
        }
    done
    
    echo -e "\n${GREEN}>>> Python dependencies installed${NC}"
}

# Function to install and configure Metasploit
install_metasploit() {
    echo -e "${CYAN}Installing Metasploit...${NC}"
    
    # Install Metasploit
    safe_install_package "metasploit-framework" || handle_error "Failed to install Metasploit"
    
    # Start PostgreSQL
    systemctl start postgresql >/dev/null 2>&1
    
    # Initialize Metasploit database
    if [ ! -f ~/.msf4/db_initialized ]; then
        msfdb init >/dev/null 2>&1
        touch ~/.msf4/db_initialized
    fi
    
    echo -e "${GREEN}>>> Metasploit installed and configured${NC}"
}

# Function to install AI models with progress bar
install_ai_models() {
    echo -e "${CYAN}Installing AI models...${NC}"
    
    # Install Ollama
    if ! command -v ollama &> /dev/null; then
        curl -fsSL https://ollama.com/install.sh | sh >/dev/null 2>&1
    fi
    
    # Start Ollama service
    systemctl start ollama >/dev/null 2>&1
    systemctl enable ollama >/dev/null 2>&1
    
    # Wait for Ollama to start
    sleep 10
    
    # Install models with progress bar
    echo -e "${CYAN}Downloading AI models...${NC}"
    ollama pull artifish/llama3.2-uncensored >/dev/null 2>&1 &
    local pid1=$!
    ollama pull gemma:7b >/dev/null 2>&1 &
    local pid2=$!
    
    # Show progress while models are downloading
    while kill -0 $pid1 2>/dev/null || kill -0 $pid2 2>/dev/null; do
        progress_bar 50
        sleep 1
    done
    
    echo -e "\n${GREEN}>>> AI models installed${NC}"
}

# Function to create directories
create_directories() {
    echo -e "${CYAN}Creating directories...${NC}"
    
    mkdir -p /var/log/AI_MAL
    mkdir -p /opt/AI_MAL/results
    mkdir -p /opt/AI_MAL/scripts
    mkdir -p /opt/AI_MAL/logs
    
    chmod 755 /var/log/AI_MAL
    chmod 755 /opt/AI_MAL
    chmod 755 /opt/AI_MAL/results
    chmod 755 /opt/AI_MAL/scripts
    chmod 755 /opt/AI_MAL/logs
    
    echo -e "${GREEN}>>> Directories created${NC}"
}

# Function to set up environment variables
setup_environment() {
    echo -e "${CYAN}Setting up environment...${NC}"
    
    cat > /etc/profile.d/AI_MAL.sh << EOF
# AI_MAL Environment Variables
export DEBUG=1
export OLLAMA_HOST=http://localhost:11434
export OLLAMA_MODEL=artifish/llama3.2-uncensored
export OLLAMA_FALLBACK_MODEL=gemma:7b
export AI_MAL_LOG_DIR=/var/log/AI_MAL
export AI_MAL_RESULTS_DIR=/opt/AI_MAL/results
export AI_MAL_SCRIPTS_DIR=/opt/AI_MAL/scripts
EOF
    
    source /etc/profile.d/AI_MAL.sh
    
    echo -e "${GREEN}>>> Environment configured${NC}"
}

# Main installation process
main() {
    echo -e "${YELLOW}>>> AI_MAL Installation${NC}"
    echo -e "${YELLOW}>>> This script will install all necessary components${NC}\n"
    
    # Update system
    echo -e "${CYAN}Updating system...${NC}"
    apt-get update >/dev/null 2>&1
    apt-get upgrade -y >/dev/null 2>&1
    
    # Install components
    install_system_dependencies
    install_python_dependencies
    install_metasploit
    install_ai_models
    create_directories
    setup_environment
    
    echo -e "\n${GREEN}>>> AI_MAL installation completed successfully${NC}"
    echo -e "${YELLOW}>>> Please restart your terminal or run 'source /etc/profile.d/AI_MAL.sh'${NC}"
}

# Run main installation
main

# Reset terminal
reset_terminal
exit 0 