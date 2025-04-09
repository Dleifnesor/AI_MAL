#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${YELLOW}>>> AI_MAL Fast Installation Script${NC}"
echo -e "${YELLOW}>>> This script will install the essential components with minimal dependencies${NC}"

# Parse command line arguments
SKIP_MODELS=false
SKIP_LIBSSL=false # Include libssl-dev by default
SKIP_UPDATE=true # Skip system update by default to avoid hanging
SKIP_MSF=false

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
    --with-update)
      SKIP_UPDATE=false
      shift
      ;;
    --no-msf)
      SKIP_MSF=true
      shift
      ;;
    --help)
      echo "Usage: ./install.sh [OPTIONS]"
      echo "Options:"
      echo "  --no-models      Skip downloading AI models"
      echo "  --skip-libssl    Skip installing libssl-dev (use if installation hangs)"
      echo "  --with-update    Update system packages (may be slow)"
      echo "  --no-msf         Skip Metasploit installation"
      echo "  --help           Show this help message"
      exit 0
      ;;
  esac
done

# Function to handle errors
handle_error() {
    echo -e "${RED}Error: $1${NC}"
    exit 1
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    handle_error "Please run as root (sudo ./install.sh)"
fi

# Function to check if a package is available in the repositories
check_package_availability() {
    local package=$1
    apt-cache search "^$package$" | grep -q "^$package "
    return $?
}

# Function to safely install a package with fallbacks
safe_install_package() {
    local package=$1
    local is_essential=${2:-false}
    
    echo -e "${CYAN}Installing $package...${NC}"
    
    # Check if package is already installed
    if dpkg -s "$package" &>/dev/null; then
        echo -e "${GREEN}>>> $package is already installed${NC}"
        return 0
    fi
    
    # Check if package is available in repositories
    if ! check_package_availability "$package"; then
        echo -e "${YELLOW}>>> Package $package not found in repositories. Checking alternatives...${NC}"
        
        # Try to find alternative package names (common variations)
        case "$package" in
            "libssl-dev")
                alternatives=("libssl1.1-dev" "libssl3-dev" "libssl1.0-dev" "libssl1.0.2-dev")
                ;;
            *)
                alternatives=()
                ;;
        esac
        
        # Try alternatives if available
        for alt in "${alternatives[@]}"; do
            if check_package_availability "$alt"; then
                echo -e "${YELLOW}>>> Found alternative package: $alt${NC}"
                DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$alt"
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}>>> Successfully installed alternative package: $alt${NC}"
                    return 0
                fi
            fi
        done
        
        # If no alternatives found and it's essential, fail
        if [ "$is_essential" = true ]; then
            echo -e "${RED}>>> Essential package $package not available. Installation cannot continue.${NC}"
            return 1
        else
            echo -e "${YELLOW}>>> Package $package and alternatives not available. Skipping...${NC}"
            return 0
        fi
    fi
    
    # Install the package
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$package"
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}>>> Failed to install $package. Trying with --fix-missing...${NC}"
        DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing --no-install-recommends "$package"
        
        if [ $? -ne 0 ]; then
            if [ "$is_essential" = true ]; then
                echo -e "${RED}>>> Failed to install essential package $package. Installation cannot continue.${NC}"
                return 1
            else
                echo -e "${YELLOW}>>> Failed to install $package. Continuing anyway...${NC}"
                return 0
            fi
        fi
    fi
    
    echo -e "${GREEN}>>> Successfully installed $package${NC}"
    return 0
}

# Function to safely install libssl-dev
install_libssl_dev() {
    if [ "$SKIP_LIBSSL" = true ]; then
        echo -e "${YELLOW}>>> Skipping libssl-dev installation (--skip-libssl flag detected)${NC}"
        return 0
    fi
    
    echo -e "${YELLOW}>>> Installing OpenSSL development libraries...${NC}"
    
    # First attempt: direct apt installation
    echo -e "${CYAN}Attempting standard installation of libssl-dev...${NC}"
    if timeout 120 apt-get install -y libssl-dev; then
        echo -e "${GREEN}>>> Successfully installed libssl-dev${NC}"
        return 0
    fi
    
    echo -e "${YELLOW}>>> Standard installation failed. Trying alternative approaches...${NC}"
    
    # Second attempt: try specific version
    if command -v apt-cache &>/dev/null; then
        # Find available versions
        AVAILABLE_VERSIONS=$(apt-cache madison libssl-dev | awk '{print $3}')
        if [ -n "$AVAILABLE_VERSIONS" ]; then
            FIRST_VERSION=$(echo "$AVAILABLE_VERSIONS" | head -n 1)
            echo -e "${CYAN}Attempting to install specific version: libssl-dev=$FIRST_VERSION${NC}"
            if timeout 120 apt-get install -y libssl-dev=$FIRST_VERSION; then
                echo -e "${GREEN}>>> Successfully installed libssl-dev version $FIRST_VERSION${NC}"
                return 0
            fi
        fi
    fi
    
    # Third attempt: try to download and install directly
    echo -e "${CYAN}Attempting manual download and installation...${NC}"
    TEMP_DIR="$TMP_DIR/libssl"
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"
    
    apt-get download libssl-dev &>/dev/null
    if [ $? -eq 0 ] && [ -f *.deb ]; then
        echo -e "${CYAN}Downloaded package. Attempting installation...${NC}"
        if dpkg -i *.deb; then
            echo -e "${GREEN}>>> Successfully installed libssl-dev using dpkg${NC}"
            cd - &>/dev/null
            return 0
        fi
    fi
    cd - &>/dev/null
    
    # Fourth attempt: try alternative packages
    for alt_pkg in "libssl1.1-dev" "libssl3-dev" "libssl1.0-dev"; do
        echo -e "${CYAN}Trying alternative package: $alt_pkg${NC}"
        if timeout 120 apt-get install -y $alt_pkg; then
            echo -e "${GREEN}>>> Successfully installed $alt_pkg as an alternative${NC}"
            echo -e "${YELLOW}>>> Note: Using $alt_pkg instead of libssl-dev${NC}"
            return 0
        fi
    done
    
    # Final fallback: try to install openssl binary and headers
    echo -e "${CYAN}Trying to install openssl package...${NC}"
    if timeout 120 apt-get install -y openssl; then
        echo -e "${YELLOW}>>> Installed openssl binary, but development headers may be missing${NC}"
        echo -e "${YELLOW}>>> Some features requiring OpenSSL development headers may not work${NC}"
        return 1
    fi
    
    echo -e "${RED}>>> Failed to install OpenSSL development libraries${NC}"
    echo -e "${YELLOW}>>> Some cryptographic features may not work correctly${NC}"
    return 1
}

# Create necessary directories
echo -e "${YELLOW}>>> Creating necessary directories...${NC}"
mkdir -p logs scan_results msf_resources generated_scripts workspaces

# Make sure sources.list is properly configured
echo -e "${YELLOW}>>> Checking package sources...${NC}"
if [ -f /etc/apt/sources.list ]; then
    # Check if main repositories are enabled
    if ! grep -q "^deb.*main" /etc/apt/sources.list; then
        echo -e "${YELLOW}>>> Warning: Main repository not found in sources.list${NC}"
        echo -e "${YELLOW}>>> This might cause package installation issues${NC}"
    fi
    
    # Check for kali-rolling repository (specific to Kali Linux)
    if ! grep -q "kali-rolling" /etc/apt/sources.list && [ -f /etc/os-release ] && grep -q "kali" /etc/os-release; then
        echo -e "${YELLOW}>>> Kali Linux detected but kali-rolling repository not found${NC}"
        echo -e "${YELLOW}>>> Consider adding 'deb http://http.kali.org/kali kali-rolling main contrib non-free'${NC}"
    fi
fi

# Update package repository but skip upgrade
if [ "$SKIP_UPDATE" = false ]; then
    echo -e "${YELLOW}>>> Updating package repository (skipping upgrade)...${NC}"
    apt-get update
fi

# Install essential packages only, one at a time for reliability
echo -e "${YELLOW}>>> Installing essential packages...${NC}"
essential_packages=(
    "python3" "python3-pip" "python3-venv" "python3-dev" "git" "curl" 
    "build-essential" "nmap" "python3-nmap" "libpcap-dev"
)

for package in "${essential_packages[@]}"; do
    safe_install_package "$package" true
    if [ $? -ne 0 ]; then
        handle_error "Failed to install essential package $package. Aborting installation."
    fi
done

# Install OpenSSL development libraries
install_libssl_dev

# Additional important libraries that might be needed
additional_libs=(
    "libyaml-dev" "zlib1g-dev" "libffi-dev" "libxml2-dev" "libxslt1-dev"
)

echo -e "${YELLOW}>>> Installing additional important libraries...${NC}"
for lib in "${additional_libs[@]}"; do
    safe_install_package "$lib"
done

# Trap to handle script interruptions
trap_script_interruption() {
    echo -e "\n${RED}>>> Installation interrupted. Cleaning up...${NC}"
    
    # Kill any running processes
    pkill -P $$ 2>/dev/null || true
    
    # Remove temporary directories
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi

    # Clean up package management locks if needed
    if [ -f /var/lib/dpkg/lock-frontend ]; then
        rm -f /var/lib/dpkg/lock-frontend
        rm -f /var/lib/dpkg/lock
        rm -f /var/cache/apt/archives/lock
    fi
    
    echo -e "${YELLOW}>>> Installation was interrupted. Some components may not be installed properly.${NC}"
    exit 1
}

# Set trap for interruptions
trap trap_script_interruption INT TERM

# Global temporary directory
TMP_DIR=$(mktemp -d)

# Install Metasploit Framework only if not skipped
if [ "$SKIP_MSF" = false ]; then
    echo -e "${YELLOW}>>> Installing Metasploit Framework (this may take some time)...${NC}"
    
    # First make sure PostgreSQL is installed
    safe_install_package "postgresql" false
    
    if ! dpkg -s "metasploit-framework" &>/dev/null; then
        # Try repository installation first
        echo -e "${CYAN}Attempting to install metasploit-framework from repositories...${NC}"
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends metasploit-framework
        
        if [ $? -ne 0 ]; then
            echo -e "${YELLOW}>>> Repository installation failed. Trying alternative installation...${NC}"
            
            # Make sure we have the prerequisites
            prerequisites=("curl" "gnupg2" "ruby" "ruby-dev" "build-essential" "patch")
            for prereq in "${prerequisites[@]}"; do
                safe_install_package "$prereq" false
            done
            
            # Try downloading and installing from Rapid7
            echo -e "${CYAN}Adding Metasploit Framework repository...${NC}"
            curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key | apt-key add -
            echo "deb https://apt.metasploit.com/ kali main" > /etc/apt/sources.list.d/metasploit.list
            apt-get update
            
            DEBIAN_FRONTEND=noninteractive apt-get install -y metasploit-framework
            if [ $? -ne 0 ]; then
                echo -e "${RED}>>> Failed to install Metasploit Framework${NC}"
                echo -e "${YELLOW}>>> Some penetration testing features will not be available${NC}"
            else
                echo -e "${GREEN}>>> Successfully installed Metasploit Framework from Rapid7 repository${NC}"
            fi
        else
            echo -e "${GREEN}>>> Successfully installed Metasploit Framework from repository${NC}"
        fi
    else
        echo -e "${GREEN}>>> Metasploit Framework is already installed${NC}"
    fi
    
    # Initialize Metasploit database
    if dpkg -s "metasploit-framework" &>/dev/null; then
        echo -e "${YELLOW}>>> Configuring Metasploit database...${NC}"
        
        # Ensure PostgreSQL is running
        if ! systemctl is-active --quiet postgresql; then
            echo -e "${YELLOW}>>> Starting PostgreSQL service...${NC}"
            systemctl start postgresql
            systemctl enable postgresql
        fi
        
        # Initialize msfdb
        if command -v msfdb &>/dev/null; then
            echo -e "${CYAN}Initializing Metasploit database...${NC}"
            msfdb init || echo -e "${YELLOW}>>> Warning: msfdb initialization failed. Some features may not work correctly.${NC}"
        fi
    fi
else
    echo -e "${YELLOW}>>> Skipping Metasploit Framework installation (--no-msf flag detected)${NC}"
fi

# Clean up at the end of the script
cleanup() {
    echo -e "${YELLOW}>>> Cleaning up temporary files...${NC}"
    
    # Remove temporary directory
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
    
    # Fix any broken packages
    echo -e "${YELLOW}>>> Fixing any broken packages...${NC}"
    apt-get -f install -y || true
    
    echo -e "${GREEN}>>> Cleanup completed${NC}"
}

# Register cleanup function to run at script exit
trap cleanup EXIT

# Ensure nmap has proper permissions
echo -e "${YELLOW}>>> Setting proper permissions for nmap...${NC}"
if [ -f /usr/bin/nmap ]; then
    chmod +s /usr/bin/nmap
    echo -e "${GREEN}>>> Set setuid bit on nmap to allow privileged operations${NC}"
else
    echo -e "${RED}>>> Could not find nmap executable. Scanning functionality may be limited.${NC}"
fi

# Create Python virtual environment
echo -e "${YELLOW}>>> Creating Python virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo -e "${YELLOW}>>> Installing Python dependencies...${NC}"
pip install --upgrade pip wheel setuptools

# Install core Python dependencies individually for reliability
core_packages=(
    "rich" "python-nmap" "pathlib" "requests" "numpy" "pandas" 
    "argparse" "pyyaml" "cryptography" "tqdm" "paramiko" "scapy"
    "colorama" "prompt_toolkit" "beautifulsoup4" "lxml"
)

for package in "${core_packages[@]}"; do
    echo -e "${CYAN}Installing $package...${NC}"
    pip install $package
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}>>> Warning: Failed to install $package. Trying alternative installation...${NC}"
        pip install --no-deps $package
        if [ $? -ne 0 ]; then
            echo -e "${YELLOW}>>> Warning: Alternative installation failed. Some functionality may be limited.${NC}"
        fi
    fi
done

# Install package in development mode
echo -e "${YELLOW}>>> Installing AI_MAL package...${NC}"
pip install -e .

# Install Ollama if not already installed
if ! command -v ollama &> /dev/null; then
    echo -e "${YELLOW}>>> Installing Ollama...${NC}"
    
    # Download the script to a file
    curl -fsSL https://ollama.com/install.sh -o ollama_install.sh
    
    # Make it executable and run
    chmod +x ollama_install.sh
    ./ollama_install.sh
    
    # Clean up
    rm -f ollama_install.sh
    
    # Start Ollama service
    systemctl start ollama || echo -e "${YELLOW}>>> Warning: Failed to start Ollama service. AI analysis may not work.${NC}"
    systemctl enable ollama || echo -e "${YELLOW}>>> Warning: Failed to enable Ollama service.${NC}"
    
    # Wait for Ollama to start
    echo -e "${YELLOW}>>> Waiting for Ollama service to start...${NC}"
    sleep 10
else
    echo -e "${GREEN}>>> Ollama is already installed${NC}"
fi

# Download models if not skipped
if [ "$SKIP_MODELS" = false ]; then
    # Check if Ollama is running
    if ! curl -s -f http://localhost:11434/api/tags &>/dev/null; then
        echo -e "${YELLOW}>>> Warning: Ollama service is not running. Starting it...${NC}"
        systemctl start ollama || echo -e "${YELLOW}>>> Failed to start Ollama service. AI models cannot be downloaded.${NC}"
        sleep 5
    fi
    
    if curl -s -f http://localhost:11434/api/tags &>/dev/null; then
        echo -e "${YELLOW}>>> Downloading AI models (this may take some time)...${NC}"
        
        if ollama list 2>/dev/null | grep -q "artifish/llama3.2-uncensored"; then
            echo -e "${GREEN}>>> Primary model artifish/llama3.2-uncensored is already available${NC}"
        else
            echo -e "${YELLOW}>>> Pulling primary AI model: artifish/llama3.2-uncensored...${NC}"
            ollama pull artifish/llama3.2-uncensored &
            echo -e "${YELLOW}>>> Download started in background. It will continue even after installer completes.${NC}"
        fi
        
        if ollama list 2>/dev/null | grep -q "gemma:1b"; then
            echo -e "${GREEN}>>> Fallback model gemma:1b is already available${NC}"
        else
            echo -e "${YELLOW}>>> Pulling fallback AI model: gemma:1b...${NC}"
            ollama pull gemma:1b &
            echo -e "${YELLOW}>>> Download started in background. It will continue even after installer completes.${NC}"
        fi
    else
        echo -e "${RED}>>> Ollama service is not running. AI models cannot be downloaded.${NC}"
        echo -e "${YELLOW}>>> You can download models later after starting Ollama with:${NC}"
        echo -e "${YELLOW}>>>   systemctl start ollama${NC}"
        echo -e "${YELLOW}>>>   ollama pull artifish/llama3.2-uncensored${NC}"
        echo -e "${YELLOW}>>>   ollama pull gemma:1b${NC}"
    fi
else
    echo -e "${YELLOW}>>> Skipping AI model downloads${NC}"
    echo -e "${YELLOW}>>> You can download models later with:${NC}"
    echo -e "${YELLOW}>>>   ollama pull artifish/llama3.2-uncensored${NC}"
    echo -e "${YELLOW}>>>   ollama pull gemma:1b${NC}"
fi

# Create a system-wide executable
echo -e "${YELLOW}>>> Creating system-wide executable...${NC}"
cat > /usr/local/bin/AI_MAL << 'EOF'
#!/bin/bash
cd $(dirname $(readlink -f $(which AI_MAL)))/../..
source venv/bin/activate 2>/dev/null || true
python -m AI_MAL.main "$@"
EOF

chmod +x /usr/local/bin/AI_MAL

# Create a configuration file if it doesn't exist
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}>>> Creating default configuration file...${NC}"
    cat > .env << 'EOF'
OLLAMA_MODEL=artifish/llama3.2-uncensored
OLLAMA_FALLBACK_MODEL=gemma:1b
OLLAMA_URL=http://localhost:11434
LOG_DIR=logs
WORKSPACE_DIR=workspaces
EOF
    echo -e "${GREEN}>>> Created default configuration file${NC}"
fi

# Verify installation
echo -e "${YELLOW}>>> Verifying installation...${NC}"

# Check if Python virtual environment is properly installed
if [ -d "venv" ] && [ -f "venv/bin/activate" ]; then
    echo -e "${GREEN}>>> Python virtual environment is properly installed${NC}"
    
    # Verify critical Python packages
    source venv/bin/activate
    
    critical_pkgs=("rich" "nmap" "requests")
    missing_pkgs=()
    
    for pkg in "${critical_pkgs[@]}"; do
        python -c "import $pkg" 2>/dev/null
        if [ $? -ne 0 ]; then
            missing_pkgs+=("$pkg")
        fi
    done
    
    if [ ${#missing_pkgs[@]} -gt 0 ]; then
        echo -e "${YELLOW}>>> Warning: Some critical Python packages are missing: ${missing_pkgs[*]}${NC}"
        echo -e "${YELLOW}>>> Trying to reinstall them...${NC}"
        
        for pkg in "${missing_pkgs[@]}"; do
            pip install --no-cache-dir $pkg
        done
    else
        echo -e "${GREEN}>>> All critical Python packages are installed${NC}"
    fi
else
    echo -e "${RED}>>> Python virtual environment is missing or incomplete${NC}"
    echo -e "${YELLOW}>>> You may need to run: python3 -m venv venv${NC}"
fi

# Check nmap
if command -v nmap &> /dev/null; then
    echo -e "${GREEN}>>> nmap is installed${NC}"
    # Test nmap basic functionality
    if nmap -V &>/dev/null; then
        echo -e "${GREEN}>>> nmap is functioning correctly${NC}"
    else
        echo -e "${RED}>>> nmap is installed but not functioning correctly${NC}"
    fi
else
    echo -e "${RED}>>> nmap is not installed. Scanning functionality will not work.${NC}"
fi

# Check if AI_MAL executable is available
if [ -f "/usr/local/bin/AI_MAL" ] && [ -x "/usr/local/bin/AI_MAL" ]; then
    echo -e "${GREEN}>>> AI_MAL executable is available and has proper permissions${NC}"
else
    echo -e "${RED}>>> AI_MAL executable is missing or not executable${NC}"
fi

# Final summary
echo ""
echo -e "${GREEN}╔═════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           AI_MAL Installation Complete          ║${NC}"
echo -e "${GREEN}╚═════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}>>> You can now run AI_MAL with: AI_MAL <target> [options]${NC}"
echo -e "${GREEN}>>> Example: AI_MAL 192.168.1.1 --vuln --os --services${NC}"
echo -e "${GREEN}>>> For a local test, try: AI_MAL 127.0.0.1 --vuln --os${NC}"
echo ""

exit 0 